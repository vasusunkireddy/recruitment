const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const mysql = require('mysql2/promise');
const multer = require('multer');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('uploads')); // Serve uploaded resumes

// MySQL Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'recruitpro_db'
});

// Test MySQL Connection
async function testDB() {
    try {
        const connection = await db.getConnection();
        console.log("✅ MySQL Connected Successfully!");
        connection.release();
    } catch (error) {
        console.error("❌ MySQL Connection Failed:", error.message);
        process.exit(1);
    }
}
testDB();

// Verify Environment Variables
const requiredEnv = ['EMAIL_USER', 'EMAIL_PASS', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
requiredEnv.forEach(key => {
    if (!process.env[key]) {
        console.error(`❌ Missing environment variable: ${key}`);
        process.exit(1);
    }
});
console.log("🔹 Email User:", process.env.EMAIL_USER);
console.log("🔹 Email Pass Loaded:", process.env.EMAIL_PASS ? "Yes" : "No");

// Nodemailer Setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Test Email Configuration
async function testEmail() {
    try {
        await transporter.verify();
        console.log("✅ Email service configured successfully!");
    } catch (error) {
        console.error("❌ Email configuration failed:", error.message, error.stack);
        console.log("Please check your .env file for EMAIL_USER and EMAIL_PASS.");
        process.exit(1);
    }
}
testEmail();

// Multer for File Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// Temporary OTP Storage (Use Redis in production)
const otps = {};

// Helper Function to Send Emails
const sendEmail = async (to, subject, text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text,
    };
    try {
        console.log(`Attempting to send email to ${to} with subject: ${subject}`);
        const info = await transporter.sendMail(mailOptions);
        console.log(`Email sent successfully to ${to}. Message ID: ${info.messageId}`);
    } catch (error) {
        console.error(`Failed to send email to ${to}:`, error.message, error.stack);
        throw new Error(`Email sending failed: ${error.message}`);
    }
};

// Admin Authentication Middleware
const isAdmin = async (req, res, next) => {
    const { adminId } = req.body || req.headers;
    if (!adminId) {
        return res.status(401).json({ message: 'Admin ID required' });
    }
    try {
        const [rows] = await db.query('SELECT * FROM admins WHERE id = ?', [adminId]);
        if (rows.length === 0) {
            return res.status(403).json({ message: 'Unauthorized: Not an admin' });
        }
        req.admin = rows[0];
        next();
    } catch (error) {
        console.error('Admin check error:', error.message);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};

// Routes
app.get('/', (req, res) => {
    res.send('Welcome to the RecruitPro Backend!');
});

// Signup - Send OTP
app.post('/api/signup', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    otps[email] = { otp, expires: Date.now() + 10 * 60 * 1000 }; // 10 minutes expiration

    try {
        console.log(`Generating OTP ${otp} for ${email}`);
        await sendEmail(email, 'RecruitPro - Your OTP', `Your OTP for signup is: ${otp}. It is valid for 10 minutes.`);
        res.json({ message: 'OTP sent to your email!' });
    } catch (error) {
        console.error(`OTP sending failed for ${email}:`, error.message, error.stack);
        res.status(500).json({ message: 'Failed to send OTP', error: error.message });
    }
});

// Verify OTP & Create Account
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp, password, confirmPassword } = req.body;

    if (!otps[email] || otps[email].otp != otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
    if (otps[email].expires < Date.now()) {
        delete otps[email];
        return res.status(400).json({ message: 'OTP has expired' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const [existingUser] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);
        delete otps[email];

        await sendEmail(email, 'Welcome to RecruitPro!', 'Your account has been successfully created! You can now log in and start applying for jobs.');
        res.json({ success: true, message: 'Account created successfully!', userId: result.insertId });
    } catch (error) {
        console.error('Database error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Login (User/Admin)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const [adminRows] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
        if (adminRows.length > 0) {
            const isPasswordValid = await bcrypt.compare(password, adminRows[0].password);
            if (isPasswordValid) {
                await sendEmail(email, 'RecruitPro - Admin Login', `You have successfully logged in as an admin on ${new Date().toLocaleString()}.`);
                return res.json({
                    success: true,
                    role: 'admin',
                    message: 'Admin login successful!',
                    adminId: adminRows[0].id
                });
            }
        }

        const [userRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (userRows.length > 0) {
            const isPasswordValid = await bcrypt.compare(password, userRows[0].password);
            if (isPasswordValid) {
                await sendEmail(email, 'RecruitPro - User Login', `You have successfully logged in on ${new Date().toLocaleString()}.`);
                return res.json({
                    success: true,
                    role: 'user',
                    message: 'User login successful!',
                    userId: userRows[0].id
                });
            }
        }

        res.status(401).json({ success: false, message: 'Invalid email or password' });
    } catch (error) {
        console.error('Login error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Logout (Admin/User)
app.post('/api/logout', async (req, res) => {
    const { adminId, userId } = req.body;

    try {
        let email = null;
        if (adminId) {
            const [adminRows] = await db.query('SELECT * FROM admins WHERE id = ?', [adminId]);
            if (adminRows.length === 0) {
                return res.status(404).json({ message: 'Admin not found' });
            }
            email = adminRows[0].email;
            console.log(`Admin ${adminId} logged out`);
        } else if (userId) {
            const [userRows] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
            if (userRows.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }
            email = userRows[0].email;
            console.log(`User ${userId} logged out`);
        }

        if (email) {
            await sendEmail(email, 'RecruitPro - Logout', `You have successfully logged out on ${new Date().toLocaleString()}.`);
        }

        res.json({ success: true, message: 'Logged out successfully!' });
    } catch (error) {
        console.error('Logout error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Update Admin Profile
app.post('/api/update-profile', isAdmin, async (req, res) => {
    const { adminId, email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'UPDATE admins SET email = ?, password = ? WHERE id = ?',
            [email, hashedPassword, adminId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        await sendEmail(email, 'RecruitPro - Profile Updated', `Your admin profile has been updated successfully on ${new Date().toLocaleString()}.`);
        res.json({ success: true, message: 'Profile updated successfully!' });
    } catch (error) {
        console.error('Profile update error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Post Job (Admin Only)
app.post('/api/jobs', isAdmin, async (req, res) => {
    const { title, description, adminId } = req.body;

    if (!title || !description) {
        return res.status(400).json({ message: 'Title and description are required' });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO jobs (title, description, admin_id) VALUES (?, ?, ?)',
            [title, description, adminId]
        );

        const [adminRows] = await db.query('SELECT email FROM admins WHERE id = ?', [adminId]);
        if (adminRows.length > 0) {
            await sendEmail(adminRows[0].email, 'RecruitPro - Job Posted', `You have successfully posted a job titled "${title}" on ${new Date().toLocaleString()}.`);
        }

        res.json({ success: true, message: 'Job posted successfully!', jobId: result.insertId });
    } catch (error) {
        console.error('Job posting error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Get All Jobs
app.get('/api/jobs', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM jobs');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching jobs:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Apply for Job (With Resume Upload)
app.post('/api/apply', upload.single('resume'), async (req, res) => {
    const { userId, jobId, fullName, email } = req.body;
    const resumePath = req.file ? req.file.path : null;

    if (!userId || !jobId || !fullName || !email) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO applications (user_id, job_id, full_name, email, resume_path) VALUES (?, ?, ?, ?, ?)',
            [userId, jobId, fullName, email, resumePath]
        );

        const [jobRows] = await db.query('SELECT title FROM jobs WHERE id = ?', [jobId]);
        const jobTitle = jobRows.length > 0 ? jobRows[0].title : 'Unknown Job';

        await sendEmail(email, 'RecruitPro - Job Application Submitted', `Your application for the job "${jobTitle}" has been submitted successfully on ${new Date().toLocaleString()}. We will review your application and get back to you soon.`);

        const [adminRows] = await db.query('SELECT email FROM admins WHERE id = (SELECT admin_id FROM jobs WHERE id = ?)', [jobId]);
        if (adminRows.length > 0) {
            await sendEmail(adminRows[0].email, 'RecruitPro - New Job Application', `A new application for your job "${jobTitle}" has been submitted by ${fullName} (${email}) on ${new Date().toLocaleString()}.`);
        }

        res.json({ success: true, message: 'Application submitted successfully!', applicationId: result.insertId });
    } catch (error) {
        console.error('Application error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    try {
        const [userRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const [adminRows] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);

        if (userRows.length === 0 && adminRows.length === 0) {
            return res.status(404).json({ message: 'Email not found' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        otps[email] = { otp, expires: Date.now() + 10 * 60 * 1000 }; // 10 minutes expiration

        await sendEmail(email, 'RecruitPro - Password Reset OTP', `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`);
        res.json({ message: 'Password reset OTP sent to your email!' });
    } catch (error) {
        console.error('Reset password error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Verify Password Reset OTP and Update Password
app.post('/api/reset-password/verify', async (req, res) => {
    const { email, otp, newPassword, confirmNewPassword } = req.body;

    if (!otps[email] || otps[email].otp != otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
    if (otps[email].expires < Date.now()) {
        delete otps[email];
        return res.status(400).json({ message: 'OTP has expired' });
    }
    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const [userRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (userRows.length > 0) {
            await db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        } else {
            const [adminRows] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
            if (adminRows.length > 0) {
                await db.query('UPDATE admins SET password = ? WHERE email = ?', [hashedPassword, email]);
            } else {
                return res.status(404).json({ message: 'Email not found' });
            }
        }

        delete otps[email];

        await sendEmail(email, 'RecruitPro - Password Reset Successful', `Your password has been successfully reset on ${new Date().toLocaleString()}.`);
        res.json({ success: true, message: 'Password reset successful!' });
    } catch (error) {
        console.error('Password reset verification error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Admin Dashboard Stats
app.get('/api/jobs/count', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM jobs');
        res.json({ count: rows[0].count });
    } catch (error) {
        console.error('Jobs count error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/users/count', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM users');
        res.json({ count: rows[0].count });
    } catch (error) {
        console.error('Users count error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/actions/pending', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM applications WHERE status = "pending"');
        res.json({ count: rows[0].count });
    } catch (error) {
        console.error('Pending actions error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});