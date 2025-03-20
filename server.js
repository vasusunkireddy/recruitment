require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const mysql = require('mysql2/promise');
const multer = require('multer');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Environment Variable Validation
console.log('Environment Variables:');
console.log('EMAIL_USER:', process.env.EMAIL_USER);
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? 'Set' : 'Not Set');
console.log('EMAIL_FROM:', process.env.EMAIL_FROM);
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_NAME:', process.env.DB_NAME);

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads', file.fieldname === 'resume' ? 'resumes' : 'profiles');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => cb(null, `${uuidv4()}_${file.originalname}`)
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PDFs, JPEGs, and PNGs are allowed.'), false);
        }
    }
});

// MySQL Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '9810',
    database: process.env.DB_NAME || 'recruitpro_db',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Initialize Database and Create Tables
(async () => {
    try {
        const connection = await db.getConnection();
        const [dbInfo] = await connection.query("SELECT DATABASE()");
        console.log(`✅ Connected to database: ${dbInfo[0]['DATABASE()']}`);

        // Create users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                profile_pic VARCHAR(255),
                role ENUM('user', 'admin') DEFAULT 'user',
                verified BOOLEAN DEFAULT FALSE,
                blocked BOOLEAN DEFAULT FALSE,
                otp VARCHAR(6),
                otp_expiry DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME
            )
        `);

        // Create admins table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                profile_pic VARCHAR(255),
                role ENUM('admin') DEFAULT 'admin',
                created_at DATETIME NOT NULL,
                updated_at DATETIME
            )
        `);

        // Create pending_users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS pending_users (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                otp VARCHAR(6) NOT NULL,
                otp_expiry DATETIME NOT NULL,
                created_at DATETIME NOT NULL
            )
        `);

        // Create jobs table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS jobs (
                id VARCHAR(36) PRIMARY KEY,
                type ENUM('Job', 'Internship') NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                admin_id VARCHAR(36),
                deleted BOOLEAN DEFAULT FALSE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
            )
        `);

        // Create applications table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS applications (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                opportunity_id VARCHAR(36) NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                availability VARCHAR(255) NOT NULL,
                resume_path VARCHAR(255),
                job_title VARCHAR(255) NOT NULL,
                type ENUM('Job', 'Internship') NOT NULL,
                status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (opportunity_id) REFERENCES jobs(id) ON DELETE CASCADE
            )
        `);

        // Create resumes table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS resumes (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                phone VARCHAR(20) NOT NULL,
                address VARCHAR(255),
                objective TEXT,
                experience TEXT,
                education TEXT NOT NULL,
                trainings TEXT,
                portfolio VARCHAR(255),
                projects TEXT,
                skills TEXT NOT NULL,
                activities TEXT,
                additional TEXT,
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        connection.release();
    } catch (error) {
        console.error('❌ Database connection error:', error.message);
        process.exit(1);
    }
})();

// Email Configuration with Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify Email Configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email configuration error:', error.message);
        console.log('Using EMAIL_USER:', process.env.EMAIL_USER);
        console.log('EMAIL_PASS is set:', !!process.env.EMAIL_PASS);
    } else {
        console.log('✅ Email service is ready');
    }
});

const EMAIL_FROM = process.env.EMAIL_FROM || 'svasudevareddy18604@gmail.com';
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key-here';
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY || 'your-refresh-secret-key-here';

// Token Generation
const generateToken = (user) => jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
const generateRefreshToken = (user) => jwt.sign({ id: user.id, email: user.email, role: user.role }, REFRESH_SECRET_KEY, { expiresIn: '7d' });

// Middleware to Authenticate Token
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const userId = req.headers['id'];
    const role = req.headers['role'];

    if (!token || !userId || !role) {
        return res.status(401).json({ success: false, message: 'Access denied: Token, user ID, or role missing.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== role) {
            return res.status(403).json({ success: false, message: 'Role mismatch.' });
        }

        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const user = users[0];
        if (user.blocked) {
            return res.status(403).json({ success: false, message: 'User is blocked.' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('🚫 Token authentication error:', error.message);
        res.status(403).json({ success: false, message: 'Invalid token.' });
    }
};

// Middleware to Authenticate Admin
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const adminId = req.headers['id'];
    const role = req.headers['role'];

    if (!token || !adminId || role !== 'admin') {
        return res.status(401).json({ success: false, message: 'Access denied: Token, admin ID, or role missing.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Admin access required.' });
        }

        const [admins] = await db.query('SELECT * FROM admins WHERE id = ?', [adminId]);
        if (admins.length === 0) {
            return res.status(403).json({ success: false, message: 'Admin not found.' });
        }

        req.admin = admins[0];
        next();
    } catch (error) {
        console.error('🚫 Admin authentication error:', error.message);
        res.status(403).json({ success: false, message: 'Invalid token.' });
    }
};

// Initialize Admin if Not Exists
(async () => {
    try {
        const [admins] = await db.query('SELECT * FROM admins WHERE email = ?', ['admin@recruitpro.com']);
        if (admins.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await db.query(
                'INSERT INTO admins (id, email, password, role, created_at) VALUES (?, ?, ?, ?, NOW())',
                [uuidv4(), 'admin@recruitpro.com', hashedPassword, 'admin']
            );
            console.log('✅ Initial admin account created');
        }
    } catch (error) {
        console.error('❌ Error initializing admin:', error.message);
    }
})();

// Cleanup Expired Pending Users (Runs every 5 minutes)
setInterval(async () => {
    try {
        const [expired] = await db.query('SELECT * FROM pending_users WHERE otp_expiry < NOW()');
        if (expired.length > 0) {
            await db.query('DELETE FROM pending_users WHERE otp_expiry < NOW()');
            console.log(`🧹 Cleaned up ${expired.length} expired pending users`);
        }
    } catch (error) {
        console.error('❌ Cleanup error:', error.message);
    }
}, 5 * 60 * 1000); // Run every 5 minutes

// API Endpoints
// Signup Endpoint (Using pending_users)
app.post('/api/signup', async (req, res) => {
    const { email } = req.body;

    if (!email || !email.trim()) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    console.log('Processing signup for email:', email);

    try {
        // Check if email already exists in users (verified users)
        const [existingUsers] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            console.log('Verified user already exists:', existingUsers);
            return res.status(409).json({ success: false, message: 'This email is already registered.' });
        }

        // Check if email exists in pending_users
        const [pendingUsers] = await db.query('SELECT * FROM pending_users WHERE email = ?', [email]);
        if (pendingUsers.length > 0) {
            await db.query('DELETE FROM pending_users WHERE email = ?', [email]);
            console.log('Deleted existing pending signup for:', email);
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await db.query(
            'INSERT INTO pending_users (id, email, otp, otp_expiry, created_at) VALUES (?, ?, ?, ?, NOW())',
            [uuidv4(), email, otp, otpExpiry]
        );

        const mailOptions = {
            from: EMAIL_FROM,
            to: email,
            subject: 'Your OTP for RecruitPro Registration',
            text: `Your OTP is ${otp}. It is valid for 10 minutes. Please do not share it with anyone.`
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log('✅ OTP sent to:', email);
            res.status(200).json({ success: true, message: 'OTP sent to your email. Please verify to complete registration.' });
        } catch (emailError) {
            console.error('🚫 Email sending error:', emailError.message);
            await db.query('DELETE FROM pending_users WHERE email = ?', [email]);
            console.log('Deleted pending user due to email failure:', email);
            res.status(500).json({ success: false, message: 'Failed to send OTP email. Please try again later.' });
        }
    } catch (error) {
        console.error('🚫 Signup error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to process signup. Please try again later.' });
    }
});

// Verify OTP Endpoint
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp, password, confirmPassword } = req.body;

    const errors = {};
    if (!email) errors.email = 'Email is required.';
    if (!otp) errors.otp = 'OTP is required.';
    if (!password) errors.password = 'Password is required.';
    if (!confirmPassword) errors.confirmPassword = 'Confirm password is required.';
    if (Object.keys(errors).length > 0) {
        return res.status(400).json({ success: false, errors });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, errors: { confirmPassword: 'Passwords do not match.' } });
    }

    try {
        const [pendingUsers] = await db.query(
            'SELECT * FROM pending_users WHERE email = ? AND otp = ? AND otp_expiry > NOW()',
            [email, otp]
        );
        if (pendingUsers.length === 0) {
            return res.status(400).json({ success: false, errors: { otp: 'Invalid or expired OTP.' } });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query(
            'INSERT INTO users (id, email, password, role, verified, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
            [uuidv4(), email, hashedPassword, 'user', true]
        );

        await db.query('DELETE FROM pending_users WHERE email = ?', [email]);

        const [newUser] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const accessToken = generateToken(newUser[0]);
        const refreshToken = generateRefreshToken(newUser[0]);

        res.status(201).json({
            success: true,
            message: 'Account created successfully!',
            accessToken,
            refreshToken,
            userId: newUser[0].id,
            role: newUser[0].role
        });
    } catch (error) {
        console.error('🚫 Verify OTP error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to verify OTP. Please try again.' });
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required.'
        });
    }

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const [admins] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
        const user = users[0] || admins[0];

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Check if user is blocked
        if (user.role === 'user' && user.blocked) {
            return res.status(403).json({ success: false, message: 'User is blocked.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid password.' });
        }

        const accessToken = generateToken(user);
        const refreshToken = generateRefreshToken(user);

        res.status(200).json({
            success: true,
            message: 'Login successful!',
            accessToken,
            refreshToken,
            role: user.role,
            userId: users[0]?.id,
            adminId: admins[0]?.id,
            email: user.email
        });
    } catch (error) {
        console.error('🚫 Login error:', error.message);
        res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
    }
});

// Refresh Token Endpoint
app.post('/api/refresh-token', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ success: false, message: 'Refresh token is required.' });
    }

    jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid refresh token.' });
        }
        const accessToken = generateToken(user);
        res.status(200).json({ success: true, accessToken });
    });
});

// Logout Endpoint
app.post('/api/logout', (req, res) => {
    res.status(200).json({ success: true, message: 'Logged out successfully.' });
});

// Reset Password Endpoint
app.post('/api/reset-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        await db.query('UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?', [otp, otpExpiry, email]);

        const mailOptions = {
            from: EMAIL_FROM,
            to: email,
            subject: 'Your OTP for Password Reset',
            text: `Your OTP is ${otp}. It is valid for 10 minutes. Please do not share it.`
        };

        await transporter.sendMail(mailOptions);
        console.log('✅ Password reset OTP sent to:', email);
        res.status(200).json({ success: true, message: 'OTP sent to your email for password reset.' });
    } catch (error) {
        console.error('🚫 Reset password error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to initiate password reset.' });
    }
});

// Verify Reset Password OTP Endpoint
app.post('/api/reset-password/verify', async (req, res) => {
    const { email, otp, newPassword, confirmNewPassword } = req.body;

    const errors = {};
    if (!email) errors.email = 'Email is required.';
    if (!otp) errors.otp = 'OTP is required.';
    if (!newPassword) errors.newPassword = 'New password is required.';
    if (!confirmNewPassword) errors.confirmNewPassword = 'Confirm new password is required.';
    if (Object.keys(errors).length > 0) {
        return res.status(400).json({ success: false, errors });
    }

    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ success: false, errors: { confirmNewPassword: 'Passwords do not match.' } });
    }

    try {
        const [users] = await db.query(
            'SELECT * FROM users WHERE email = ? AND otp = ? AND otp_expiry > NOW()',
            [email, otp]
        );
        if (users.length === 0) {
            return res.status(400).json({ success: false, errors: { otp: 'Invalid or expired OTP.' } });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?', [
            hashedPassword,
            email
        ]);

        res.status(200).json({ success: true, message: 'Password reset successful!' });
    } catch (error) {
        console.error('🚫 Reset password verify error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to reset password.' });
    }
});

// Jobs Endpoints
app.get('/api/jobs', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const userId = req.headers['id'];

    try {
        let query = 'SELECT * FROM jobs WHERE deleted = FALSE';
        if (authHeader && userId) {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, SECRET_KEY);
            if (decoded.role === 'admin') {
                query = 'SELECT * FROM jobs WHERE deleted = FALSE'; // Admins see only non-deleted jobs in this endpoint
            }
        }

        const [rows] = await db.query(query);
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch jobs error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch jobs.' });
    }
});

app.post('/api/jobs', authenticateAdmin, async (req, res) => {
    const { type, title, description } = req.body;
    const adminId = req.admin.id;

    if (!type || !title || !description) {
        return res.status(400).json({ success: false, message: 'All fields (type, title, description) are required.' });
    }

    if (!['job', 'internship'].includes(type.toLowerCase())) {
        return res.status(400).json({ success: false, message: 'Type must be either "job" or "internship".' });
    }

    try {
        await db.query(
            'INSERT INTO jobs (id, type, title, description, admin_id, created_at, deleted) VALUES (?, ?, ?, ?, ?, NOW(), FALSE)',
            [uuidv4(), type, title, description, adminId]
        );
        res.status(201).json({ success: true, message: 'Job/Internship posted successfully!' });
    } catch (error) {
        console.error('🚫 Post job error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to post job.' });
    }
});

app.put('/api/jobs/:id', authenticateAdmin, async (req, res) => {
    const jobId = req.params.id;
    const { type, title, description } = req.body;

    if (!type || !title || !description) {
        return res.status(400).json({ success: false, message: 'All fields (type, title, description) are required.' });
    }

    if (!['job', 'internship'].includes(type.toLowerCase())) {
        return res.status(400).json({ success: false, message: 'Type must be either "job" or "internship".' });
    }

    try {
        const [result] = await db.query(
            'UPDATE jobs SET type = ?, title = ?, description = ?, updated_at = NOW() WHERE id = ? AND deleted = FALSE',
            [type, title, description, jobId]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Job not found or already deleted.' });
        }
        res.status(200).json({ success: true, message: 'Job updated successfully.' });
    } catch (error) {
        console.error('🚫 Update job error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to update job.' });
    }
});

app.get('/api/jobs/count', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM jobs WHERE deleted = FALSE');
        res.status(200).json({ success: true, count: rows[0].count });
    } catch (error) {
        console.error('🚫 Count jobs error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to count jobs.' });
    }
});

app.delete('/api/jobs/:id', authenticateAdmin, async (req, res) => {
    const jobId = req.params.id;

    try {
        const [result] = await db.query('UPDATE jobs SET deleted = TRUE, updated_at = NOW() WHERE id = ?', [jobId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }
        res.status(200).json({ success: true, message: 'Job moved to trash successfully.' });
    } catch (error) {
        console.error('🚫 Delete job error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to move job to trash.' });
    }
});

app.get('/api/jobs/trash', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM jobs WHERE deleted = TRUE');
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch trash jobs error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch trashed jobs.' });
    }
});

app.put('/api/jobs/restore/:id', authenticateAdmin, async (req, res) => {
    const jobId = req.params.id;

    try {
        const [result] = await db.query('UPDATE jobs SET deleted = FALSE, updated_at = NOW() WHERE id = ?', [jobId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Job not found in trash.' });
        }
        res.status(200).json({ success: true, message: 'Job restored successfully.' });
    } catch (error) {
        console.error('🚫 Restore job error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to restore job.' });
    }
});

app.delete('/api/jobs/permanent/:id', authenticateAdmin, async (req, res) => {
    const jobId = req.params.id;

    try {
        const [result] = await db.query('DELETE FROM jobs WHERE id = ? AND deleted = TRUE', [jobId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Job not found in trash.' });
        }
        res.status(200).json({ success: true, message: 'Job permanently deleted successfully.' });
    } catch (error) {
        console.error('🚫 Permanently delete job error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to permanently delete job.' });
    }
});

// Applications Endpoints
app.post('/api/applications', authenticateToken, upload.single('resume'), async (req, res) => {
    const { opportunityId, fullName, availability, useGeneratedResume, resumeId } = req.body;
    const userId = req.user.id;

    if (!opportunityId || !fullName || !availability) {
        return res.status(400).json({ success: false, message: 'Opportunity ID, full name, and availability are required.' });
    }

    try {
        const [job] = await db.query('SELECT * FROM jobs WHERE id = ? AND deleted = FALSE', [opportunityId]);
        if (job.length === 0) {
            return res.status(404).json({ success: false, message: 'Job/Internship not found.' });
        }

        const [existingApplication] = await db.query(
            'SELECT * FROM applications WHERE user_id = ? AND opportunity_id = ?',
            [userId, opportunityId]
        );
        if (existingApplication.length > 0) {
            return res.status(400).json({ success: false, message: 'You have already applied for this opportunity.' });
        }

        let resumePath = null;
        if (useGeneratedResume === 'true') {
            if (!resumeId) {
                return res.status(400).json({ success: false, message: 'Resume ID is required when using a generated resume.' });
            }
            const [resume] = await db.query('SELECT * FROM resumes WHERE id = ? AND user_id = ?', [resumeId, userId]);
            if (resume.length === 0) {
                return res.status(404).json({ success: false, message: 'Generated resume not found.' });
            }
        } else {
            if (!req.file) {
                return res.status(400).json({ success: false, message: 'Resume file is required.' });
            }
            resumePath = `/uploads/resumes/${req.file.filename}`;
        }

        await db.query(
            'INSERT INTO applications (id, user_id, opportunity_id, full_name, email, availability, resume_path, job_title, type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
            [
                uuidv4(),
                userId,
                opportunityId,
                fullName,
                req.user.email,
                availability,
                resumePath,
                job[0].title,
                job[0].type
            ]
        );

        res.status(201).json({ success: true, message: 'Application submitted successfully!' });
    } catch (error) {
        console.error('🚫 Submit application error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to submit application.' });
    }
});

app.get('/api/user/applications', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query('SELECT * FROM applications WHERE user_id = ?', [userId]);
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch user applications error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch applications.' });
    }
});

app.get('/api/applications', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM applications');
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch admin applications error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch applications.' });
    }
});

app.get('/api/applications/pending', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM applications WHERE status = "pending"');
        res.status(200).json({ success: true, count: rows[0].count });
    } catch (error) {
        console.error('🚫 Count pending applications error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to count pending applications.' });
    }
});

app.put('/api/applications/:id', authenticateAdmin, async (req, res) => {
    console.log('📥 Received request to update application status');
    console.log('Request Headers:', req.headers);
    console.log('Request Params:', req.params);
    console.log('Request Body:', req.body);

    const applicationId = req.params.id;
    const { status } = req.body;

    // Validate the status
    if (!status || !['pending', 'accepted', 'rejected'].includes(status)) {
        console.log('❌ Validation failed: Invalid status');
        return res.status(400).json({ success: false, message: 'Valid status is required (pending, accepted, rejected).' });
    }

    try {
        console.log(`🔍 Fetching application with ID: ${applicationId}`);
        const [applications] = await db.query('SELECT * FROM applications WHERE id = ?', [applicationId]);
        if (applications.length === 0) {
            console.log('❌ Application not found');
            return res.status(404).json({ success: false, message: 'Application not found.' });
        }

        const application = applications[0];
        console.log('✅ Application found:', application);
        const userEmail = application.email;
        const userName = application.full_name;
        const jobTitle = application.job_title;
        const applicationType = application.type;

        console.log(`📝 Updating application status to: ${status}`);
        const [result] = await db.query(
            'UPDATE applications SET status = ?, updated_at = NOW() WHERE id = ?',
            [status, applicationId]
        );

        if (result.affectedRows === 0) {
            console.log('❌ No rows affected during update');
            return res.status(404).json({ success: false, message: 'Application not found.' });
        }

        console.log('✅ Application status updated successfully');

        // Send professional email notification to the user
        const statusText = status.charAt(0).toUpperCase() + status.slice(1);
        const subject = `RecruitPro: Application Status Update for ${jobTitle}`;
        const emailBody = `
Dear ${userName},

We hope this message finds you well.

We are writing to inform you that the status of your application for the ${applicationType} position of "${jobTitle}" at RecruitPro has been updated to **${statusText}**.

**Application Details:**
- **Position:** ${jobTitle}
- **Type:** ${applicationType}
- **Status:** ${statusText}
- **Updated On:** ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}

${
    status === 'accepted'
        ? 'Congratulations on being accepted! Our team will reach out to you shortly with the next steps in the hiring process. We look forward to welcoming you to the team.'
        : status === 'rejected'
        ? 'We appreciate your interest in this position. While your application was not selected at this time, we encourage you to apply for other opportunities that match your skills and experience. Thank you for considering RecruitPro.'
        : 'Your application is currently under review. We will notify you of any updates as soon as possible. Thank you for your patience.'
}

If you have any questions or need further assistance, please do not hesitate to contact us at support@recruitpro.com.

Thank you for choosing RecruitPro as your career platform. We wish you the best in your career journey!

Best regards,  
**RecruitPro Team**  
support@recruitpro.com  
www.recruitpro.com
        `;

        const mailOptions = {
            from: `"RecruitPro Team" <${EMAIL_FROM}>`,
            to: userEmail,
            subject: subject,
            text: emailBody
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`✅ Notification email sent to ${userEmail} for ${statusText} status of ${jobTitle}`);
        } catch (emailError) {
            console.error(`🚫 Failed to send notification email to ${userEmail}:`, emailError.message);
            // Note: We don't fail the request if the email fails, but we log the error
        }

        res.status(200).json({ success: true, message: 'Application status updated successfully!' });
    } catch (error) {
        console.error('🚫 Update application status error:', error.message);
        console.error('Error details:', error);
        res.status(500).json({ success: false, message: 'Failed to update application status.' });
    }
});

// Resume Endpoints
app.post('/api/resumes', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const {
        name,
        email,
        phone,
        address,
        objective,
        experience,
        education,
        trainings,
        portfolio,
        projects,
        skills,
        activities,
        additional
    } = req.body;

    if (!name || !email || !phone || !education || !skills) {
        return res.status(400).json({ success: false, message: 'Name, email, phone, education, and skills are required.' });
    }

    try {
        await db.query(
            `INSERT INTO resumes (
                id, user_id, name, email, phone, address, objective, experience, education, 
                trainings, portfolio, projects, skills, activities, additional, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
                uuidv4(),
                userId,
                name,
                email,
                phone,
                address || null,
                objective || null,
                experience || null,
                education,
                trainings || null,
                portfolio || null,
                projects || null,
                skills,
                activities || null,
                additional || null
            ]
        );
        res.status(201).json({ success: true, message: 'Resume created successfully!' });
    } catch (error) {
        console.error('🚫 Create resume error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to create resume.' });
    }
});

app.get('/api/resumes', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query('SELECT * FROM resumes WHERE user_id = ?', [userId]);
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch resumes error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch resumes.' });
    }
});

app.put('/api/resumes/:id', authenticateToken, async (req, res) => {
    const resumeId = req.params.id;
    const userId = req.user.id;
    const {
        name,
        email,
        phone,
        address,
        objective,
        experience,
        education,
        trainings,
        portfolio,
        projects,
        skills,
        activities,
        additional
    } = req.body;

    if (!name || !email || !phone || !education || !skills) {
        return res.status(400).json({ success: false, message: 'Name, email, phone, education, and skills are required.' });
    }

    try {
        const [result] = await db.query(
            `UPDATE resumes SET 
                name = ?, email = ?, phone = ?, address = ?, objective = ?, experience = ?, 
                education = ?, trainings = ?, portfolio = ?, projects = ?, skills = ?, 
                activities = ?, additional = ?, updated_at = NOW()
            WHERE id = ? AND user_id = ?`,
            [
                name,
                email,
                phone,
                address || null,
                objective || null,
                experience || null,
                education,
                trainings || null,
                portfolio || null,
                projects || null,
                skills,
                activities || null,
                additional || null,
                resumeId,
                userId
            ]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Resume not found or you do not have permission to update it.' });
        }
        res.status(200).json({ success: true, message: 'Resume updated successfully.' });
    } catch (error) {
        console.error('🚫 Update resume error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to update resume.' });
    }
});

app.delete('/api/resumes/:id', authenticateToken, async (req, res) => {
    const resumeId = req.params.id;
    const userId = req.user.id;

    try {
        const [result] = await db.query('DELETE FROM resumes WHERE id = ? AND user_id = ?', [resumeId, userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Resume not found or you do not have permission to delete it.' });
        }
        res.status(200).json({ success: true, message: 'Resume deleted successfully.' });
    } catch (error) {
        console.error('🚫 Delete resume error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to delete resume.' });
    }
});

app.get('/api/resume/download/:id', authenticateToken, async (req, res) => {
    const resumeId = req.params.id;
    const userId = req.user.id;

    try {
        const [resumes] = await db.query('SELECT * FROM resumes WHERE id = ? AND user_id = ?', [resumeId, userId]);
        if (resumes.length === 0) {
            return res.status(404).json({ success: false, message: 'Resume not found.' });
        }

        const resume = resumes[0];
        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: 50, bottom: 50, left: 50, right: 50 }
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=resume_${resumeId}.pdf`);

        doc.pipe(res);

        // Title
        doc.font('Times-Bold').fontSize(20).text(resume.name, { align: 'center' });
        doc.moveDown(0.5);

        // Contact Information
        doc.font('Times-Roman').fontSize(12);
        doc.text(resume.email, { align: 'center' });
        doc.text(resume.phone, { align: 'center' });
        if (resume.address) {
            doc.text(resume.address, { align: 'center' });
        }
        doc.moveDown(1);

        // Horizontal Line
        doc.lineWidth(1).moveTo(50, doc.y).lineTo(550, doc.y).stroke();
        doc.moveDown(1);

        // Objective
        if (resume.objective) {
            doc.font('Times-Bold').fontSize(14).text('Career Objective', { underline: true });
            doc.font('Times-Roman').fontSize(12).text(resume.objective, { align: 'justify' });
            doc.moveDown(1);
        }

        // Education
        doc.font('Times-Bold').fontSize(14).text('Education', { underline: true });
        doc.font('Times-Roman').fontSize(12);
        resume.education.split('\n').forEach(line => {
            doc.text(`• ${line.trim()}`, { indent: 20 });
        });
        doc.moveDown(1);

        // Experience
        if (resume.experience) {
            doc.font('Times-Bold').fontSize(14).text('Work Experience', { underline: true });
            doc.font('Times-Roman').fontSize(12);
            resume.experience.split('\n').forEach(line => {
                doc.text(`• ${line.trim()}`, { indent: 20 });
            });
            doc.moveDown(1);
        }

        // Trainings/Certifications
        if (resume.trainings) {
            doc.font('Times-Bold').fontSize(14).text('Trainings/Certifications', { underline: true });
            doc.font('Times-Roman').fontSize(12);
            resume.trainings.split('\n').forEach(line => {
                doc.text(`• ${line.trim()}`, { indent: 20 });
            });
            doc.moveDown(1);
        }

        // Portfolio
        if (resume.portfolio) {
            doc.font('Times-Bold').fontSize(14).text('Portfolio', { underline: true });
            doc.font('Times-Roman').fontSize(12).text(resume.portfolio);
            doc.moveDown(1);
        }

        // Projects
        if (resume.projects) {
            doc.font('Times-Bold').fontSize(14).text('Projects', { underline: true });
            doc.font('Times-Roman').fontSize(12);
            resume.projects.split('\n').forEach(line => {
                doc.text(`• ${line.trim()}`, { indent: 20 });
            });
            doc.moveDown(1);
        }

        // Skills
        doc.font('Times-Bold').fontSize(14).text('Skills', { underline: true });
        doc.font('Times-Roman').fontSize(12);
        resume.skills.split('\n').forEach(line => {
            doc.text(`• ${line.trim()}`, { indent: 20 });
        });
        doc.moveDown(1);

        // Activities
        if (resume.activities) {
            doc.font('Times-Bold').fontSize(14).text('Extra-Curricular Activities', { underline: true });
            doc.font('Times-Roman').fontSize(12);
            resume.activities.split('\n').forEach(line => {
                doc.text(`• ${line.trim()}`, { indent: 20 });
            });
            doc.moveDown(1);
        }

        // Additional Details
        if (resume.additional) {
            doc.font('Times-Bold').fontSize(14).text('Additional Details', { underline: true });
            doc.font('Times-Roman').fontSize(12);
            resume.additional.split('\n').forEach(line => {
                doc.text(`• ${line.trim()}`, { indent: 20 });
            });
            doc.moveDown(1);
        }

        // Footer
        doc.font('Times-Italic').fontSize(10).text('Powered by RecruitPro', { align: 'center', continued: false });

        doc.end();
    } catch (error) {
        console.error('🚫 Download resume error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to download resume.' });
    }
});

// Profile Endpoints
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [users] = await db.query('SELECT id, email, name, profile_pic FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.status(200).json(users[0]);
    } catch (error) {
        console.error('🚫 Fetch user profile error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch profile.' });
    }
});

app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
    const adminId = req.admin.id;

    try {
        const [admins] = await db.query('SELECT id, email, name, profile_pic FROM admins WHERE id = ?', [adminId]);
        if (admins.length === 0) {
            return res.status(404).json({ success: false, message: 'Admin not found.' });
        }
        res.status(200).json(admins[0]);
    } catch (error) {
        console.error('🚫 Fetch admin profile error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch admin profile.' });
    }
});

app.post('/api/update-profile', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const userId = req.headers['id'];
    const role = req.headers['role'];

    if (!token || !userId || !role) {
        return res.status(401).json({ success: false, message: 'Access denied: Token, user ID, or role missing.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== role) {
            return res.status(403).json({ success: false, message: 'Role mismatch.' });
        }

        if (role === 'user') {
            // Handle user profile update with file upload
            upload.single('profilePic')(req, res, async (err) => {
                if (err) {
                    return res.status(400).json({ success: false, message: err.message });
                }

                const { name, email, password } = req.body;

                if (!name && !email && !password && !req.file) {
                    return res.status(400).json({ success: false, message: 'At least one field (name, email, password, or profile picture) must be provided.' });
                }

                try {
                    const updates = {};
                    const params = [];

                    if (name) {
                        updates.name = name;
                        params.push(name);
                    }
                    if (email) {
                        const [existingEmail] = await db.query('SELECT * FROM users WHERE email = ? AND id != ?', [email, userId]);
                        if (existingEmail.length > 0) {
                            return res.status(409).json({ success: false, message: 'Email is already in use by another user.' });
                        }
                        updates.email = email;
                        params.push(email);
                    }
                    if (password) {
                        const hashedPassword = await bcrypt.hash(password, 10);
                        updates.password = hashedPassword;
                        params.push(hashedPassword);
                    }
                    if (req.file) {
                        // Delete old profile picture if exists
                        const [user] = await db.query('SELECT profile_pic FROM users WHERE id = ?', [userId]);
                        if (user[0].profile_pic) {
                            const oldPath = path.join(__dirname, user[0].profile_pic);
                            if (fs.existsSync(oldPath)) {
                                fs.unlinkSync(oldPath);
                            }
                        }
                        updates.profile_pic = `/uploads/profiles/${req.file.filename}`;
                        params.push(updates.profile_pic);
                    }

                    if (Object.keys(updates).length === 0) {
                        return res.status(400).json({ success: false, message: 'No valid fields to update.' });
                    }

                    params.push(userId);
                    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
                    await db.query(`UPDATE users SET ${setClause}, updated_at = NOW() WHERE id = ?`, params);

                    res.status(200).json({ success: true, message: 'Profile updated successfully!' });
                } catch (error) {
                    console.error('🚫 Update user profile error:', error.message);
                    res.status(500).json({ success: false, message: 'Failed to update profile.' });
                }
            });
        } else if (role === 'admin') {
            // Handle admin profile update without file upload
            const { name, email, password } = req.body;

            if (!name && !email && !password) {
                return res.status(400).json({ success: false, message: 'At least one field (name, email, password) must be provided.' });
            }

            try {
                const updates = {};
                const params = [];

                if (name) {
                    updates.name = name;
                    params.push(name);
                }
                if (email) {
                    const [existingEmail] = await db.query('SELECT * FROM admins WHERE email = ? AND id != ?', [email, userId]);
                    if (existingEmail.length > 0) {
                        return res.status(409).json({ success: false, message: 'Email is already in use by another admin.' });
                    }
                    updates.email = email;
                    params.push(email);
                }
                if (password) {
                    const hashedPassword = await bcrypt.hash(password, 10);
                    updates.password = hashedPassword;
                    params.push(hashedPassword);
                }

                if (Object.keys(updates).length === 0) {
                    return res.status(400).json({ success: false, message: 'No valid fields to update.' });
                }

                params.push(userId);
                const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
                await db.query(`UPDATE admins SET ${setClause}, updated_at = NOW() WHERE id = ?`, params);

                res.status(200).json({ success: true, message: 'Profile updated successfully!' });
            } catch (error) {
                console.error('🚫 Update admin profile error:', error.message);
                res.status(500).json({ success: false, message: 'Failed to update profile.' });
            }
        } else {
            return res.status(400).json({ success: false, message: 'Invalid role.' });
        }
    } catch (error) {
        console.error('🚫 Profile update authentication error:', error.message);
        res.status(403).json({ success: false, message: 'Invalid token.' });
    }
});

// Admin Endpoints
app.get('/api/users', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, email, name, role, verified, blocked, created_at FROM users');
        res.status(200).json(rows);
    } catch (error) {
        console.error('🚫 Fetch users error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch users.' });
    }
});

app.get('/api/users/count', authenticateAdmin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) as count FROM users WHERE blocked = FALSE');
        res.status(200).json({ success: true, count: rows[0].count });
    } catch (error) {
        console.error('🚫 Count users error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to count users.' });
    }
});

app.put('/api/users/block/:id', authenticateAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const [result] = await db.query('UPDATE users SET blocked = TRUE, updated_at = NOW() WHERE id = ?', [userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.status(200).json({ success: true, message: 'User blocked successfully.' });
    } catch (error) {
        console.error('🚫 Block user error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to block user.' });
    }
});

app.put('/api/users/unblock/:id', authenticateAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const [result] = await db.query('UPDATE users SET blocked = FALSE, updated_at = NOW() WHERE id = ?', [userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.status(200).json({ success: true, message: 'User unblocked successfully.' });
    } catch (error) {
        console.error('🚫 Unblock user error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to unblock user.' });
    }
});

app.delete('/api/users/:id', authenticateAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const [result] = await db.query('DELETE FROM users WHERE id = ?', [userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.status(200).json({ success: true, message: 'User deleted successfully.' });
    } catch (error) {
        console.error('🚫 Delete user error:', error.message);
        res.status(500).json({ success: false, message: 'Failed to delete user.' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});