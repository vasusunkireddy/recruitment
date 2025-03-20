const bcrypt = require('bcrypt');

const newPassword = 'admin123';  // Set the new password you want for the admin
const saltRounds = 10;

bcrypt.hash(newPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error("Error hashing password:", err);
    } else {
        console.log("New Hashed Password:", hash);
    }
});
