const bcrypt = require('bcrypt');

const enteredPassword = 'admin123';  // The password you are using to log in
const hashedPassword = '$2b$10$CGpK9n96XxttnmVvh/Uv9u3yJznzGnuwtFQ8a2m11mkICfuPqKaZ6'; // The one stored in the database

bcrypt.compare(enteredPassword, hashedPassword, (err, result) => {
    if (err) {
        console.error("Error comparing passwords:", err);
    } else {
        console.log("Do passwords match?", result);
    }
});
