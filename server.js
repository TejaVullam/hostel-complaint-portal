const express = require('express');
require('dotenv').config();
const connectDB = require('./config/db');
const cors = require('cors');
const path = require('path');
const { generateKeys } = require('./utils/cryptoUtils');

// Initialize App
const app = express();

// Connect Database
connectDB();

const User = require('./models/User');
const bcrypt = require('bcryptjs');

// Generate Crypto Keys (if missing)
generateKeys();

// Seed Database (Admin + Workers)
const seedDatabase = async () => {
    try {
        const users = [
            { username: 'admin', email: 'admin@hostel.com', pass: 'admin123', role: 'admin' },
            { username: 'plumber', email: 'plumber@hostel.com', pass: 'worker123', role: 'worker' },
            { username: 'electrician', email: 'electrician@hostel.com', pass: 'worker123', role: 'worker' },
            { username: 'carpenter', email: 'carpenter@hostel.com', pass: 'worker123', role: 'worker' }
        ];

        for (const u of users) {
            const exists = await User.findOne({ username: u.username });
            if (!exists) {
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(u.pass, salt);

                await User.create({
                    username: u.username,
                    email: u.email,
                    password: hashedPassword,
                    role: u.role,
                    isVerified: true
                });
                console.log(`[SEED] Created: ${u.username} / ${u.pass}`);
            }
        }
    } catch (err) {
        console.error('Seeding Error:', err);
    }
};

seedDatabase();

// Middleware
app.use(express.json());
app.use(cors());

// Serve Static Files (Frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Define Routes
console.log("Registering /api/auth routes...");
app.use('/api/auth', require('./routes/auth'));
app.use('/api/complaints', require('./routes/complaint'));

// Default Route serves index.html
// Default Route serves index.html
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
