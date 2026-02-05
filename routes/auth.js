const express = require('express');
const router = express.Router();
console.log("Auth Router Loaded. Routes: /register, /verify-otp, /login-otp-request, /login");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const OTP = require('../models/OTP');
const sendOTP = require('../utils/emailService');

const JWT_SECRET = process.env.JWT_SECRET; // Loaded from .env

// 1. REGISTER
router.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        // Validation
        if (!username || !email || !password) return res.status(400).json({ msg: 'All fields required' });

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) return res.status(400).json({ msg: 'User already exists' });

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save OTP
        await OTP.create({ email, otp });

        // Send OTP
        await sendOTP(email, otp);

        // Hash Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save User (unverified)
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role: role || 'user',
            isVerified: false
        });
        await newUser.save();

        res.json({ msg: 'Registration successful. OTP sent to email/console.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 2. VERIFY OTP
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const otpRecord = await OTP.findOne({ email, otp });
        if (!otpRecord) return res.status(400).json({ msg: 'Invalid or Expired OTP' });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ msg: 'User not found' });

        user.isVerified = true;
        await user.save();

        // Delete OTP after usage
        await OTP.deleteOne({ _id: otpRecord._id });

        res.json({ msg: 'Email Verified. You can now login.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 3. LOGIN (Password)
// 3. LOGIN STEP 1: Validate Password & Send OTP
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ msg: 'Invalid Credentials' });

        if (!user.isVerified) return res.status(403).json({ msg: 'Account not verified. Please verify registration OTP first.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid Credentials' });

        // MFA: Generate OTP for Login
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save OTP (Upsert to handle re-tries)
        await OTP.findOneAndUpdate(
            { email: user.email },
            { otp, email: user.email },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        // Send OTP
        await sendOTP(user.email, otp);

        res.json({ msg: 'Credentials Valid. OTP sent to email. Please verify to complete login.', step: 'mfa_required', email: user.email });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 4. LOGIN STEP 2: Verify OTP & Issue Token
router.post('/login-verify-mfa', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const otpRecord = await OTP.findOne({ email, otp });
        if (!otpRecord) return res.status(400).json({ msg: 'Invalid or Expired OTP' });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ msg: 'User not found' });

        // Helper to check for default accounts (optional, but good for testing)
        // In this logic, every user including admin must MFA.

        // Delete OTP
        await OTP.deleteOne({ _id: otpRecord._id });

        // Issue Token
        const payload = {
            user: {
                id: user.id,
                role: user.role,
                username: user.username
            }
        };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, role: user.role, username: user.username });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

module.exports = router;
