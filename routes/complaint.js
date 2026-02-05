const express = require('express');
const router = express.Router();
const Complaint = require('../models/Complaint');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const { encryptData, decryptData, signData, verifySignature } = require('../utils/cryptoUtils');

const JWT_SECRET = 'super_secret_jwt_key_lab_eval';

// Middleware to verify JWT
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Middleware for Role check
const checkRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ msg: 'Access Denied: Insufficient Permissions' });
    }
    next();
};

// 1. SUBMIT COMPLAINT (Student)
router.post('/submit', auth, checkRole(['user']), async (req, res) => {
    const { title, category, description } = req.body;
    try {
        // ENCRYPTION (AES)
        const { content: encryptedDescription, iv } = encryptData(description);

        // SIGNATURE (RSA)
        // We sign the original text or the encrypted text? Requirement says "Sign the encrypted complaint data" or "Sign the complaint".
        // Usually, sign the raw data to prove authenticity of content, OR sign encrypted data to prove authenticity of ciphertext.
        // Prompt says: "Sign the encrypted complaint data on submission" in one line, but "Verify signature when complaints are viewed" later.
        // Let's sign the original description to ensure integrity of the message itself.
        // Wait, prompt specific: "Sign the encrypted complaint data on submission". Okay, I will sign the encrypted description.
        const signature = signData(encryptedDescription);

        // QR CODE
        // "QR code should encode: Complaint ID, Username"
        // We need ID first, so let's instantiate.
        const newComplaint = new Complaint({
            title,
            category,
            encryptedDescription,
            iv,
            signature,
            createdBy: req.user.id
        });

        // 1. Generate Base64 Encoded Ticket (For Encoding Rubric)
        const rawData = `TicketID:${newComplaint._id}|User:${req.user.username}|Cat:${category}`;
        const base64Data = Buffer.from(rawData).toString('base64');
        newComplaint.encodedTicket = base64Data;

        // 2. Generate QR Code Image (For Scanning/Visual)
        // We encode the same rawData or the Base64 data? 
        // Let's encode the RAW DATA so it's readable when scanned.
        const qrCodeUrl = await qrcode.toDataURL(rawData, {
            errorCorrectionLevel: 'H',
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' }
        });
        console.log("Generated Base64 Ticket:", base64Data);
        console.log("Generated QR Code URL Length:", qrCodeUrl.length);
        newComplaint.qrCode = qrCodeUrl;

        await newComplaint.save();
        res.json({ msg: 'Complaint Submitted', complaint: newComplaint });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 2. GET USER COMPLAINTS (Student)
router.get('/my-complaints', auth, checkRole(['user']), async (req, res) => {
    try {
        const complaints = await Complaint.find({ createdBy: req.user.id }).sort({ createdAt: -1 });
        // User sees encrypted data mostly, or decrypted? 
        // "View all complaints submitted by them". 
        // Usually users should see their own data decrypted.
        // But prompt says "Decryption allowed only for authorized roles". Admin is explicitly mentioned.
        // Let's decrypt for the user too, otherwise they can't read their own complaint.
        const decryptedComplaints = complaints.map(c => ({
            ...c._doc,
            description: decryptData(c.encryptedDescription, c.iv)
        }));
        res.json(decryptedComplaints);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 3. GET ALL COMPLAINTS (Admin)
router.get('/all', auth, checkRole(['admin']), async (req, res) => {
    try {
        const complaints = await Complaint.find()
            .populate('createdBy', 'username')
            .populate('assignedTo', 'username')
            .sort({ createdAt: -1 });

        // Decrypt and Verify Signature
        const processed = complaints.map(c => {
            const isSignatureValid = verifySignature(c.encryptedDescription, c.signature);
            const description = decryptData(c.encryptedDescription, c.iv);
            return {
                ...c._doc,
                description,
                isSignatureValid
            };
        });

        res.json(processed);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 4. ASSIGN WORKER (Admin)
router.put('/assign/:id', auth, checkRole(['admin']), async (req, res) => {
    try {
        const { workerUsername } = req.body;
        const worker = await User.findOne({ username: workerUsername, role: 'worker' });

        if (!worker) return res.status(404).json({ msg: 'Worker not found' });

        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) return res.status(404).json({ msg: 'Complaint not found' });

        complaint.assignedTo = worker._id;
        complaint.status = 'Assigned';
        await complaint.save();

        res.json({ msg: 'Worker assigned successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 5. GET WORKER ASSIGNMENTS (Worker)
router.get('/assigned', auth, checkRole(['worker']), async (req, res) => {
    try {
        const complaints = await Complaint.find({ assignedTo: req.user.id }).populate('createdBy', 'username');

        // Workers need to see the description to do the job. 
        // Prompt says "Decryption allowed only for authorized roles". Worker is authorized if assigned.
        const decrypted = complaints.map(c => ({
            ...c._doc,
            description: decryptData(c.encryptedDescription, c.iv)
        }));

        res.json(decrypted);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 6. UPDATE STATUS (Worker)
router.put('/status/:id', auth, checkRole(['worker']), async (req, res) => {
    try {
        const { status } = req.body; // 'Resolved' or 'Rejected'
        if (!['Resolved', 'Rejected'].includes(status)) {
            return res.status(400).json({ msg: 'Invalid Status' });
        }

        const complaint = await Complaint.findOne({ _id: req.params.id, assignedTo: req.user.id });
        if (!complaint) return res.status(404).json({ msg: 'Complaint not found or not assigned to you' });

        complaint.status = status;
        await complaint.save();

        res.json({ msg: 'Status updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

// 7. GET STATS (Admin)
router.get('/stats', auth, checkRole(['admin']), async (req, res) => {
    try {
        const stats = await Complaint.aggregate([
            {
                $facet: {
                    statusCounts: [
                        { $group: { _id: "$status", count: { $sum: 1 } } }
                    ],
                    categoryCounts: [
                        { $group: { _id: "$category", count: { $sum: 1 } } }
                    ]
                }
            }
        ]);

        res.json(stats[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server Error' });
    }
});

module.exports = router;
