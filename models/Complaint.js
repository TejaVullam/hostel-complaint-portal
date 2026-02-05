const mongoose = require('mongoose');

const ComplaintSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    category: {
        type: String,
        required: true,
        enum: ['Plumbing', 'Electrical', 'Furniture', 'Other']
    },
    // AES-256 Encrypted Description
    encryptedDescription: {
        type: String,
        required: true
    },
    // Initialization Vector for AES
    iv: {
        type: String,
        required: true
    },
    // RSA Digital Signature of the original description
    signature: {
        type: String,
        required: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    assignedTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    status: {
        type: String,
        enum: ['Pending', 'Assigned', 'Resolved', 'Rejected'],
        default: 'Pending'
    },
    encodedTicket: {
        type: String // Base64 Encoded Text
    },
    qrCode: {
        type: String // Qr Code Image Data URL
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Complaint', ComplaintSchema);
