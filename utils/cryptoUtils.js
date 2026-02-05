const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- AES Configuration ---
// For simplicity in this lab, we use a fixed secret key.
// In production, this should be in an environment variable.
const AES_SECRET = crypto.createHash('sha256').update(process.env.AES_SECRET_PHRASE).digest();
const AES_ALGORITHM = 'aes-256-cbc';

// --- RSA Key Paths ---
const PRIVATE_KEY_PATH = path.join(__dirname, '../keys', 'private.pem');
const PUBLIC_KEY_PATH = path.join(__dirname, '../keys', 'public.pem');

// 1. Generate RSA Keys if not exist
const generateKeys = () => {
    if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
        console.log("Generating RSA Keys...");
        const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" }
        });

        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
        fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);
        console.log("RSA Keys Generated.");
    }
};

// 2. Encryption (AES)
const encryptData = (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, AES_SECRET, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        content: encrypted,
        iv: iv.toString('hex')
    };
};

// 3. Decryption (AES)
const decryptData = (encryptedData, ivHex) => {
    try {
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv(AES_ALGORITHM, AES_SECRET, iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error("Decryption failed:", err.message);
        return "[Decryption Failed]";
    }
};

// 4. Digital Signature (RSA-SHA256)
const signData = (data) => {
    const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'hex');
};

// 5. Verify Signature
const verifySignature = (data, signature) => {
    const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'hex');
};

module.exports = {
    generateKeys,
    encryptData,
    decryptData,
    signData,
    verifySignature
};
