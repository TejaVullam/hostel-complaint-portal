const nodemailer = require('nodemailer');
require('dotenv').config();

const sendOTP = async (email, otp) => {
    // ALWAYS Log to console for Lab Evaluation/Debugging
    console.log("=================================================");
    console.log(`[SERVER LOG] Email to: ${email}`);
    console.log(`[SERVER LOG] OTP: ${otp}`);
    console.log("=================================================");

    // If no credentials, just return
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        return;
    }

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Hostel Portal Registration OTP',
        text: `Your OTP for registration is: ${otp}. It expires in 5 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${email}`);
    } catch (error) {
        console.error("Error sending email:", error);
        // Fallback to console in case of error too
        console.log(`[FALLBACK] OTP for ${email}: ${otp}`);
    }
};

module.exports = sendOTP;
