const qrcode = require('qrcode');

const testQR = async () => {
    try {
        const qrData = JSON.stringify({
            id: '12345',
            username: 'testuser',
            type: "Encoded Complaint Info"
        });

        console.log("Generating QR...");
        const url = await qrcode.toDataURL(qrData);
        console.log("QR Generated successfully.");
        console.log("Start of Data URL:", url.substring(0, 50));
        console.log("Length:", url.length);
    } catch (err) {
        console.error("QR Generation Failed:", err);
    }
};

testQR();
