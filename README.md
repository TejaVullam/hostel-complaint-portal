🏠 Hostel Complaint Portal
Secure Complaint Management System (Cyber Security Lab Project)
📌 Project Overview

The Hostel Complaint Portal is a secure, role-based web application designed to manage hostel-related complaints efficiently while enforcing strong cybersecurity principles.

This system allows:

Students (Users) to submit and track complaints

Admin/Warden to review, assign, and manage complaints

Workers (Plumber, Electrician, etc.) to accept/reject and update complaint status

The project is implemented with authentication, authorization, encryption, hashing, JWT, OTP verification, and role-based access control, fulfilling all core Foundations of Cyber Security requirements.

🛡️ Security Features Implemented
🔐 Authentication

Username + Password login

Email-based OTP verification during registration

JWT (JSON Web Token) based session authentication

Token expiry handling

🔑 Authorization (Access Control)

Role-Based Access Control (RBAC)

USER

ADMIN / WARDEN

WORKER

Middleware-enforced authorization at API level

Least privilege principle applied

🔒 Encryption

AES-256-CBC used to encrypt complaint descriptions

Initialization Vector (IV) generated per complaint

Ciphertext stored securely in database

✍️ Digital Signatures

RSA public/private key pair

Complaints are digitally signed

Signature verification ensures:

Data integrity

Non-repudiation

🧂 Hashing

SHA-256 used for password hashing

Plain-text passwords are never stored

📧 Secure Email OTP

OTP sent via Gmail (App Password)

OTP stored temporarily with expiration (TTL)

📦 Database Security

MongoDB used for persistent storage

Encrypted data stored instead of plaintext

👥 System Roles & Responsibilities
👤 User (Student)

Register with email + OTP verification

Login securely using JWT

Submit encrypted complaints

View only their own complaints

View complaint QR code (tracking)

🛡️ Admin / Warden

View all complaints

Identify complaint origin

Assign complaints to workers

Monitor status updates

Acts as central authority

🛠️ Worker

Login using worker credentials

View complaints assigned by admin

Accept or reject complaints

Update complaint status & ETA

Notify admin through status updates

📊 Dashboard Features

Clean UI with role-specific dashboards

Real-time complaint status updates

QR code generated per complaint for tracking

Basic statistics (complaints count, status)

🗂️ Project Structure
hostel_complaint_portal/
│
├── config/
│   └── db.js                 # MongoDB connection configuration
│
├── keys/
│   ├── private.pem           # RSA private key (signing)
│   └── public.pem            # RSA public key (verification)
│
├── models/
│   ├── User.js               # User schema (user / admin / worker)
│   ├── Complaint.js          # Complaint schema (encrypted data)
│   └── OTP.js                # OTP schema (email verification)
│
├── routes/
│   ├── auth.js               # Authentication routes (register, login, OTP, JWT)
│   └── complaint.js          # Complaint routes (user, admin, worker actions)
│
├── utils/
│   ├── cryptoUtils.js        # AES encryption, RSA signing, hashing
│   └── emailService.js       # OTP email service (Nodemailer)
│
├── public/
│   ├── index.html            # Login & Registration page
│   ├── user.html             # User dashboard (submit & view complaints)
│   ├── admin.html            # Admin dashboard (assign complaints)
│   ├── worker.html           # Worker dashboard (update complaint status)
│   │
│   ├── css/
│   │   └── style.css         # Unified green-themed UI styles
│   │
│   └── js/
│       └── utils.js          # Frontend helper functions (fetch, JWT handling)
│
├── server.js                 # Main backend server (Express + JWT + AES + RSA)
├── test-qr.js                # QR code testing utility
├── .env                      # Environment variables (ignored in Git)
├── .gitignore                # Git ignore rules
├── package.json              # Project dependencies
├── package-lock.json         # Dependency lock file
└── README.md                 # Project documentation


⚙️ Technologies Used
Category	Technology
Backend	Node.js, Express.js
Frontend	HTML, CSS, JavaScript
Database	MongoDB
Authentication	JWT
Encryption	AES-256
Hashing	SHA-256
Digital Signature	RSA
Email	Nodemailer (Gmail)
QR Code	qrcode
Version Control	Git, GitHub
🚀 How to Run the Project
1️⃣ Clone the Repository
git clone https://github.com/TejaVullam/hostel-complaint-portal.git
cd hostel-complaint-portal

2️⃣ Install Dependencies
npm install

3️⃣ Configure Environment Variables

Create a .env file:

MONGO_URI=mongodb://127.0.0.1:27017/secure_complaint_db
JWT_SECRET=your_secret_key
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_gmail_app_password

4️⃣ Start MongoDB

Ensure MongoDB is running locally.

5️⃣ Run the Server
node server.js


Server runs on:

http://localhost:4000

🔍 Security Levels & Risk Analysis
Security Level: Moderate to High

Strong encryption for sensitive data

Token-based authentication

Role isolation prevents privilege escalation

Known Risks

No HTTPS (local environment)

JWT token theft if stored insecurely

Email OTP dependency on Gmail availability

Mitigations

Encrypted storage

Short-lived JWT tokens

OTP expiration

RBAC enforcement

🌳 Possible Attack Tree (Summary)

Credential brute force → mitigated by hashing

Token replay → JWT expiry

Data tampering → RSA signature verification

Unauthorized access → RBAC middleware

MITM → mitigated partially (encryption, but HTTPS recommended)

📚 Academic Relevance

This project demonstrates:

Authentication & Authorization

Encryption & Cryptographic analysis

Digital signatures

Secure system design

Practical application of cyber security concepts

👨‍🎓 Author

Teja Vullam
Foundations of Cyber Security
Semester 6 – Lab Evaluation Project

✅ Conclusion

The Hostel Complaint Portal is a secure, role-based, real-world complaint management system that successfully integrates core cyber security principles with a functional web application.
