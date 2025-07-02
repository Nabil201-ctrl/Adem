import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { body, param, validationResult, query } from 'express-validator';
import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary'; // NEW: Import Cloudinary storage for Multer
import { v2 as cloudinary } from 'cloudinary';
import path from 'path';

dotenv.config();

const app = express();

// Configure CORS (unchanged)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json());

// Validate environment variables
const requiredEnv = [
    'MONGO_URI',
    'JWT_SECRET',
    'GMAIL_USER',
    'GMAIL_PASS',
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'ADMIN_SECRET_KEY'
];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`❌ Missing environment variable: ${env}`);
        process.exit(1);
    }
}


// NEW: Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Multer for file uploads to Cloudinary
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'payment-slips', // Cloudinary folder for organization
        allowed_formats: ['jpeg', 'jpg', 'png', 'pdf'], // Allowed file types
        resource_type: 'auto' // Automatically detect file type (image or raw for PDFs)
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|pdf/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, and PDF allowed.'), false);
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});


// MongoDB Connection
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ MongoDB connected');
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
}
connectDB();

// Schemas


const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, index: true, lowercase: true },
    password: { type: String, required: true },
    userType: { type: String, enum: ['admin', 'student'], required: true },
    matricNumber: {
        type: String,
        unique: true,
        sparse: true,
        match: [/^\d{2}\/[A-Z0-9]{6}\/\d{3}$/, 'Invalid matric number format (e.g., 23/208CSE/786)'],
        required: function () { return this.userType === 'student'; }
    },
    phone: {
        type: String,
        match: /^\+?[\d\s()-]{10,}$/,
        required: function () { return this.userType === 'student'; }
    },
    gender: {
        type: String,
        enum: ['Male'],
        required: function () { return this.userType === 'student'; }
    },
    dateOfBirth: {
        type: Date,
        required: function () { return this.userType === 'student'; }
    },
    faculty: {
        type: String,
        trim: true,
        required: function () { return this.userType === 'student'; }
    },
    level: {
        type: String,
        required: function () { return this.userType === 'student'; },
        match: [/^(100|200|300|400|500|600|700)level$/, 'Invalid level (e.g., 400level)']
    },
    department: {
        type: String,
        trim: true,
        required: function () { return this.userType === 'student'; }
    },
    room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room' },
    status: { type: String, enum: ['Pending', 'Approved', 'Declined'], default: 'Pending' },
    otp: { type: String },
    otpExpires: { type: Date },
    interviewDate: { type: Date },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    avatar: { type: String, default: '' }, // Profile picture URL
    notifications: {
        email: { type: Boolean, default: true }, // Email notifications for payments
        newStudent: { type: Boolean, default: true }, // Notifications for new student registrations
        maintenance: { type: Boolean, default: false } // Notifications for system maintenance
    },
    security: {
        twoFactorAuth: { type: Boolean, default: false }, // 2FA setting
        twoFactorSecret: { type: String } // Optional: for storing 2FA secret if implementing TOTP
    },
    preferences: {
        language: { type: String, enum: ['en', 'fr', 'es'], default: 'en' }, // Language preference
        timezone: { type: String, enum: ['GMT+0', 'GMT+1', 'GMT+2'], default: 'GMT+1' } // Timezone preference
    },
    avatar: {
        url: { type: String, default: '' }, // Cloudinary URL
        publicId: { type: String, default: '' } // Cloudinary public ID for deletion
  }
});


const RoomSchema = new mongoose.Schema({
    roomNumber: { type: String, required: true, unique: true, index: true },
    type: { type: String, enum: ['Standard', 'Premium'], required: true },
    capacity: { type: Number, required: true, min: 1 },
    occupants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    status: { type: String, enum: ['Occupied', 'Available', 'Maintenance'], default: 'Available' },
    createdAt: { type: Date, default: Date.now },
});

const EventSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    date: { type: Date, required: true, index: true },
    time: { type: String, required: true, match: /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/ },
    description: { type: String, trim: true },
    status: { type: String, enum: ['Scheduled', 'Pending', 'Cancelled'], default: 'Scheduled' },
    createdAt: { type: Date, default: Date.now },
});

const MaintenanceSchema = new mongoose.Schema({
    room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
    issue: { type: String, required: true, trim: true },
    type: { type: String, enum: ['warning', 'danger'], default: 'warning' },
    icon: { type: String, default: 'wrench' },
    status: { type: String, enum: ['Open', 'Resolved'], default: 'Open' },
    createdAt: { type: Date, default: Date.now },
});

const SettingsSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    notifications: {
        email: { type: Boolean, default: true },
        newStudent: { type: Boolean, default: true },
        maintenance: { type: Boolean, default: true },
    },
    updatedAt: { type: Date, default: Date.now },
});

const PaymentSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 0 },
    status: { type: String, enum: ['Paid', 'Pending', 'Overdue'], default: 'Pending' },
    createdAt: { type: Date, default: Date.now, index: true },
    transactionRef: { type: String } // Added for Paystack integration
});

const PaymentSlipSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fileUrl: { type: String, required: true }, // Updated: Store Cloudinary URL instead of filePath
    publicId: { type: String, required: true }, // NEW: Store Cloudinary public ID for deletion
    fileType: { type: String, enum: ['image', 'raw'], required: true }, // NEW: Store file type (image or raw for PDF)
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    amount: { type: Number, required: true, min: 0 },
    createdAt: { type: Date, default: Date.now, index: true },
});

const RegistrationDeadlineSchema = new mongoose.Schema({
    deadline: { type: Date, required: true },
    extended: { type: Boolean, default: false },
    extendedDeadline: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    type: { type: String, enum: ['info', 'warning', 'alert'], default: 'info' },
    createdAt: { type: Date, default: Date.now }
});


const Notification = mongoose.model('Notification', NotificationSchema);
const RegistrationDeadline = mongoose.model('RegistrationDeadline', RegistrationDeadlineSchema);
const User = mongoose.model('User', UserSchema);
const Room = mongoose.model('Room', RoomSchema);
const Event = mongoose.model('Event', EventSchema);
const Maintenance = mongoose.model('Maintenance', MaintenanceSchema);
const Settings = mongoose.model('Settings', SettingsSchema);
const Payment = mongoose.model('Payment', PaymentSchema);
const PaymentSlip = mongoose.model('PaymentSlip', PaymentSlipSchema);

// Nodemailer Setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});

async function sendEmail(recipient, subject, text, html) {
    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: recipient,
        subject,
        text,
        html,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Email sent:', info.response);
        return info;
    } catch (error) {
        console.error('❌ Error sending email:', error);
        throw new Error(`Failed to send email: ${error.message}`);
    }
}


// Password Hashing
const SALT_ROUNDS = 10;
async function hashing(plainPassword) {
    return await bcrypt.hash(plainPassword, SALT_ROUNDS);
}

// Generate OTP
function generateOTP() {
    return crypto.randomBytes(3).toString('hex').toUpperCase();
}

// JWT Token Generation
function generateToken(user) {
    return jwt.sign(
        { id: user._id, email: user.email, userType: user.userType, name: user.name },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
}

// Token Verification Middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: { message: 'Access denied. Token missing.', code: 'NO_TOKEN' } });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        return res.status(403).json({ error: { message: 'Invalid token', code: 'INVALID_TOKEN' } });
    }
}

// Admin Middleware
function isAdmin(req, res, next) {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: { message: 'Access denied. Admins only.', code: 'ADMIN_ONLY' } });
    }
    next();
}

// Student Middleware
function isStudent(req, res, next) {
    if (req.user.userType !== 'student') {
        return res.status(403).json({ error: { message: 'Access denied. Students only.', code: 'STUDENT_ONLY' } });
    }
    next();
}

// Multer Error Handling Middleware
function handleMulterError(err, req, res, next) {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: { message: err.message, code: 'MULTER_ERROR' } });
    } else if (err) {
        return res.status(400).json({ error: { message: err.message, code: 'FILE_ERROR' } });
    }
    next();
}

// Routes
app.get('/api/protected', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('name email userType').lean();
        if (!user) {
            return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
        }
        res.json({
            message: 'This is protected data',
            user: { id: user._id, name: user.name, email: user.email, userType: user.userType },
        });
    } catch (error) {
        console.error('❌ Protected Route Error:', error);
        res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
    }
});

app.post(
    '/api/register',
    [
        body('email').isEmail().withMessage('Invalid email format'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('userType').isIn(['admin', 'student']).withMessage('Invalid user type'),
        body('adminSecretKey')
            .if(body('userType').equals('admin'))
            .notEmpty().withMessage('Admin secret key is required for admin registration'),
        body('matricNumber')
            .if(body('userType').equals('student'))
            .notEmpty().withMessage('Matric number is required for students')
            .matches(/^\d{2}\/[A-Z0-9]{6}\/\d{3}$/).withMessage('Invalid matric number format (e.g., 23/208CSE/786)'),
        body('phone')
            .if(body('userType').equals('student'))
            .notEmpty().withMessage('Phone number is required for students')
            .matches(/^\+?[\d\s()-]{10,}$/).withMessage('Invalid phone number format'),
        body('gender')
            .if(body('userType').equals('student'))
            .isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender'),
        body('dateOfBirth')
            .if(body('userType').equals('student'))
            .isISO8601().toDate().withMessage('Invalid date of birth')
            .custom((value) => {
                const dob = new Date(value);
                const today = new Date();
                if (dob >= today || today.getFullYear() - dob.getFullYear() < 15) {
                    throw new Error('Must be at least 15 years old');
                }
                return true;
            }),
        body('faculty')
            .if(body('userType').equals('student'))
            .trim().notEmpty().withMessage('Faculty is required for students'),
        body('level')
            .if(body('userType').equals('student'))
            .matches(/^(100|200|300|400|500|600|700)level$/).withMessage('Invalid level (e.g., 400level)'),
        body('department')
            .if(body('userType').equals('student'))
            .trim().notEmpty().withMessage('Department is required for students'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { email, password, userType, name, adminSecretKey, matricNumber, phone, gender, dateOfBirth, faculty, level, department } = req.body;

            // Check registration deadline for students
            if (userType === 'student') {
                const deadline = await RegistrationDeadline.findOne();
                const now = new Date();

                if (deadline) {
                    const currentDeadline = deadline.extended && deadline.extendedDeadline ? deadline.extendedDeadline : deadline.deadline;
                    if (now > currentDeadline) {
                        return res.status(403).json({
                            error: {
                                message: 'The Adem Baba Hostel has closed the page for booking hostel.',
                                code: 'REGISTRATION_CLOSED',
                                deadline: currentDeadline
                            }
                        });
                    }
                } else {
                    return res.status(403).json({
                        error: {
                            message: 'The Adem Baba Hostel has closed the page for booking hostel.',
                            code: 'NO_DEADLINE_SET'
                        }
                    });
                }
            }

            // Admin-specific checks
            if (userType === 'admin') {
                // Verify admin secret key
                if (adminSecretKey !== process.env.ADMIN_SECRET_KEY) {
                    return res.status(403).json({
                        error: {
                            message: 'Invalid admin secret key. Admin registration is restricted.',
                            code: 'INVALID_ADMIN_KEY'
                        }
                    });
                }

                // Check admin count
                const adminCount = await User.countDocuments({ userType: 'admin' });
                if (adminCount >= 2) {
                    return res.status(403).json({
                        error: {
                            message: 'Maximum number of admin accounts (2) has been reached.',
                            code: 'ADMIN_LIMIT_EXCEEDED'
                        }
                    });
                }
            }

            const existingUser = await User.findOne({ $or: [{ email }, { matricNumber: matricNumber || null }] });
            if (existingUser) {
                return res.status(400).json({ error: { message: 'Email or matric number already exists', code: 'DUPLICATE' } });
            }

            const hashedPassword = await hashing(password);
            const user = new User({
                name,
                email,
                password: hashedPassword,
                userType,
                matricNumber: userType === 'student' ? matricNumber : undefined,
                phone: userType === 'student' ? phone : undefined,
                gender: userType === 'student' ? gender : undefined,
                dateOfBirth: userType === 'student' ? dateOfBirth : undefined,
                faculty: userType === 'student' ? faculty : undefined,
                level: userType === 'student' ? level : undefined,
                department: userType === 'student' ? department : undefined,
                status: userType === 'student' ? 'Pending' : 'Approved',
            });
            await user.save();

            if (userType === 'student') {
                const admins = await User.find({ userType: 'admin' });
                for (const admin of admins) {
                    const settings = await Settings.findOne({ user: admin._id });
                    if (settings?.notifications.newStudent) {
                        await sendEmail(
                            admin.email,
                            'Student Registration Request – Approval Needed',
                            `A new student named ${name} (${email}) with Matric Number ${matricNumber} has submitted a registration request and is awaiting your approval.`,
                            `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">📌 New Student Registration Request</h2>
        <p><strong>Student Name:</strong> ${name}</p>
        <p><strong>Email Address:</strong> ${email}</p>
        <p><strong>Matric Number:</strong> ${matricNumber}</p>
        <hr style="margin: 20px 0;" />
        <p>Please log in to the Admin Dashboard to review and approve this request.</p>
        <p style="font-size: 12px; color: #666;">If you did not expect this email or believe it was sent in error, please disregard it.</p>
    </div>
    `
                        );
                    }
                }
            } else {
                await sendEmail(
                    email,
                    'Welcome to Adem Baba – Admin Access Granted',
                    `Hello ${name}, you have been successfully registered as an Admin for Adem Baba. Your account is now active.`,
                    `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🎉 Welcome to Adem Baba</h2>
        <p>Hi <strong>${name}</strong>,</p>
        <p>We're excited to let you know that your admin account has been successfully activated.</p>
        <p>You now have full access to the Admin Dashboard and can begin managing the platform.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you have any questions or need help getting started, feel free to contact support.</p>
    </div>
    `
                );
            }

            res.status(201).json({ message: 'Registration successful.' });
        } catch (error) {
            console.error('❌ Registration Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

// Generate OTP (Admin)
app.post(
    '/api/students/generate-otp',
    verifyToken,
    isAdmin,
    [body('studentId').isMongoId().withMessage('Invalid student ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { studentId } = req.body;
            const student = await User.findById(studentId);
            if (!student || student.userType !== 'student' || student.status !== 'Pending') {
                return res.status(404).json({ error: { message: 'Student not found or not pending', code: 'NOT_FOUND' } });
            }

            if (student.interviewDate && student.interviewDate > new Date()) {
                return res.status(400).json({ error: { message: 'Interview not yet conducted', code: 'INTERVIEW_PENDING' } });
            }

            const otp = generateOTP();
            const otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
            student.otp = otp;
            student.otpExpires = otpExpires;
            student.status = 'Approved';
            await student.save();

            const frontendUrl = 'http://127.0.0.1:5500/login-form/verify-otp.html';
            await sendEmail(
                student.email,
                'Adem Baba – Your One-Time Password (OTP)',
                `Hello ${student.name}, your registration has been approved. Use the OTP ${otp} to activate your account. It will expire in 24 hours. Verify at ${frontendUrl}.`,
                `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">✅ Account Approved – Your OTP</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>Your registration request for Adem Baba has been approved.</p>
        <p>Please use the following One-Time Password (OTP) to activate your account:</p>
        <p style="font-size: 24px; font-weight: bold; background-color: #f5f5f5; padding: 10px; border-radius: 6px; text-align: center;">${otp}</p>
        <p>This OTP will expire in <strong>24 hours</strong>.</p>
        <p>
            <a href="${frontendUrl}" style="display: inline-block; background-color: #0073bb; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">Verify OTP</a>
        </p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you did not request this, please ignore this message.</p>
    </div>
    `
            );

            res.json({ message: 'OTP generated and sent to student' });
        } catch (error) {
            console.error('❌ Generate OTP Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

// Verify OTP (Student)
app.post(
    '/api/verify-otp',
    [
        body('email').isEmail().withMessage('Invalid email format'),
        body('otp').notEmpty().withMessage('OTP is required'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { email, otp } = req.body;
            const student = await User.findOne({ email, userType: 'student' });
            if (!student) {
                return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
            }

            if (student.status !== 'Approved' || !student.otp || student.otp !== otp || student.otpExpires < Date.now()) {
                return res.status(400).json({ error: { message: 'Invalid or expired OTP', code: 'INVALID_OTP' } });
            }

            student.isVerified = true;
            student.otp = undefined;
            student.otpExpires = undefined;
            await student.save();

            const token = generateToken(student);
            res.json({
                message: 'Account activated successfully',
                token,
                user: { id: student._id, name: student.name, email: student.email, userType: student.userType },
            });
        } catch (error) {
            console.error('❌ Verify OTP Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

app.post(
    '/api/login',
    [
        body('email').isEmail().withMessage('Invalid email format'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { email, password } = req.body;
            const user = await User.findOne({ email }).select('+password');
            if (!user) {
                console.log(`Login attempt with non-existent email: ${email}`);
                return res.status(400).json({ error: { message: 'Invalid email', code: 'NOT_FOUND' } });
            }

            // Admin-specific checks
            if (user.userType === 'admin') {
                // Verify admin count to ensure no more than two admins are active
                const adminCount = await User.countDocuments({ userType: 'admin', status: 'Approved' });
                if (adminCount > 2) {
                    console.error(`Login attempt blocked: Too many admin accounts detected (count: ${adminCount})`);
                    return res.status(403).json({
                        error: {
                            message: 'Login restricted: Maximum number of admin accounts exceeded. Contact support.',
                            code: 'ADMIN_LIMIT_EXCEEDED'
                        }
                    });
                }

                // Ensure admin account is approved
                if (user.status !== 'Approved') {
                    console.log(`Admin login attempt with non-approved account: ${email}`);
                    return res.status(403).json({
                        error: {
                            message: 'Admin account not approved. Contact support.',
                            code: 'ADMIN_NOT_APPROVED'
                        }
                    });
                }

                // Log admin login attempt for auditing
                console.log(`Admin login attempt: ${email} at ${new Date().toISOString()}`);
            }

            // Student-specific checks
            if (user.userType === 'student') {
                if (user.status === 'Pending') {
                    return res.status(403).json({ error: { message: 'Account awaiting approval', code: 'PENDING' } });
                }

                if (user.status === 'Declined') {
                    return res.status(403).json({ error: { message: 'Account declined', code: 'DECLINED' } });
                }

                if (!user.isVerified) {
                    return res.status(403).json({ error: { message: 'Account not verified. Please verify your OTP.', code: 'NOT_VERIFIED' } });
                }
            }

            // Verify password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.log(`Invalid password attempt for: ${email}`);
                return res.status(400).json({ error: { message: 'Invalid password', code: 'INVALID_CREDENTIALS' } });
            }

            // Check payment status for students
            let needsPayment = false;
            if (user.userType === 'student') {
                const paymentSlip = await PaymentSlip.findOne({ student: user._id, status: 'Approved' });
                needsPayment = !paymentSlip;
            }

            // Generate JWT token
            const token = generateToken(user);
            res.json({
                message: 'Login successful',
                token,
                user: { id: user._id, name: user.name, email: user.email, userType: user.userType },
                needsPayment,
            });

            console.log(`Successful login: ${email} (${user.userType}) at ${new Date().toISOString()}`);
        } catch (error) {
            console.error('❌ Login Error:', error);
            res.status(500).json({ error: { message: 'Server error during login', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

// Get All Users
app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find().select('name email userType status createdAt').lean();
        res.json(users);
    } catch (error) {
        console.error('❌ Users Error:', error);
        res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
    }
});

// Admin Dashboard
app.get('/api/dashboard', verifyToken, isAdmin, async (req, res) => {
    try {
        const totalStudents = await User.countDocuments({ userType: 'student' });
        const occupiedRooms = await Room.countDocuments({ status: 'Occupied' });
        const monthlyRevenue = await Payment.aggregate([
            {
                $match: {
                    status: 'Paid',
                    createdAt: {
                        $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
                        $lt: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1),
                    },
                },
            },
            { $group: { _id: null, total: { $sum: '$amount' } } },
        ]).then((result) => result[0]?.total || 0);
        const pendingRequests = await User.countDocuments({ userType: 'student', status: 'Pending' });

        res.json({
            totalStudents,
            occupiedRooms,
            monthlyRevenue,
            pendingRequests,
        });
    } catch (error) {
        console.error('❌ Dashboard Error:', error);
        res.status(500).json({ error: { message: 'Failed to load dashboard data', code: 'SERVER_ERROR' } });
    }

});

// Student Dashboard
app.get('/api/student/dashboard', verifyToken, isStudent, async (req, res) => {
    try {
        // Check for an approved payment slip
        const paymentSlip = await PaymentSlip.findOne({
            student: req.user.id,
            status: 'Approved',
        }).lean();

        // If no approved payment slip exists, return a 403 with redirect instruction
        if (!paymentSlip) {
            return res.status(403).json({
                error: {
                    message: 'Payment required. Please upload a payment slip.',
                    code: 'PAYMENT_REQUIRED',
                    redirect: '/login-form/payment-upload.html', // Frontend path for payment upload
                },
            });
        }

        // Proceed with dashboard data if payment is approved
        const student = await User.findById(req.user.id)
            .select('name email matricNumber room dateOfBirth faculty level department')
            .populate('room', 'roomNumber type')
            .lean();

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const weekEnd = new Date(today);
        weekEnd.setDate(weekEnd.getDate() + 7);

        const upcomingEvents = await Event.find({
            date: { $gte: today, $lt: weekEnd },
            status: 'Scheduled',
        })
            .sort({ date: 1 })
            .limit(5)
            .lean();

        const latestPaymentSlip = await PaymentSlip.findOne({
            student: req.user.id,
        })
            .sort({ createdAt: -1 })
            .lean();

        res.json({
            student: {
                name: student.name,
                email: student.email,
                matricNumber: student.matricNumber,
                dateOfBirth: student.dateOfBirth,
                faculty: student.faculty,
                level: student.level,
                department: student.department,
                room: student.room ? { roomNumber: student.room.roomNumber, type: student.room.type } : null,
            },
            upcomingEvents,
            paymentStatus: latestPaymentSlip
                ? { amount: latestPaymentSlip.amount, status: latestPaymentSlip.status }
                : null,
        });
    } catch (error) {
        console.error('❌ Student Dashboard Error:', error);
        res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
    }
});



// Student Stats
app.get('/api/students/stats', verifyToken, isAdmin, async (req, res) => {
    try {
        const totalStudents = await User.countDocuments({ userType: 'student' });
        const maleStudents = await User.countDocuments({ userType: 'student', gender: 'Male' });
        const pendingApplications = await User.countDocuments({ userType: 'student', status: 'Pending' });

        res.json({
            totalStudents,
            maleStudents,
            pendingApplications,
        });
    } catch (error) {
        console.error('❌ Student Stats Error:', error);
        res.status(500).json({ error: { message: 'Failed to load student stats', code: 'SERVER_ERROR' } });
    }
});

// Get Students
app.get('/api/students', verifyToken, isAdmin, async (req, res) => {
    try {
        const students = await User.find({ userType: 'student' })
            .select('name email userType status createdAt matricNumber phone gender dateOfBirth faculty level department room interviewDate')
            .populate('room', 'roomNumber')
            .lean();
        res.json(students);
    } catch (error) {
        console.error('❌ Students Error:', error);
        res.status(500).json({ error: { message: 'Failed to load students', code: 'SERVER_ERROR' } });
    }
});

// Pending Requests
app.get('/api/pending-requests', verifyToken, isAdmin, async (req, res) => {
    try {
        const requests = await User.find({ userType: 'student', status: 'Pending' })
            .select('name email matricNumber phone gender dateOfBirth faculty level department createdAt status _id interviewDate')
            .lean();
        res.json({ requests });
    } catch (error) {
        console.error('❌ Pending Requests Error:', error);
        res.status(500).json({ error: { message: 'Failed to load pending requests', code: 'SERVER_ERROR' } });
    }
});

// Accept Request (Schedule Interview)
app.post(
    '/api/accept-request',
    verifyToken,
    isAdmin,
    [
        body('studentId').isMongoId().withMessage('Invalid student ID'),
        body('interviewDate').isISO8601().toDate().withMessage('Invalid interview date')
            .custom((value) => {
                const interview = new Date(value);
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                if (interview < today) {
                    throw new Error('Interview date must be in the future');
                }
                return true;
            }),
        body('interviewTime').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { studentId, interviewDate, interviewTime } = req.body;
            const student = await User.findById(studentId);
            if (!student || student.userType !== 'student' || student.status !== 'Pending') {
                return res.status(404).json({ error: { message: 'Student not found or not pending', code: 'NOT_FOUND' } });
            }

            const [hours, minutes] = interviewTime.split(':');
            const interviewDateTime = new Date(interviewDate);
            interviewDateTime.setHours(parseInt(hours), parseInt(minutes));

            student.interviewDate = interviewDateTime;
            await student.save();

            const interviewFileUrl = 'https://www.dropbox.com/scl/fi/rtqbr66dqjvs7y8o8rx5u/UNIVERSITY-OF-ABUJA-ADEM-BABA-HOSTEL-FORM.pdf?rlkey=d3x9ahnebbekdwtdniqxxweon&st=d79hytj4&dl=1'; // dl=1 for direct download
            try {
                const attachment = await fetchFileForAttachment(interviewFileUrl, 'interview-instructions.pdf');
                await sendEmail(
                    student.email,
                    'Adem Baba – Interview Invitation',
                    `Hello ${student.name}, your registration has been accepted. You are invited for an interview on ${interviewDateTime.toLocaleString()} at the Adem Baba Hostel Office. Please review the attached interview instructions.`,
                    `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">📅 Interview Scheduled</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>Congratulations! Your registration request has been accepted.</p>
        <p>You are invited to attend an in-person interview. Please find the details below:</p>
        <ul style="line-height: 1.6;">
            <li><strong>Date:</strong> ${interviewDateTime.toLocaleDateString()}</li>
            <li><strong>Time:</strong> ${interviewTime}</li>
            <li><strong>Location:</strong> Adem Baba Hostel Office</li>
        </ul>
        <p>📎 Please refer to the attached document for interview guidelines and expectations.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you have any questions or are unable to attend, please contact the office as soon as possible.</p>
    </div>
    `,
                    [attachment]
                );

            } catch (fetchError) {
                console.error('❌ Failed to fetch interview document:', fetchError);
                // Fallback: Send email without attachment
                await sendEmail(
                    student.email,
                    'Adem Baba – Interview Invitation',
                    `Hello ${student.name}, your registration has been accepted. You are invited for an interview on ${interviewDateTime.toLocaleString()} at the Adem Baba Hostel Office.`,
                    `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🎓 Interview Invitation</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>We’re pleased to inform you that your registration has been accepted.</p>
        <p><strong>You are scheduled for an interview with the following details:</strong></p>
        <ul style="line-height: 1.6;">
            <li><strong>Date:</strong> ${interviewDateTime.toLocaleDateString()}</li>
            <li><strong>Time:</strong> ${interviewTime}</li>
            <li><strong>Location:</strong> Adem Baba Hostel Office</li>
        </ul>
        <p>Please ensure you arrive a few minutes early and bring any necessary documents.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you have any questions or are unable to attend, please notify the office in advance.</p>
    </div>
    `
                );

            }

            res.json({ message: 'Interview scheduled and details sent to student.' });
        } catch (error) {
            console.error('❌ Accept Request Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

// Upload Payment Slip (Student)
app.post(
    '/api/payment-slips/upload',
    verifyToken,
    isStudent,
    upload.single('paymentSlip'),
    handleMulterError,
    [body('amount').isFloat({ min: 0 }).withMessage('Amount must be a positive number')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            if (!req.file) {
                return res.status(400).json({ error: { message: 'No file uploaded', code: 'NO_FILE' } });
            }

            console.log('Cloudinary upload response:', req.file);

            const { amount } = req.body;
            const student = await User.findById(req.user.id);
            if (!student) {
                await cloudinary.uploader.destroy(req.file.filename, { resource_type: req.file.mimetype.startsWith('image') ? 'image' : 'raw' });
                return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
            }

            const paymentSlip = new PaymentSlip({
                student: req.user.id,
                fileUrl: req.file.path,
                publicId: req.file.filename,
                fileType: req.file.mimetype.startsWith('image') ? 'image' : 'raw',
                amount: parseFloat(amount),
                status: 'Pending',
            });
            console.log('Saving payment slip:', paymentSlip);
            await paymentSlip.save();

            const admins = await User.find({ userType: 'admin' });
            for (const admin of admins) {
                sendEmail(
                    admin.email,
                    'Adem Baba – New Payment Slip Uploaded',
                    `Hello, student ${student.name} has uploaded a payment slip of ₦${amount.toLocaleString()}. Please log in to the Admin Dashboard to review the submission.`,
                    `
        <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
            <h2 style="color: #232f3e;">💰 New Payment Slip Uploaded</h2>
            <p><strong>Student:</strong> ${student.name}</p>
            <p><strong>Amount:</strong> ₦${amount.toLocaleString()}</p>
            <p><a href="${paymentSlip.fileUrl}" style="display: inline-block; background-color: #0073bb; color: white; padding: 10px 16px; border-radius: 6px; text-decoration: none;">View Payment Slip</a></p>
            <hr style="margin: 20px 0;" />
            <p style="font-size: 12px; color: #666;">Please take appropriate action in the Admin Dashboard.</p>
        </div>
        `
                ).catch((emailError) =>
                    console.error('Email failed for', admin.email, emailError)
                );
            }


            res.status(201).json({ message: 'Payment slip uploaded successfully' });
        } catch (error) {
            console.error('❌ Upload Payment Slip Error:', error);
            if (req.file && req.file.filename) {
                await cloudinary.uploader.destroy(req.file.filename, { resource_type: req.file.mimetype.startsWith('image') ? 'image' : 'raw' });
            }
            res.status(500).json({ error: { message: 'Failed to upload payment slip', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

// Get Payment Slips (Admin)
app.get('/api/payment-slips', verifyToken, isAdmin, async (req, res) => {
    try {
        const paymentSlips = await PaymentSlip.find()
            .populate('student', 'name matricNumber email')
            .lean();
        res.json(paymentSlips);
    } catch (error) {
        console.error('❌ Get Payment Slips Error:', error);
        res.status(500).json({ error: { message: 'Failed to load payment slips', code: 'SERVER_ERROR' } });
    }
});
// Approve Payment Slip (Admin)
app.post(
    '/api/payment-slips/:id/approve',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid payment slip ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const paymentSlip = await PaymentSlip.findById(id).populate('student', 'name email');
            if (!paymentSlip) {
                return res.status(404).json({ error: { message: 'Payment slip not found', code: 'NOT_FOUND' } });
            }

            paymentSlip.status = 'Approved';
            await paymentSlip.save();

            const payment = new Payment({
                student: paymentSlip.student._id,
                amount: paymentSlip.amount,
                status: 'Paid',
            });
            await payment.save();

            await sendEmail(
                paymentSlip.student.email,
                'Adem Baba – Payment Slip Approved',
                `Hello ${paymentSlip.student.name}, your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been approved. You now have full access to your dashboard.`,
                `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">✅ Payment Approved</h2>
        <p>Hi <strong>${paymentSlip.student.name}</strong>,</p>
        <p>We're pleased to inform you that your payment slip for <strong>₦${paymentSlip.amount.toLocaleString()}</strong> has been approved.</p>
        <p>You can now access your student dashboard and continue with your application process.</p>
        <p>
            <a href="${frontendUrl}" style="display: inline-block; background-color: #0073bb; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">Go to Dashboard</a>
        </p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you have any questions, feel free to contact support.</p>
    </div>
    `
            );


            res.json({ message: 'Payment slip approved successfully' });
        } catch (error) {
            console.error('❌ Approve Payment Slip Error:', error);
            res.status(500).json({ error: { message: 'Failed to approve payment slip', code: 'SERVER_ERROR' } });
        }
    }
);


// Reject Payment Slip (Admin)
app.post(
    '/api/payment-slips/:id/reject',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid payment slip ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const paymentSlip = await PaymentSlip.findById(id).populate('student', 'name email');
            if (!paymentSlip) {
                return res.status(404).json({ error: { message: 'Payment slip not found', code: 'NOT_FOUND' } });
            }

            // Delete file from Cloudinary
            await cloudinary.uploader.destroy(paymentSlip.publicId, { resource_type: paymentSlip.fileType });

            paymentSlip.status = 'Rejected';
            await paymentSlip.save();

            await sendEmail(
                paymentSlip.student.email,
                'Adem Baba – Payment Slip Rejected',
                `Hello ${paymentSlip.student.name}, your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been reviewed and unfortunately, it was rejected. Please upload a valid payment slip to proceed.`,
                `
    <div style="font-family: Arial, sans-serif; color: #c0392b; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #c0392b;">⚠️ Payment Slip Rejected</h2>
        <p>Hi <strong>${paymentSlip.student.name}</strong>,</p>
        <p>We’ve reviewed your payment slip for <strong>₦${paymentSlip.amount.toLocaleString()}</strong> and found it to be invalid or unclear.</p>
        <p>Please upload a valid and clearly visible payment slip in your dashboard to continue the process.</p>
        <p>
            <a href="${frontendUrl}" style="display: inline-block; background-color: #c0392b; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">Upload New Slip</a>
        </p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you believe this was an error, please contact support for clarification.</p>
    </div>
    `
            );


            res.json({ message: 'Payment slip rejected successfully' });
        } catch (error) {
            console.error('❌ Reject Payment Slip Error:', error);
            res.status(500).json({ error: { message: 'Failed to reject payment slip', code: 'SERVER_ERROR' } });
        }
    }
);


// Download Payment Slip File (Admin)
app.get(
    '/api/payment-slips/:id/download',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid payment slip ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const paymentSlip = await PaymentSlip.findById(id).populate('student', 'matricNumber');
            if (!paymentSlip) {
                return res.status(404).json({ error: { message: 'Payment slip not found', code: 'NOT_FOUND' } });
            }

            const fileExt = paymentSlip.fileType === 'image' ? 'jpg' : 'pdf';
            const fileName = `payment-slip-${paymentSlip.student.matricNumber}-${id}.${fileExt}`;
            res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
            res.redirect(paymentSlip.fileUrl);
        } catch (error) {
            console.error('❌ Download Payment Slip Error:', error);
            res.status(500).json({ error: { message: 'Failed to download payment slip', code: 'SERVER_ERROR' } });
        }
    }
);

// Updated: Get Payment Slips (Student)
app.get('/api/student/payment-slips', verifyToken, isStudent, async (req, res) => {
    try {
        const paymentSlips = await PaymentSlip.find({ student: req.user.id })
            .select('amount status createdAt fileUrl')
            .lean();
        res.json(paymentSlips);
    } catch (error) {
        console.error('❌ Get Student Payment Slips Error:', error);
        res.status(500).json({ error: { message: 'Failed to load payment slips', code: 'SERVER_ERROR' } });
    }
});

// Accept Request Direct (Immediate Approval with OTP)
app.post(
    '/api/accept-request-direct',
    verifyToken,
    isAdmin,
    [body('studentId').isMongoId().withMessage('Invalid student ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { studentId } = req.body;
            const student = await User.findById(studentId);
            if (!student || student.userType !== 'student' || student.status !== 'Pending') {
                return res.status(404).json({ error: { message: 'Student not found or not pending', code: 'NOT_FOUND' } });
            }

            const otp = generateOTP();
            const otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
            student.otp = otp;
            student.otpExpires = otpExpires;
            student.status = 'Approved';
            await student.save();

            const frontendUrl = 'http://127.0.0.1:5500/login-form/verify-otp.html';
            const welcomeFileUrl = 'https://www.dropbox.com/scl/fi/0i4r8x3sr7irlcmez9scd/NEAR-HOSTEL-AGREEMENT.pdf?rlkey=svmwneyiff3pnxq85hh9o6eiu&st=oek0pb71&dl=1'; // dl=1 for direct download
            try {
                const attachment = await fetchFileForAttachment(welcomeFileUrl);
                await sendEmail(
                    student.email,
                    'Adem Baba – Your OTP & Welcome Guide',
                    `Hello ${student.name}, your registration has been approved. Use the OTP ${otp} to activate your account. It expires in 1 day. Please verify at ${frontendUrl}. We've also attached a welcome guide to help you get started.`,
                    `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🎉 Welcome to Adem Baba</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>Your registration request has been approved.</p>
        <p><strong>Use the OTP below to activate your account:</strong></p>
        <p style="font-size: 24px; font-weight: bold; background-color: #f5f5f5; padding: 10px; border-radius: 6px; text-align: center;">${otp}</p>
        <p>This OTP will expire in <strong>1 day</strong>.</p>
        <p>
            <a href="${frontendUrl}" style="display: inline-block; background-color: #0073bb; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">Verify OTP</a>
        </p>
        <p>📎 We've also attached a welcome guide to help you get started.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you did not request this, please disregard this message.</p>
    </div>
    `,
                    [attachment]
                );

            } catch (fetchError) {
                console.error('❌ Failed to fetch welcome document:', fetchError);
                // Fallback: Send email without attachment
                await sendEmail(
                    student.email,
                    'Adem Baba – Your One-Time Password (OTP)',
                    `Hello ${student.name}, your registration has been approved. Use the OTP ${otp} to activate your account. It expires in 1 day. You can verify your account at ${frontendUrl}.`,
                    `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🔐 Your One-Time Password</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>Your registration request has been approved.</p>
        <p>Please use the following One-Time Password (OTP) to activate your account:</p>
        <p style="font-size: 24px; font-weight: bold; background-color: #f9f9f9; padding: 10px; border-radius: 6px; text-align: center;">${otp}</p>
        <p>This OTP will expire in <strong>24 hours</strong>.</p>
        <p>
            <a href="${frontendUrl}" style="display: inline-block; background-color: #0073bb; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">Verify Account</a>
        </p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you did not initiate this registration, please ignore this message.</p>
    </div>
    `
                );

            }

            res.json({ message: 'Student approved and OTP sent.' });
        } catch (error) {
            console.error('❌ Accept Request Direct Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

// Decline Request
app.post(
    '/api/decline-request',
    verifyToken,
    isAdmin,
    [body('studentId').isMongoId().withMessage('Invalid student ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { studentId } = req.body;
            const student = await User.findById(studentId);
            if (!student || student.userType !== 'student' || student.status !== 'Pending') {
                return res.status(404).json({ error: { message: 'Student not found or not pending', code: 'NOT_FOUND' } });
            }

            student.status = 'Declined';
            await student.save();

            await sendEmail(
                student.email,
                'Adem Baba – Registration Declined',
                `Hello ${student.name}, we regret to inform you that your registration request has been declined. We appreciate your interest in Adem Baba Hostel and wish you all the best.`,
                `
    <div style="font-family: Arial, sans-serif; color: #c0392b; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #c0392b;">🚫 Registration Declined</h2>
        <p>Hi <strong>${student.name}</strong>,</p>
        <p>Thank you for your interest in Adem Baba Hostel.</p>
        <p>After careful review, we regret to inform you that your registration request has not been approved.</p>
        <p>We wish you success in your future endeavors and appreciate the time you took to apply.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">If you believe this was an error or have any questions, feel free to contact our team.</p>
    </div>
    `
            );


            res.json({ message: 'Request declined and notification sent to student.' });
        } catch (error) {
            console.error('❌ Decline Request Error:', error);
            res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
        }
    }
);

// Forgot Password Route
app.post(
    '/api/forgot-password',
    [body('email').isEmail().withMessage('Invalid email format')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { email } = req.body;
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: { message: 'Email not found', code: 'NOT_FOUND' } });
            }

            // Only generate new token if none exists or existing one is expired
            if (!user.resetPasswordToken || user.resetPasswordExpires < Date.now()) {
                const resetToken = crypto.randomBytes(32).toString('hex');
                await User.updateOne(
                    { _id: user._id },
                    {
                        $set: {
                            resetPasswordToken: resetToken,
                            resetPasswordExpires: Date.now() + 3600000 // 1 hour
                        }
                    }
                );

                const resetUrl = `http://127.0.0.1:5500/login-form/reset-password.html?token=${resetToken}`;
                await sendEmail(
                    email,
                    'Adem Baba – Password Reset Instructions',
                    `Hello, you requested to reset the password for your Adem Baba account. Use the link below to choose a new password:\n${resetUrl}\n\n\
This link will expire in 1 hour for your security. \
If you did not request this reset, please ignore this message.`,
                    `
<div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
<h2 style="color: #232f3e;">🔑 Password Reset Request</h2>
<p>You recently requested to reset your password for your Adem Baba account.</p>
<p>Click the button below to set a new password:</p>
<p style="text-align:center;">
<a href="${resetUrl}"
style="display:inline-block; background-color:#0073bb; color:#fff;
padding:12px 24px; border-radius:6px; text-decoration:none;
font-weight:bold;">
Reset Password
</a>
</p>
<p>This link will expire in <strong>1&nbsp;hour</strong>.</p>
<hr style="margin:20px 0;" />
<p style="font-size:12px; color:#666;">
If you did not request this reset, please ignore this email or contact support.
</p>
</div>`
                );
                console.log('Reset email sent:', { email, resetUrl });
            }

            res.json({ message: 'Password reset email sent. Check your email.' });

        } catch (error) {
            console.error('❌ Forgot Password Error:', error);
            res.status(500).json({ error: { message: 'Failed to send reset link', code: 'SERVER_ERROR' } });
        }
    }
);



// Reset Password Route
app.post(
    '/api/reset-password',
    [
        body('token').notEmpty().withMessage('Reset token is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { token, password } = req.body;
            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() },
            }).select('+password');

            if (!user) {
                return res.status(400).json({ error: { message: 'Invalid or expired reset token', code: 'INVALID_TOKEN' } });
            }

            // Hash the new password
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

            // Update user document using updateOne to ensure atomic update
            await User.updateOne(
                { _id: user._id },
                {
                    $set: {
                        password: hashedPassword,
                        resetPasswordToken: null,
                        resetPasswordExpires: null
                    }
                }
            );

            // Send confirmation email
            await sendEmail(
                user.email,
                'Adem Baba – Password Reset Successful',
                `Hello ${user.name}, your password has been successfully reset. You can now log in using your new password. If you did not perform this action, please contact support immediately.`,
                `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
                    <h2 style="color: #232f3e;">✅ Password Reset Successful</h2>
                    <p>Hi <strong>${user.name}</strong>,</p>
                    <p>Your password has been successfully reset.</p>
                    <p>You can now log in to your Adem Baba account using your new credentials.</p>
                    <hr style="margin: 20px 0;" />
                    <p style="font-size: 12px; color: #666;">If you did not perform this action, please contact support immediately to secure your account.</p>
                </div>
                `
            );

            res.json({ message: 'Password reset successful' });
        } catch (error) {
            console.error('❌ Reset Password Error:', error);
            res.status(500).json({ error: { message: 'Failed to reset password', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

// Add Student (Admin)
app.post(
    '/api/students',
    verifyToken,
    isAdmin,
    [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('email').isEmail().withMessage('Invalid email format'),
        body('matricNumber').notEmpty().matches(/^[A-Z0-9]+$/).withMessage('Invalid matric number format'),
        body('phone').notEmpty().matches(/^\+?[\d\s()-]{10,}$/).withMessage('Invalid phone number format'),
        body('gender').isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender'),
        body('userType').equals('student').withMessage('User type must be student'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { name, email, matricNumber, phone, gender, userType, password } = req.body;
            const existingUser = await User.findOne({ $or: [{ email }, { matricNumber }] });
            if (existingUser) {
                return res.status(400).json({ error: { message: 'Email or matric number already exists', code: 'DUPLICATE' } });
            }

            const hashedPassword = await hashing(password);
            const user = new User({
                name,
                email,
                matricNumber,
                phone,
                gender,
                userType,
                password: hashedPassword,
                status: 'Approved',
                isVerified: true,
            });
            await user.save();
            res.status(201).json({ message: 'Student added successfully' });
        } catch (error) {
            console.error('❌ Add Student Error:', error);
            res.status(500).json({ error: { message: 'Failed to add student', code: 'SERVER_ERROR' } });
        }
    }
);

// Update Student (Admin)
app.patch('/api/students/:id', verifyToken, isAdmin, [
    param('id').isMongoId().withMessage('Invalid student ID'),
    body('name').optional().notEmpty().withMessage('Name cannot be empty'),
    body('email').optional().isEmail().withMessage('Invalid email format'),
    body('matricNumber').optional().matches(/^\d{2}\/[A-Z0-9]{6}\/\d{3}$/).withMessage('Invalid matric number format'),
    body('phone').optional().matches(/^\+?[\d\s()-]{10,}$/).withMessage('Invalid phone number'),
    body('gender').optional().isIn(['Male']).withMessage('Only male students allowed'),
    body('dateOfBirth').optional().isISO8601().withMessage('Invalid date of birth'),
    body('faculty').optional().notEmpty().withMessage('Faculty cannot be empty'),
    body('level').optional().matches(/^(100|200|300|400|500)$/).withMessage('Invalid level'),
    body('department').optional().notEmpty().withMessage('Department cannot be empty')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
        }

        const updates = req.body;
        updates.level = updates.level ? `${updates.level}level` : undefined; // Transform level
        const student = await User.findOneAndUpdate(
            { _id: req.params.id, userType: 'student' },
            { $set: updates },
            { new: true }
        ).populate('room', 'roomNumber type');

        if (!student) {
            return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
        }

        console.log(`Student ${student._id} updated by admin ${req.user.email}`);
        res.json({ message: 'Student updated successfully', student });
    } catch (error) {
        console.error('❌ Update Student Error:', error);
        res.status(500).json({ error: { message: 'Failed to update student', code: 'SERVER_ERROR', details: error.message } });
    }
});


// Get Single Student (Admin)
app.get(
    '/api/students/:id',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid student ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    error: {
                        message: 'Validation failed',
                        details: errors.array(),
                        code: 'VALIDATION_ERROR'
                    }
                });
            }

            const student = await User.findById(req.params.id)
                .populate('room', 'roomNumber type')
                .lean();

            if (!student || student.userType !== 'student') {
                return res.status(404).json({
                    error: {
                        message: 'Student not found',
                        code: 'NOT_FOUND'
                    }
                });
            }

            // Format the date fields for better readability
            const formattedStudent = {
                ...student,
                dateOfBirth: student.dateOfBirth ? new Date(student.dateOfBirth).toISOString().split('T')[0] : null,
                createdAt: new Date(student.createdAt).toLocaleString()
            };

            res.json({ student: formattedStudent });
        } catch (error) {
            console.error('❌ Get Student Error:', error);
            res.status(500).json({
                error: {
                    message: 'Failed to load student',
                    code: 'SERVER_ERROR'
                }
            });
        }
    }
);

// Delete Student (Admin)
app.delete(
    '/api/students/:id',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid student ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const student = await User.findById(id);
            if (!student || student.userType !== 'student') {
                return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
            }

            if (student.room) {
                await Room.updateOne({ _id: student.room }, { $pull: { occupants: id } });
                const room = await Room.findById(student.room);
                if (room) {
                    room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
                    await room.save();
                }
            }

            await User.deleteOne({ _id: id });
            res.json({ message: 'Student deleted successfully' });
        } catch (error) {
            console.error('❌ Delete Student Error:', error);
            res.status(500).json({ error: { message: 'Failed to delete student', code: 'SERVER_ERROR' } });
        }
    }
);

// Assign Room
app.post('/api/students/assign-room', verifyToken, isAdmin, [
    body('studentId').isMongoId().withMessage('Invalid student ID'),
    body('roomId').isMongoId().withMessage('Invalid room ID')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
        }

        const { studentId, roomId } = req.body;
        const student = await User.findOne({ _id: studentId, userType: 'student', status: 'Approved' });
        if (!student) {
            return res.status(404).json({ error: { message: 'Approved student not found', code: 'NOT_FOUND' } });
        }

        const room = await Room.findById(roomId);
        if (!room || room.status === 'Maintenance' || room.occupants.length >= room.capacity) {
            return res.status(400).json({ error: { message: 'Invalid or unavailable room', code: 'INVALID_ROOM' } });
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            await User.updateOne(
                { _id: studentId },
                { $set: { room: roomId } },
                { session }
            );
            await Room.updateOne(
                { _id: roomId },
                { $addToSet: { occupants: studentId } },
                { session }
            );
            await Room.updateMany(
                { _id: { $ne: roomId }, occupants: studentId },
                { $pull: { occupants: studentId } },
                { session }
            );
            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }

        console.log(`Room ${roomId} assigned to student ${studentId} by admin ${req.user.email}`);
        res.json({ message: 'Room assigned successfully' });
    } catch (error) {
        console.error('❌ Assign Room Error:', error);
        res.status(500).json({ error: { message: 'Failed to assign room', code: 'SERVER_ERROR', details: error.message } });
    }
});

// Activities Endpoint
app.get('/api/activities', verifyToken, isAdmin, async (req, res) => {
    try {
        const recentRegistrations = await User.find({ userType: 'student', status: 'Pending' })
            .sort({ createdAt: -1 })
            .limit(3)
            .lean()
            .then((users) =>
                users.map((u) => ({
                    icon: 'bell',
                    type: 'warning',
                    text: `New student registration request: ${u.name}`,
                    time: new Date(u.createdAt).toLocaleString(),
                }))
            );

        const recentMaintenance = await Maintenance.find({ status: 'Open' })
            .populate('room', 'roomNumber')
            .sort({ createdAt: -1 })
            .limit(3)
            .lean()
            .then((requests) =>
                requests.map((r) => ({
                    icon: r.icon,
                    type: r.type,
                    text: `Room ${r.room.roomNumber}: ${r.issue}`,
                    time: new Date(r.createdAt).toLocaleString(),
                }))
            );

        const overduePayments = await Payment.find({ status: 'Overdue' })
            .populate('student', 'name')
            .sort({ createdAt: -1 })
            .limit(3)
            .lean()
            .then((payments) =>
                payments.map((p) => ({
                    icon: 'exclamation-circle',
                    type: 'danger',
                    text: `Payment overdue: ${p.student.name}`,
                    time: new Date(p.createdAt).toLocaleString(),
                }))
            );

        const activities = [...recentRegistrations, ...recentMaintenance, ...overduePayments]
            .sort((a, b) => new Date(b.time) - new Date(a.time))
            .slice(0, 5);

        res.json(activities);
    } catch (error) {
        console.error('❌ Activities Error:', error);
        res.status(500).json({ error: { message: 'Failed to load activities', code: 'SERVER_ERROR' } });
    }
});

// Room Stats
app.get('/api/rooms/stats', verifyToken, isAdmin, async (req, res) => {
    try {
        const totalRooms = await Room.countDocuments();
        const occupiedRooms = await Room.countDocuments({ status: 'Occupied' });
        const availableRooms = await Room.countDocuments({ status: 'Available' });
        const maintenanceRooms = await Room.countDocuments({ status: 'Maintenance' });
        res.json({ totalRooms, occupiedRooms, availableRooms, maintenanceRooms });
    } catch (error) {
        console.error('❌ Room Stats Error:', error);
        res.status(500).json({ error: { message: 'Failed to load room stats', code: 'SERVER_ERROR' } });
    }
});

// Get Rooms
app.get('/api/rooms', verifyToken, isAdmin, async (req, res) => {
    try {
        const rooms = await Room.find().populate('occupants', 'name').lean();
        res.json(rooms);
    } catch (error) {
        console.error('❌ Rooms Error:', error);
        res.status(500).json({ error: { message: 'Failed to load rooms', code: 'SERVER_ERROR' } });
    }
});

// Add Room
app.post(
    '/api/rooms',
    verifyToken,
    isAdmin,
    [
        body('roomNumber').trim().notEmpty().withMessage('Room number is required'),
        body('type').isIn(['Standard', 'Premium']).withMessage('Type must be Standard or Premium'),
        body('capacity').isInt({ min: 1 }).withMessage('Capacity must be at least 1'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { roomNumber, type, capacity } = req.body;
            const existingRoom = await Room.findOne({ roomNumber });
            if (existingRoom) {
                return res.status(400).json({ error: { message: 'Room number already exists', code: 'DUPLICATE' } });
            }

            const room = new Room({ roomNumber, type, capacity });
            await room.save();
            res.status(201).json({ message: 'Room added successfully' });
        } catch (error) {
            console.error('❌ Add Room Error:', error);
            res.status(500).json({ error: { message: 'Failed to add room', code: 'SERVER_ERROR' } });
        }
    }
);

// Update Room
app.put(
    '/api/rooms/:id',
    verifyToken,
    isAdmin,
    [
        param('id').isMongoId().withMessage('Invalid room ID'),
        body('roomNumber').trim().notEmpty().withMessage('Room number is required'),
        body('type').isIn(['Standard', 'Premium']).withMessage('Type must be Standard or Premium'),
        body('capacity').isInt({ min: 1 }).withMessage('Capacity must be at least 1'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const { roomNumber, type, capacity } = req.body;

            const room = await Room.findById(id);
            if (!room) {
                return res.status(404).json({ error: { message: 'Room not found', code: 'NOT_FOUND' } });
            }

            const existingRoom = await Room.findOne({ roomNumber, _id: { $ne: id } });
            if (existingRoom) {
                return res.status(400).json({ error: { message: 'Room number already exists', code: 'DUPLICATE' } });
            }

            room.roomNumber = roomNumber;
            room.type = type;
            room.capacity = capacity;
            await room.save();

            res.json({ message: 'Room updated successfully' });
        } catch (error) {
            console.error('❌ Update Room Error:', error);
            res.status(500).json({ error: { message: 'Failed to update room', code: 'SERVER_ERROR' } });
        }
    }
);

// Delete Room
app.delete(
    '/api/rooms/:id',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid room ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const room = await Room.findById(id);
            if (!room) {
                return res.status(404).json({ error: { message: 'Room not found', code: 'NOT_FOUND' } });
            }

            if (room.occupants.length > 0) {
                return res.status(400).json({ error: { message: 'Cannot delete room with occupants', code: 'ROOM_OCCUPIED' } });
            }

            const maintenanceRequests = await Maintenance.find({ room: id, status: 'Open' });
            if (maintenanceRequests.length > 0) {
                return res.status(400).json({ error: { message: 'Cannot delete room with open maintenance requests', code: 'MAINTENANCE_ACTIVE' } });
            }

            await User.updateMany({ room: id }, { $unset: { room: '' } });
            await Room.deleteOne({ _id: id });

            res.json({ message: 'Room deleted successfully' });
        } catch (error) {
            console.error('❌ Delete Room Error:', error);
            res.status(500).json({ error: { message: 'Failed to delete room', code: 'SERVER_ERROR' } });
        }
    }
);

// Add Maintenance Request
app.post(
    '/api/maintenance',
    verifyToken,
    isAdmin,
    [
        body('roomId').isMongoId().withMessage('Invalid room ID'),
        body('issue').trim().notEmpty().withMessage('Issue is required'),
        body('type').isIn(['warning', 'danger']).withMessage('Type must be warning or danger'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { roomId, issue, type } = req.body;
            const room = await Room.findById(roomId);
            if (!room) {
                return res.status(404).json({ error: { message: 'Room not found', code: 'NOT_FOUND' } });
            }

            const maintenance = new Maintenance({ room: roomId, issue, type });
            await maintenance.save();
            room.status = 'Maintenance';
            await room.save();

            const admins = await User.find({ userType: 'admin' });
            for (const admin of admins) {
                const settings = await Settings.findOne({ user: admin._id });
                if (settings?.notifications.maintenance) {
                    await sendEmail(
                        admin.email,
                        'Adem Baba – New Maintenance Request Submitted',
                        `A new maintenance request has been submitted for Room ${room.roomNumber}. Issue: ${issue} (Type: ${type}). Please review and take appropriate action.`,
                        `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🛠️ New Maintenance Request</h2>
        <p>A maintenance request has been submitted for the following room:</p>
        <ul style="line-height: 1.6;">
            <li><strong>Room Number:</strong> ${room.roomNumber}</li>
            <li><strong>Issue:</strong> ${issue}</li>
            <li><strong>Type:</strong> ${type}</li>
        </ul>
        <p>Please review the request in the admin dashboard and take appropriate action.</p>
        <hr style="margin: 20px 0;" />
        <p style="font-size: 12px; color: #666;">This is an automated notification from the Adem Baba maintenance system.</p>
    </div>
    `
                    );

                }
            }

            res.status(201).json({ message: 'Maintenance request added successfully' });
        } catch (error) {
            console.error('❌ Add Maintenance Error:', error);
            res.status(500).json({ error: { message: 'Failed to add maintenance request', code: 'SERVER_ERROR' } });
        }
    }
);

// Delete Maintenance Request
app.delete(
    '/api/maintenance/:id',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid maintenance ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const maintenance = await Maintenance.findById(req.params.id);
            if (!maintenance) {
                return res.status(404).json({ error: { message: 'Maintenance request not found', code: 'NOT_FOUND' } });
            }

            const room = await Room.findById(maintenance.room);
            await Maintenance.deleteOne({ _id: req.params.id });

            if (room) {
                const remainingMaintenance = await Maintenance.countDocuments({ room: room._id, status: 'Open' });
                if (remainingMaintenance === 0) {
                    room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
                    await room.save();
                }
            }

            res.json({ message: 'Maintenance request deleted successfully' });
        } catch (error) {
            console.error('❌ Delete Maintenance Error:', error);
            res.status(500).json({ error: { message: 'Failed to delete maintenance request', code: 'SERVER_ERROR' } });
        }
    }
);

// Get Maintenance Requests
app.get('/api/maintenance', verifyToken, isAdmin, async (req, res) => {
    try {
        const requests = await Maintenance.find({ status: 'Open' })
            .populate('room', 'roomNumber')
            .sort({ createdAt: -1 })
            .lean();
        const formattedRequests = requests.map((r) => ({
            id: r._id,
            text: `Room ${r.room.roomNumber}: ${r.issue}`,
            type: r.type,
            icon: r.icon,
            time: new Date(r.createdAt).toLocaleString(),
        }));
        res.json(formattedRequests);
    } catch (error) {
        console.error('❌ Maintenance Error:', error);
        res.status(500).json({ error: { message: 'Failed to load maintenance requests', code: 'SERVER_ERROR' } });
    }
});

// Event Stats
app.get('/api/events/stats', verifyToken, isAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const weekStart = new Date(today);
        weekStart.setDate(today.getDate() - today.getDay());

        const todaysEvents = await Event.countDocuments({
            date: { $gte: today, $lt: new Date(today.getTime() + 86400000) }
        });
        const weeklyEvents = await Event.countDocuments({
            date: { $gte: weekStart, $lt: new Date(weekStart.getTime() + 7 * 86400000) }
        });
        const cancelledEvents = await Event.countDocuments({ status: 'Cancelled' });

        res.json({ todaysEvents, weeklyEvents, cancelledEvents });
    } catch (error) {
        res.status(500).json({ error: { message: 'Failed to fetch stats' } });
    }
});


// Get Events
app.get(
    '/api/events',
    verifyToken,
    [
        query('keyword').optional().trim(),
        query('start').optional().isISO8601(),
        query('end').optional().isISO8601(),
        query('status').optional().isIn(['Scheduled', 'Pending', 'Cancelled'])
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array() } });
            }
            const { keyword, start, end, status } = req.query;
            let filter = {};

            if (keyword) {
                filter.title = { $regex: keyword, $options: 'i' };
            }
            if (start && end) {
                filter.date = { $gte: new Date(start), $lte: new Date(end) };
            } else if (start) {
                filter.date = { $gte: new Date(start) };
            } else if (end) {
                filter.date = { $lte: new Date(end) };
            }
            if (status) {
                filter.status = status;
            } else if (req.user.userType === 'student') {
                filter.status = 'Scheduled';
            }

            const events = await Event.find(filter).sort({ date: 1, time: 1 });
            res.json(events);
        } catch (error) {
            res.status(500).json({ error: { message: 'Failed to fetch events' } });
        }
    }
);
app.post(
    '/api/events/create',
    verifyToken,
    isAdmin,
    [
        body('title').trim().notEmpty().withMessage('Title is required'),
        body('date').isISO8601().toDate().withMessage('Invalid date'),
        body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
        body('description').optional().trim()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }
            const { title, date, time, description } = req.body;
            const event = new Event({ title, date, time, description, status: 'Pending' });
            await event.save();
            res.json({ message: 'Event added successfully', event });
        } catch (error) {
            res.status(500).json({ error: { message: 'Failed to add event' } });
        }
    }
);

// Add Event
app.post('/api/events', verifyToken, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
        }

        const { start, end, status, keyword } = req.body;
        let query = {};

        // Apply date filters
        if (start && end) {
            query.date = { $gte: new Date(start), $lte: new Date(end) };
        } else if (start) {
            query.date = { $gte: new Date(start) };
        }

        // Apply status filter
        if (status) {
            query.status = status;
        } else if (req.user.userType === 'student') {
            // Students only see Scheduled events
            query.status = 'Scheduled';
        }

        // Apply keyword filter
        if (keyword) {
            query.title = { $regex: keyword, $options: 'i' };
        }

        const events = await Event.find(query)
            .sort({ date: 1 })
            .lean();

        res.json(
            events.map((event) => ({
                ...event,
                time: event.time || '00:00',
            }))
        );
    } catch (error) {
        console.error('❌ Events Error:', error);
        res.status(500).json({ error: { message: 'Failed to load events', code: 'SERVER_ERROR' } });
    }
});

// Delete Event
app.delete(
    '/api/events/:id',
    verifyToken,
    isAdmin,
    [param('id').isMongoId().withMessage('Invalid event ID')],
    async (req, res) => {
        try {
            const { id } = req.params;
            const event = await Event.findByIdAndDelete(id);
            if (!event) {
                return res.status(404).json({ error: { message: 'Event not found' } });
            }
            res.json({ message: 'Event deleted successfully' });
        } catch (error) {
            res.status(500).json({ error: { message: 'Failed to delete event' } });
        }
    }
);
// Update Event
app.put(
    '/api/events/:id',
    verifyToken,
    isAdmin,
    [
        param('id').isMongoId().withMessage('Invalid event ID'),
        body('title').trim().notEmpty().withMessage('Title is required'),
        body('date').isISO8601().toDate().withMessage('Invalid date'),
        body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
        body('description').optional().trim(),
        body('status').isIn(['Scheduled', 'Pending', 'Cancelled']).withMessage('Invalid status')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }
            const { id } = req.params;
            const { title, date, time, description, status } = req.body;
            const event = await Event.findByIdAndUpdate(
                id,
                { title, date, time, description, status },
                { new: true }
            );
            if (!event) {
                return res.status(404).json({ error: { message: 'Event not found' } });
            }
            res.json({ message: 'Event updated successfully', event });
        } catch (error) {
            res.status(500).json({ error: { message: 'Failed to update event' } });
        }
    }
);



// Get Student Profile (Student)
app.get('/api/profile', verifyToken, isStudent, async (req, res) => {
    try {
        const student = await User.findById(req.user.id)
            .select('name email matricNumber phone gender dateOfBirth faculty level department room')
            .populate('room', 'roomNumber type')
            .lean();
        if (!student) {
            return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
        }
        res.json(student);
    } catch (error) {
        console.error('❌ Get Profile Error:', error);
        res.status(500).json({ error: { message: 'Failed to load profile', code: 'SERVER_ERROR' } });
    }
});

// Get Payments (Student)
app.get('/api/payments', verifyToken, isStudent, async (req, res) => {
    try {
        const payments = await Payment.find({ student: req.user.id })
            .select('amount status createdAt transactionRef')
            .lean();
        res.json(payments);
    } catch (error) {
        console.error('❌ Get Payments Error:', error);
        res.status(500).json({ error: { message: 'Failed to load payments', code: 'SERVER_ERROR' } });
    }
});

// Get Payment Slips (Student)
app.get('/api/student/payment-slips', verifyToken, isStudent, async (req, res) => {
    try {
        const paymentSlips = await PaymentSlip.find({ student: req.user.id })
            .select('amount status createdAt filePath')
            .lean();
        res.json(paymentSlips);
    } catch (error) {
        console.error('❌ Get Student Payment Slips Error:', error);
        res.status(500).json({ error: { message: 'Failed to load payment slips', code: 'SERVER_ERROR' } });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: { message: 'Email is required' } });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: { message: 'Email not found' } });
        }

        // Generate a unique reset token
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiry
        await user.save();

        // Send email
        const resetUrl = `http://127.0.0.1:5501/login-form/reset-password.html?token=${token}`;
        console.log(resetUrl)
        await sendEmail(
            email,
            'Adem Baba – Password Reset Request',
            `Hello, you requested to reset your password for your Adem Baba account. Use the link below to choose a new password:\n${resetUrl}\n\nThis link will expire in 1 hour. If you did not request this, please ignore this message.`,
            `
    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
        <h2 style="color: #232f3e;">🔐 Password Reset Request</h2>

        <p>You have requested to reset your password for your <strong>Adem Baba</strong> account.</p>

        <p>Click the button below to reset your password:</p>

        <p style="text-align: center;">
            <a href="${resetUrl}" 
               style="display: inline-block; background-color: #0073bb; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
               Reset Password
            </a>
        </p>

        <p>This link will expire in <strong>1 hour</strong>.</p>

        <hr style="margin: 20px 0;" />

        <p style="font-size: 12px; color: #666;">If you did not request this reset, you can safely ignore this email.</p>
    </div>
    `
        );


        res.json({ message: 'Password reset email sent. Check your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: { message: 'Server error' } });
    }
});

// Reset Password Route
app.post(
    '/api/reset-password/:token',
    [
        param('token').notEmpty().withMessage('Reset token is required'),
        body('password').matches(/^(?=.*\d)(?=.*[a-zA-Z]).{8,}$/).withMessage('Password must be at least 8 characters with letters and numbers'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log('Validation errors:', errors.array());
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { token } = req.params;
            const { password } = req.body;

            console.log('Received reset password request:', { token, password: '[REDACTED]' });

            // Find user by reset token and check if it's not expired
            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() },
            }).select('+password');

            if (!user) {
                console.log('Invalid or expired reset token:', token);
                return res.status(400).json({ error: { message: 'Invalid or expired reset token', code: 'INVALID_TOKEN' } });
            }

            console.log('User found:', user.email);

            // Hash the new password
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            console.log('Password hashed successfully');

            // Update user document with new password and clear reset fields
            await User.updateOne(
                { _id: user._id },
                {
                    $set: {
                        password: hashedPassword,
                        resetPasswordToken: null,
                        resetPasswordExpires: null
                    }
                }
            );

            console.log('User password updated successfully for:', user.email);

            // Send confirmation email
            await sendEmail(
                user.email,
                'Adem Baba – Password Reset Successful',
                `Hello ${user.name}, your password has been successfully reset. You can now log in using your new password. If you did not perform this action, please contact support immediately.`,
                `
                <div style="font-family: Arial, sans-serif; color:#333; max-width:600px; margin:auto; padding:20px; border:1px solid #e2e2e2; border-radius:8px;">
                    <h2 style="color:#232f3e;">✅ Password Reset Successful</h2>
                    <p>Hi <strong>${user.name}</strong>,</p>
                    <p>Your password has been successfully reset.</p>
                    <p>You can now log in to your Adem Baba account using your new credentials.</p>
                    <hr style="margin:20px 0;" />
                    <p style="font-size:12px; color:#666;">
                        If you did not perform this action, please contact support immediately to secure your account.
                    </p>
                </div>
                `
            );

            console.log('Password reset confirmation email sent to:', user.email);
            res.json({ message: 'Password reset successful' });
        } catch (error) {
            console.error('❌ Reset Password Error:', error);
            res.status(500).json({ error: { message: 'Failed to reset password', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('❌ Unhandled Error:', err);
    res.status(500).json({
        error: {
            message: 'Internal Server Error',
            code: 'INTERNAL_SERVER_ERROR',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined,
        },
    });
});

// Registration Deadline Routes
app.post(
    '/api/registration-deadline',
    verifyToken,
    isAdmin,
    [
        body('deadline')
            .isISO8601()
            .withMessage('Invalid deadline format')
            .custom((value) => {
                const deadline = new Date(value);
                const now = new Date();
                if (deadline <= now) {
                    throw new Error('Deadline must be in the future');
                }
                return true;
            })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log('Validation errors for set deadline:', errors.array());
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { deadline } = req.body;
            const deadlineDate = new Date(deadline);
            console.log('Attempting to set deadline:', { deadline, admin: req.user.email });

            // Delete existing deadlines
            const deleteResult = await RegistrationDeadline.deleteMany({});
            console.log('Deleted existing deadlines:', deleteResult);

            // Create new deadline
            const newDeadline = new RegistrationDeadline({
                deadline: deadlineDate,
                extended: false,
                extendedDeadline: null,
                createdAt: new Date(),
                updatedAt: new Date()
            });

            const savedDeadline = await newDeadline.save();
            console.log('New deadline saved:', savedDeadline);

            res.json({ message: 'Registration deadline set successfully', deadline: savedDeadline });
        } catch (error) {
            console.error('❌ Set Deadline Error:', error);
            res.status(500).json({ error: { message: 'Failed to set deadline', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

app.patch(
    '/api/registration-deadline/extend',
    verifyToken,
    isAdmin,
    [
        body('extendedDeadline')
            .isISO8601()
            .withMessage('Invalid extended deadline format')
            .custom(async (value) => {
                const extendedDeadline = new Date(value);
                const now = new Date();
                const currentDeadline = await RegistrationDeadline.findOne({});
                if (!currentDeadline) {
                    throw new Error('No registration deadline found');
                }
                if (extendedDeadline <= currentDeadline.deadline) {
                    throw new Error('Extended deadline must be after the current deadline');
                }
                if (extendedDeadline <= now) {
                    throw new Error('Extended deadline must be in the future');
                }
                return true;
            })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log('Validation errors for extend deadline:', errors.array());
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { extendedDeadline } = req.body;
            const extendedDeadlineDate = new Date(extendedDeadline);
            console.log('Attempting to extend deadline:', { extendedDeadline, admin: req.user.email });

            const result = await RegistrationDeadline.updateOne(
                {},
                {
                    $set: {
                        extended: true,
                        extendedDeadline: extendedDeadlineDate,
                        updatedAt: new Date()
                    }
                }
            );

            if (result.matchedCount === 0) {
                console.log('No deadline found to extend');
                return res.status(404).json({ error: { message: 'No deadline found to extend', code: 'NOT_FOUND' } });
            }

            const updatedDeadline = await RegistrationDeadline.findOne({});
            console.log('Deadline extended:', updatedDeadline);

            res.json({ message: 'Registration deadline extended successfully', deadline: updatedDeadline });
        } catch (error) {
            console.error('❌ Extend Deadline Error:', error);
            res.status(500).json({ error: { message: 'Failed to extend deadline', code: 'SERVER_ERROR', details: error.message } });
        }
    }
);

app.get(
    '/api/registration-deadline',
    async (req, res) => {
        try {
            const deadline = await RegistrationDeadline.findOne();

            if (!deadline) {
                return res.json({
                    message: 'No registration deadline set',
                    deadline: null,
                    extended: false,
                    extendedDeadline: null
                });
            }

            res.json({
                deadline: deadline.deadline,
                extended: deadline.extended,
                extendedDeadline: deadline.extendedDeadline
            });
        } catch (error) {
            console.error('❌ Get Registration Deadline Error:', error);
            res.status(500).json({ error: { message: 'Failed to get registration deadline', code: 'SERVER_ERROR' } });
        }
    }
);

// Get Notifications (add to your routes)
app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.user.id })
            .sort({ createdAt: -1 })
            .limit(10)
            .lean();

        res.json({ notifications });
    } catch (error) {
        res.status(500).json({ error: { message: 'Failed to get notifications' } });
    }
});

// Mark Notification as Read
app.post('/api/notifications/:id/read', verifyToken, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, { read: true });
        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        res.status(500).json({ error: { message: 'Failed to mark notification as read' } });
    }
});

/* Serrings page */
// Check authentication (admin only)
app.get('/auth/check', verifyToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({
            name: user.name,
            email: user.email,
            avatar: user.avatar,
            notifications: user.notifications,
            security: user.security,
            preferences: user.preferences,
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

/* // Update profile (name, email, avatar) (admin only)
app.put(
    '/profile',
    verifyToken, isAdmin,
    [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('email').isEmail().withMessage('Invalid email format'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email } = req.body;

        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Check if email is already in use by another user
            if (email !== user.email) {
                const emailExists = await User.findOne({ email });
                if (emailExists) {
                    return res.status(400).json({ message: 'Email already in use' });
                }
            }

            user.name = name || user.name;
            user.email = email || user.email;

            // Handle profile picture upload
            if (req.files && req.files.avatar) {
                const file = req.files.avatar;
                const uploadResult = await cloudinary.uploader.upload(file.tempFilePath, {
                    folder: 'profile_pictures',
                });
                user.avatar = uploadResult.secure_url;
            }

            await user.save();

            // Send email notification for profile update
            await sendEmail({
                to: user.email,
                subject: 'Profile Updated',
                text: `Hello ${user.name}, your profile has been successfully updated.`,
            });

            res.json({ message: 'Profile updated successfully', user: { name: user.name, email: user.email, avatar: user.avatar } });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Update notification preferences (admin only)
app.put(
    '/notifications',
    verifyToken, isAdmin,
    [
        body('emailNotifications').isBoolean().withMessage('Invalid email notifications setting'),
        body('newStudentNotifications').isBoolean().withMessage('Invalid new student notifications setting'),
        body('maintenanceNotifications').isBoolean().withMessage('Invalid maintenance notifications setting'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { emailNotifications, newStudentNotifications, maintenanceNotifications } = req.body;

        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            user.notifications = {
                email: emailNotifications,
                newStudent: newStudentNotifications,
                maintenance: maintenanceNotifications,
            };

            await user.save();

            // Send confirmation email if email notifications are enabled
            if (emailNotifications) {
                await sendEmail({
                    to: user.email,
                    subject: 'Notification Preferences Updated',
                    text: `Hello ${user.name}, your notification preferences have been updated.`,
                });
            }

            res.json({ message: 'Notification preferences saved' });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Update security settings (password, 2FA) (admin only)
app.put(
    '/security',
    verifyToken, isAdmin,
    [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
        body('twoFactorAuth').isBoolean().withMessage('Invalid 2FA setting'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { currentPassword, newPassword, twoFactorAuth } = req.body;

        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Verify current password
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Current password is incorrect' });
            }

            // Update password if provided
            if (newPassword) {
                user.password = await bcrypt.hash(newPassword, 10);
            }

            // Update 2FA setting
            user.security = { ...user.security, twoFactorAuth };

            await user.save();

            // Send email notification for security update
            await sendEmail({
                to: user.email,
                subject: 'Security Settings Updated',
                text: `Hello ${user.name}, your security settings have been updated. Two-factor authentication is now ${twoFactorAuth ? 'enabled' : 'disabled'}.`,
            });

            res.json({ message: 'Security settings updated' });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Update system preferences (language, timezone) (admin only)
app.put(
    '/system',
    verifyToken, isAdmin,
    [
        body('language').isIn(['en', 'fr', 'es']).withMessage('Invalid language'),
        body('timezone').isIn(['GMT+0', 'GMT+1', 'GMT+2']).withMessage('Invalid timezone'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { language, timezone } = req.body;

        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            user.preferences = { language, timezone };
            await user.save();

            res.json({ message: 'System preferences saved' });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    }
);

// Nuke Data (Admin Only - Deletes all data from the database)
app.post(
    '/api/system-nuke-data',
    verifyToken,
    isAdmin,
    [
        body('confirmation').equals('NUKE_ALL_DATA').withMessage('Confirmation string must be "NUKE_ALL_DATA"'),
        body('adminPassword').notEmpty().withMessage('Admin password is required')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    error: {
                        message: 'Validation failed',
                        details: errors.array(),
                        code: 'VALIDATION_ERROR'
                    }
                });
            }

            const { adminPassword } = req.body;

            // Verify admin password
            const admin = await User.findById(req.user.id).select('+password');
            const isMatch = await bcrypt.compare(adminPassword, admin.password);
            if (!isMatch) {
                return res.status(401).json({
                    error: {
                        message: 'Invalid admin password',
                        code: 'INVALID_CREDENTIALS'
                    }
                });
            }

            // Start a MongoDB session for atomic operations
            const session = await mongoose.startSession();
            try {
                await session.withTransaction(async () => {
                    // Delete all documents from all collections
                    await User.deleteMany({}, { session });
                    await Room.deleteMany({}, { session });
                    await Event.deleteMany({}, { session });
                    await Maintenance.deleteMany({}, { session });
                    await Settings.deleteMany({}, { session });
                    await Payment.deleteMany({}, { session });
                    await PaymentSlip.deleteMany({}, { session });
                    await RegistrationDeadline.deleteMany({}, { session });
                    await Notification.deleteMany({}, { session });

                    // Delete all files from Cloudinary in the relevant folders
                    try {
                        await cloudinary.api.delete_resources_by_prefix('payment-slips', {
                            resource_type: 'image'
                        });
                        await cloudinary.api.delete_resources_by_prefix('payment-slips', {
                            resource_type: 'raw'
                        });
                        await cloudinary.api.delete_resources_by_prefix('profile_pictures', {
                            resource_type: 'image'
                        });
                    } catch (cloudinaryError) {
                        console.error('❌ Cloudinary Cleanup Error:', cloudinaryError);
                        // Continue with database cleanup even if Cloudinary fails
                    }
                });

                // Send email to all admins notifying about the data deletion
                const admins = await User.find({ userType: 'admin' });
                for (const admin of admins) {
                    await sendEmail(
                        admin.email,
                        'Adem Baba – System Data Nuked',
                        `Hello ${admin.name}, the Adem Baba system data has been completely deleted by ${req.user.email} on ${new Date().toLocaleString()}. All user data, rooms, events, payments, and related records have been removed. This action is irreversible.`,
                        `
                        <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e2e2; border-radius: 8px;">
                            <h2 style="color: #c0392b;">⚠️ System Data Nuked</h2>
                            <p>Hi <strong>${admin.name}</strong>,</p>
                            <p>The Adem Baba system data has been completely deleted by <strong>${req.user.email}</strong> on <strong>${new Date().toLocaleString()}</strong>.</p>
                            <p>All records including users, rooms, events, payments, and related data have been permanently removed. This action is irreversible.</p>
                            <hr style="margin: 20px 0;" />
                            <p style="font-size: 12px; color: #666;">If you believe this was unauthorized, please contact the system administrator immediately.</p>
                        </div>
                        `
                    ).catch((emailError) => {
                        console.error('❌ Email Notification Error:', emailError);
                    });
                }

                console.log(`System data nuked by admin ${req.user.email} at ${new Date().toLocaleString()}`);
                res.json({ message: 'All system data has been successfully deleted' });
            } finally {
                session.endSession();
            }
        } catch (error) {
            console.error('❌ Nuke Data Error:', error);
            res.status(500).json({
                error: {
                    message: 'Failed to nuke system data',
                    code: 'SERVER_ERROR',
                    details: error.message
                }
            });
        }
    }
);
 */


/* SETTINGS ROTUES*/
// Get user settings

// Nuke system data
app.delete('/api/settings/nuke', verifyToken, isAdmin, async (req, res) => {
    try {
        // Delete all non-admin users
        await User.deleteMany({ userType: { $ne: 'admin' } });

        // Delete all settings except for the current admin
        await Settings.deleteMany({ user: { $ne: req.user.id } });

        // Delete all students, rooms, schedules, and payments
        await Student.deleteMany({});
        await Room.deleteMany({});
        await Schedule.deleteMany({});
        await Payment.deleteMany({});

        // Delete all avatars from Cloudinary (except current admin's)
        const users = await User.find({ _id: { $ne: req.user.id }, avatar: { $exists: true, $ne: '' } });
        for (const user of users) {
            if (user.avatar && user.avatar.includes('cloudinary')) {
                const publicId = user.avatar.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`adem_baba/avatars/${publicId}`);
            }
        }

        // Update the current admin's settings to default
        let settings = await Settings.findOne({ user: req.user.id });
        if (settings) {
            settings.notifications = { email: true, newStudent: false, maintenance: true };
            settings.preferences = { language: 'en', timezone: 'Africa/Lagos', theme: 'dark' };
            await settings.save();
        }

        // Notify admin via email
        const admin = await User.findById(req.user.id);
        await sendEmail(
            admin.email,
            'Adem Baba - System Data Reset',
            'All system data has been successfully reset.',
            '<p>All system data has been successfully reset.</p>'
        );

        res.json({ message: 'System data has been reset successfully' });
    } catch (error) {
        console.error('❌ Nuke System Error:', error);
        res.status(500).json({ error: { message: 'Failed to nuke system data', code: 'SERVER_ERROR' } });
    }
});


app.get('/api/settings', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('name email avatar userType security');
        const settings = await Settings.findOne({ user: req.user.id });
        if (!user) {
            return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
        }
        res.json({
            name: user.name,
            email: user.email,
            avatar: user.avatar || '',
            userType: user.userType,
            settings: settings || {
                notifications: { email: true, newStudent: false, maintenance: true },
                preferences: { language: 'en', timezone: 'Africa/Lagos', theme: 'dark' }
            },
            security: user.security || { twoFactorAuth: false }
        });
    } catch (error) {
        console.error('❌ Get Settings Error:', error);
        res.status(500).json({ error: { message: 'Server error', code: 'SERVER_ERROR' } });
    }
});

// Update profile
app.put(
    '/api/settings/profile',
    verifyToken,
    upload.single('avatar'),
    handleMulterError,
    [
        body('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
        body('email').isEmail().withMessage('Invalid email format')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: errors.array()[0].msg, code: 'VALIDATION_ERROR' } });
        }
        try {
            const { name, email } = req.body;
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
            }
            if (email !== user.email) {
                const emailExists = await User.findOne({ email, _id: { $ne: user._id } });
                if (emailExists) {
                    return res.status(400).json({ error: { message: 'Email already in use', code: 'EMAIL_TAKEN' } });
                }
            }
            let avatarUrl = user.avatar;
            if (req.file) {
                const uploadResult = await cloudinary.uploader.upload(req.file.path, {
                    folder: 'adem_baba/avatars',
                    resource_type: 'image'
                });
                avatarUrl = uploadResult.secure_url;
                if (user.avatar && user.avatar.includes('cloudinary')) {
                    const publicId = user.avatar.split('/').pop().split('.')[0];
                    await cloudinary.uploader.destroy(`adem_baba/avatars/${publicId}`);
                }
            }
            user.name = name;
            user.email = email;
            user.avatar = avatarUrl;
            await user.save();
            await sendEmail(
                user.email,
                'Adem Baba - Profile Updated',
                `Your profile has been updated successfully.`,
                `<p>Your profile has been updated successfully.</p>`
            );
            res.json({ message: 'Profile updated successfully', data: { name, email, avatar: avatarUrl } });
        } catch (error) {
            console.error('❌ Update Profile Error:', error);
            res.status(500).json({ error: { message: 'Failed to update profile', code: 'SERVER_ERROR' } });
        }
    }
);

// Update notification preferences
app.put(
    '/api/settings/notifications',
    verifyToken,
    isAdmin,
    [
        body('email').isBoolean().withMessage('Email notification must be a boolean'),
        body('newStudent').isBoolean().withMessage('New student notification must be a boolean'),
        body('maintenance').isBoolean().withMessage('Maintenance notification must be a boolean')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: errors.array()[0].msg, code: 'VALIDATION_ERROR' } });
        }
        try {
            const { email, newStudent, maintenance } = req.body;
            let settings = await Settings.findOne({ user: req.user.id });
            if (!settings) {
                settings = new Settings({ user: req.user.id });
            }
            settings.notifications = { email, newStudent, maintenance };
            await settings.save();
            res.json({ message: 'Notification preferences updated', data: settings.notifications });
        } catch (error) {
            console.error('❌ Update Notifications Error:', error);
            res.status(500).json({ error: { message: 'Failed to update notifications', code: 'SERVER_ERROR' } });
        }
    }
);

// Update security settings
app.put(
    '/api/settings/security',
    verifyToken,
    isAdmin,
    [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword').optional().isLength({ min: 8 }).matches(/[A-Z]/).matches(/[0-9]/).withMessage('New password must be at least 8 characters with uppercase and number'),
        body('confirmPassword').custom((value, { req }) => !req.body.newPassword || value === req.body.newPassword).withMessage('Passwords do not match'),
        body('twoFactorAuth').isBoolean().withMessage('Two-factor auth must be a boolean')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: errors.array()[0].msg, code: 'VALIDATION_ERROR' } });
        }
        try {
            const { currentPassword, newPassword, twoFactorAuth } = req.body;
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
            }
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: { message: 'Current password is incorrect', code: 'INVALID_PASSWORD' } });
            }
            if (newPassword) {
                user.password = await bcrypt.hash(newPassword, 10);
            }
            if (twoFactorAuth && !user.security.twoFactorAuth) {
                const secret = speakeasy.generateSecret({ name: `Adem Baba:${user.email}` });
                user.security.twoFactorSecret = secret.base32;
            } else if (!twoFactorAuth && user.security.twoFactorAuth) {
                user.security.twoFactorSecret = null;
            }
            user.security.twoFactorAuth = twoFactorAuth;
            await user.save();
            res.json({ message: 'Security settings updated' });
        } catch (error) {
            console.error('❌ Update Security Error:', error);
            res.status(500).json({ error: { message: 'Failed to update security settings', code: 'SERVER_ERROR' } });
        }
    }
);

// Generate 2FA QR code
app.get('/api/settings/2fa-qr', verifyToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
        }
        if (!user.security.twoFactorSecret) {
            const secret = speakeasy.generateSecret({ name: `Adem Baba:${user.email}` });
            user.security.twoFactorSecret = secret.base32;
            await user.save();
        }
        const qrCodeUrl = speakeasy.otpauthURL({
            secret: user.security.twoFactorSecret,
            label: `Adem Baba:${user.email}`,
            issuer: 'Adem Baba'
        });
        const qrCodeImage = await qrcode.toDataURL(qrCodeUrl);
        res.json({ qrCodeUrl: qrCodeImage });
    } catch (error) {
        console.error('❌ 2FA QR Code Error:', error);
        res.status(500).json({ error: { message: 'Failed to generate 2FA QR code', code: 'SERVER_ERROR' } });
    }
});

// Update system preferences
app.put(
    '/api/settings/system',
    verifyToken,
    isAdmin,
    [
        body('language').isIn(['en', 'fr', 'es']).withMessage('Invalid language'),
        body('timezone').isIn(['Africa/Lagos', 'Africa/Accra', 'Africa/Johannesburg']).withMessage('Invalid timezone'),
        body('theme').isIn(['light', 'dark']).withMessage('Invalid theme')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: { message: errors.array()[0].msg, code: 'VALIDATION_ERROR' } });
        }
        try {
            const { language, timezone, theme } = req.body;
            let settings = await Settings.findOne({ user: req.user.id });
            if (!settings) {
                settings = new Settings({ user: req.user.id });
            }
            settings.preferences = { language, timezone, theme };
            await settings.save();
            res.json({ message: 'System preferences updated', data: settings.preferences });
        } catch (error) {
            console.error('❌ Update System Error:', error);
            res.status(500).json({ error: { message: 'Failed to update system preferences', code: 'SERVER_ERROR' } });
        }
    }
);

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});