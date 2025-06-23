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
    'CLOUDINARY_API_SECRET'
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
        match: /^[A-Z0-9]+$/,
        required: function () { return this.userType === 'student'; }
    },
    phone: {
        type: String,
        match: /^\+?[\d\s()-]{10,}$/,
        required: function () { return this.userType === 'student'; }
    },
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other'],
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
        enum: ['100', '200', '300', '400', '500'],
        required: function () { return this.userType === 'student'; }
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
    resetPasswordExpires: { type: Date }
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

// Updated Register Route with Deadline Check
app.post(
    '/api/register',
    [
        body('email').isEmail().withMessage('Invalid email format'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('userType').isIn(['admin', 'student']).withMessage('Invalid user type'),
        body('matricNumber')
            .if(body('userType').equals('student'))
            .notEmpty().withMessage('Matric number is required for students')
            .matches(/^[A-Z0-9]+$/).withMessage('Invalid matric number format'),
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
            .isIn(['100', '200', '300', '400', '500']).withMessage('Invalid level'),
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

            // Check registration deadline first
            const deadline = await RegistrationDeadline.findOne();
            const now = new Date();

            if (req.body.userType === 'student') {
                if (deadline) {
                    const currentDeadline = deadline.extended ? deadline.extendedDeadline : deadline.deadline;
                    if (now > currentDeadline) {
                        return res.status(400).json({
                            error: {
                                message: 'Registration is closed. The deadline has passed.',
                                code: 'REGISTRATION_CLOSED',
                                deadline: currentDeadline
                            }
                        });
                    }
                }
            }

            const { email, password, userType, name, matricNumber, phone, gender, dateOfBirth, faculty, level, department } = req.body;

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
                            'New Student Registration Request',
                            `Student ${name} (${email}) has registered and is awaiting your approval.`,
                            `<h1>New Student Registration</h1><p>Student: ${name}<br>Email: ${email}<br>Matric Number: ${matricNumber}</p><p>Please review the request in the admin dashboard.</p>`
                        );
                    }
                }
            } else {
                await sendEmail(
                    email,
                    'Welcome Admin',
                    `You have been registered as an Admin for Adem Baba.`,
                    `<h1>Welcome ${name}</h1><p>Your admin account is active.</p>`
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
                'Your OTP for Adem Baba',
                `Your registration request has been approved. Your OTP is ${otp}. It expires in 1 day. Verify at ${frontendUrl}`,
                `<h1>Your OTP</h1><p>Your registration request has been approved.</p><p>Use this OTP to activate your account: <strong>${otp}</strong></p><p>Expires in 1 day.</p><p><a href="${frontendUrl}">Verify OTP</a></p>`
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

// Login Route
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
                return res.status(400).json({ error: { message: 'Invalid email', code: 'NOT_FOUND' } });
            }

            if (user.status === 'Pending' && user.userType === 'student') {
                return res.status(403).json({ error: { message: 'Account awaiting approval', code: 'PENDING' } });
            }

            if (user.status === 'Declined' && user.userType === 'student') {
                return res.status(403).json({ error: { message: 'Account declined', code: 'DECLINED' } });
            }

            if (user.userType === 'student' && !user.isVerified) {
                return res.status(403).json({ error: { message: 'Account not verified. Please verify your OTP.', code: 'NOT_VERIFIED' } });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: { message: 'Invalid password', code: 'INVALID_CREDENTIALS' } });
            }

            let needsPayment = false;
            if (user.userType === 'student') {
                const paymentSlip = await PaymentSlip.findOne({ student: user._id, status: 'Approved' });
                needsPayment = !paymentSlip;
            }

            const token = generateToken(user);
            res.json({
                message: 'Login successful',
                token,
                user: { id: user._id, name: user.name, email: user.email, userType: user.userType },
                needsPayment,
            });
        } catch (error) {
            console.error('❌ Login Error:', error);
            res.status(500).json({ error: { message: 'Server error during login', code: 'SERVER_ERROR' } });
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
                    'Adem Baba - Interview Scheduled',
                    `Your registration request has been accepted. You are invited for an interview on ${interviewDateTime.toLocaleString()}. Please attend at the Adem Baba Hostel Office. See the attached interview instructions.`,
                    `<h1>Interview Scheduled</h1><p>Your registration request has been accepted.</p><p><strong>Interview Details:</strong><br>Date: ${interviewDateTime.toLocaleDateString()}<br>Time: ${interviewTime}<br>Location: Adem Baba Hostel Office</p><p>Please see the attached interview instructions.</p>`,
                    [attachment]
                );
            } catch (fetchError) {
                console.error('❌ Failed to fetch interview document:', fetchError);
                // Fallback: Send email without attachment
                await sendEmail(
                    student.email,
                    'Adem Baba - Interview Scheduled',
                    `Your registration request has been accepted. You are invited for an interview on ${interviewDateTime.toLocaleString()}. Please attend at the Adem Baba Hostel Office.`,
                    `<h1>Interview Scheduled</h1><p>Your registration request has been accepted.</p><p><strong>Interview Details:</strong><br>Date: ${interviewDateTime.toLocaleDateString()}<br>Time: ${interviewTime}<br>Location: Adem Baba Hostel Office</p>`
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
                    'New Payment Slip Uploaded',
                    `Student ${student.name} has uploaded a payment slip of ₦${amount.toLocaleString()}. Please review in the admin dashboard.`,
                    `<h1>New Payment Slip</h1><p>Student: ${student.name}<br>Amount: ₦${amount.toLocaleString()}<br><a href="${paymentSlip.fileUrl}">View Payment Slip</a></p>`
                ).catch((emailError) => console.error('Email failed for', admin.email, emailError));
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
                'Payment Slip Approved',
                `Your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been approved. You can now access your dashboard.`,
                `<h1>Payment Approved</h1><p>Your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been approved.</p><p>You can now access your dashboard.</p>`
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
                'Payment Slip Rejected',
                `Your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been rejected. Please upload a valid payment slip.`,
                `<h1>Payment Rejected</h1><p>Your payment slip for ₦${paymentSlip.amount.toLocaleString()} has been rejected.</p><p>Please upload a valid payment slip.</p>`
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
            .select('amount status createdAt filePath')
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
                    'Your OTP for Adem Baba',
                    `Your registration request has been approved. Your OTP is ${otp}. It expires in 1 day. Verify at ${frontendUrl}. Please find the welcome guide attached.`,
                    `<h1>Your OTP</h1><p>Your registration request has been approved.</p><p>Use this OTP to activate your account: <strong>${otp}</strong></p><p>Expires in 1 day.</p><p><a href="${frontendUrl}">Verify OTP</a></p><p>Please find the welcome guide attached.</p>`,
                    [attachment]
                );
            } catch (fetchError) {
                console.error('❌ Failed to fetch welcome document:', fetchError);
                // Fallback: Send email without attachment
                await sendEmail(
                    student.email,
                    'Your OTP for Adem Baba',
                    `Your registration request has been approved. Your OTP is ${otp}. It expires in 1 day. Verify at ${frontendUrl}`,
                    `<h1>Your OTP</h1><p>Your registration request has been approved.</p><p>Use this OTP to activate your account: <strong>${otp}</strong></p><p>Expires in 1 day.</p><p><a href="${frontendUrl}">Verify OTP</a></p>`
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
                'Adem Baba - Registration Declined',
                `We regret to inform you that your registration request has been declined. Thank you for your interest in Adem Baba Hostel.`,
                `<h1>Registration Declined</h1><p>We regret to inform you that your registration request has been declined.</p><p>Thank you for your interest in Adem Baba Hostel.</p>`
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

            const resetToken = crypto.randomBytes(20).toString('hex');
            // Update only specific fields to avoid unintended changes
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
                'Adem Baba - Password Reset',
                `You requested a password reset for your Adem Baba account. Click the link to reset your password: ${resetUrl}\nThis link expires in 1 hour.\nIf you did not request this, please ignore this email.`,
                `<h1>Password Reset Request</h1><p>You requested a password reset for your Adem Baba account.</p><p>Click <a href="${resetUrl}">here</a> to reset your password.</p><p>This link expires in 1 hour.</p><p>If you did not request this, please ignore this email.</p>`
            );

            console.log('Reset email sent:', { email, resetUrl });
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
            });

            if (!user) {
                return res.status(400).json({ error: { message: 'Invalid or expired reset token', code: 'INVALID_TOKEN' } });
            }

            user.password = await hashing(password);
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            await sendEmail(
                user.email,
                'Adem Baba - Password Reset Successful',
                'Your password has been successfully reset. You can now log in with your new password.',
                `<h1>Password Reset Successful</h1><p>Your password has been successfully reset.</p><p>You can now log in with your new password.</p>`
            );

            res.json({ message: 'Password reset successful' });
        } catch (error) {
            console.error('❌ Reset Password Error:', error);
            res.status(500).json({ error: { message: 'Failed to reset password', code: 'SERVER_ERROR' } });
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
app.put(
    '/api/students/:id',
    verifyToken,
    isAdmin,
    [
        param('id').isMongoId().withMessage('Invalid student ID'),
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
        body('matricNumber').notEmpty().matches(/^[A-Z0-9]+$/).withMessage('Invalid matric number format'),
        body('phone').notEmpty().matches(/^\+?[\d\s()-]{10,}$/).withMessage('Invalid phone number format'),
        body('gender').isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender'),
        body('dateOfBirth').isISO8601().toDate().withMessage('Invalid date of birth')
            .custom((value) => {
                const dob = new Date(value);
                const today = new Date();
                if (dob >= today || today.getFullYear() - dob.getFullYear() < 15) {
                    throw new Error('Must be at least 15 years old');
                }
                return true;
            }),
        body('faculty').trim().notEmpty().withMessage('Faculty is required'),
        body('level').isIn(['100', '200', '300', '400', '500']).withMessage('Invalid level'),
        body('department').trim().notEmpty().withMessage('Department is required'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { id } = req.params;
            const { name, email, matricNumber, phone, gender, dateOfBirth, faculty, level, department } = req.body;

            const student = await User.findById(id);
            if (!student || student.userType !== 'student') {
                return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
            }

            const existingUser = await User.findOne({
                $or: [{ email }, { matricNumber }],
                _id: { $ne: id },
            });
            if (existingUser) {
                return res.status(400).json({ error: { message: 'Email or matric number already exists', code: 'DUPLICATE' } });
            }

            student.name = name;
            student.email = email;
            student.matricNumber = matricNumber;
            student.phone = phone;
            student.gender = gender;
            student.dateOfBirth = dateOfBirth;
            student.faculty = faculty;
            student.level = level;
            student.department = department;
            await student.save();

            res.json({ message: 'Student updated successfully' });
        } catch (error) {
            console.error('❌ Update Student Error:', error);
            res.status(500).json({ error: { message: 'Failed to update student', code: 'SERVER_ERROR' } });
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
app.post(
    '/api/students/assign-room',
    verifyToken,
    isAdmin,
    [body('studentId').isMongoId().withMessage('Invalid student ID'), body('roomId').isMongoId().withMessage('Invalid room ID')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { studentId, roomId } = req.body;
            const student = await User.findById(studentId);
            if (!student || student.userType !== 'student') {
                return res.status(404).json({ error: { message: 'Student not found', code: 'NOT_FOUND' } });
            }

            const room = await Room.findById(roomId);
            if (!room) {
                return res.status(404).json({ error: { message: 'Room not found', code: 'NOT_FOUND' } });
            }

            if (room.status === 'Maintenance' || room.occupants.length >= room.capacity) {
                return res.status(400).json({ error: { message: 'Room is unavailable or full', code: 'ROOM_UNAVAILABLE' } });
            }

            if (student.room) {
                await Room.updateOne({ _id: student.room }, { $pull: { occupants: studentId } });
            }

            student.room = roomId;
            room.occupants.push(studentId);
            room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
            await student.save();
            await room.save();

            const settings = await Settings.findOne({ user: student._id });
            if (settings?.notifications.email) {
                await sendEmail(
                    student.email,
                    'Room Assignment',
                    `You have been assigned to Room ${room.roomNumber}.`,
                    `<h1>Room Assignment</h1><p>You have been assigned to Room ${room.roomNumber} (${room.type}).</p>`
                );
            }

            res.json({ message: 'Room assigned successfully' });
        } catch (error) {
            console.error('❌ Assign Room Error:', error);
            res.status(500).json({ error: { message: 'Failed to assign room', code: 'SERVER_ERROR' } });
        }
    }
);

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
                        'New Maintenance Request',
                        `Room ${room.roomNumber}: ${issue}`,
                        `<h1>Maintenance Request</h1><p>Room: ${room.roomNumber}<br>Issue: ${issue}<br>Type: ${type}</p>`
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

// Get Settings (User-specific)
app.get('/api/settings', verifyToken, async (req, res) => {
    try {
        const settings = await Settings.findOne({ user: req.user.id }).lean();
        if (!settings) {
            return res.status(404).json({ error: { message: 'Settings not found', code: 'NOT_FOUND' } });
        }
        res.json(settings);
    } catch (error) {
        console.error('❌ Get Settings Error:', error);
        res.status(500).json({ error: { message: 'Failed to load settings', code: 'SERVER_ERROR' } });
    }
});

// Update Profile Settings
app.put(
    '/api/settings/profile',
    verifyToken,
    [
        body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
        body('email').optional().isEmail().withMessage('Invalid email format'),
        body('phone').optional().matches(/^\+?[\d\s()-]{10,}$/).withMessage('Invalid phone number format'),
        body('gender').optional().isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender'),
        body('dateOfBirth')
            .optional()
            .isISO8601()
            .toDate()
            .withMessage('Invalid date of birth')
            .custom((value) => {
                const dob = new Date(value);
                const today = new Date();
                if (dob >= today || today.getFullYear() - dob.getFullYear() < 15) {
                    throw new Error('Must be at least 15 years old');
                }
                return true;
            }),
        body('faculty').optional().trim().notEmpty().withMessage('Faculty cannot be empty'),
        body('level').optional().isIn(['100', '200', '300', '400', '500']).withMessage('Invalid level'),
        body('department').optional().trim().notEmpty().withMessage('Department cannot be empty'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { name, email, phone, gender, dateOfBirth, faculty, level, department } = req.body;
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
            }

            if (email && email !== user.email) {
                const existingUser = await User.findOne({ email });
                if (existingUser) {
                    return res.status(400).json({ error: { message: 'Email already exists', code: 'DUPLICATE' } });
                }
                user.email = email;
            }

            if (name) user.name = name;
            if (phone && user.userType === 'student') user.phone = phone;
            if (gender && user.userType === 'student') user.gender = gender;
            if (dateOfBirth && user.userType === 'student') user.dateOfBirth = dateOfBirth;
            if (faculty && user.userType === 'student') user.faculty = faculty;
            if (level && user.userType === 'student') user.level = level;
            if (department && user.userType === 'student') user.department = department;

            await user.save();
            res.json({ message: 'Profile updated successfully' });
        } catch (error) {
            console.error('❌ Update Profile Error:', error);
            res.status(500).json({ error: { message: 'Failed to update profile', code: 'SERVER_ERROR' } });
        }
    }
);

// Update Notification Settings
app.put(
    '/api/settings/notifications',
    verifyToken,
    [
        body('notifications.email').optional().isBoolean().withMessage('Email notification must be a boolean'),
        body('notifications.newStudent').optional().isBoolean().withMessage('New student notification must be a boolean'),
        body('notifications.maintenance').optional().isBoolean().withMessage('Maintenance notification must be a boolean'),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { notifications } = req.body;
            let settings = await Settings.findOne({ user: req.user.id });

            if (!settings) {
                settings = new Settings({ user: req.user.id, notifications: {} });
            }

            if (notifications.email !== undefined) settings.notifications.email = notifications.email;
            if (notifications.newStudent !== undefined) settings.notifications.newStudent = notifications.newStudent;
            if (notifications.maintenance !== undefined) settings.notifications.maintenance = notifications.maintenance;

            settings.updatedAt = new Date();
            await settings.save();

            res.json({ message: 'Notification settings updated successfully' });
        } catch (error) {
            console.error('❌ Update Notifications Error:', error);
            res.status(500).json({ error: { message: 'Failed to update notification settings', code: 'SERVER_ERROR' } });
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
        await sendEmail(
            email,
            'Adem Baba - Password Reset',
            `You requested a password reset for your Adem Baba account. Click the link to reset your password: ${resetUrl}. This link expires in 1 hour.`,
            `<p>You requested a password reset for your Adem Baba account.</p>
            <p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>
            <p>If you did not request this, please ignore this email.</p>`
        );

        res.json({ message: 'Password reset email sent. Check your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: { message: 'Server error' } });
    }
});

// Reset password route
app.post(
    '/api/reset-password/:token',
    [
        param('token').notEmpty().withMessage('Reset token is required'),
        body('password')
            .matches(/^(?=.*\d)(?=.*[a-zA-Z]).{8,}$/)
            .withMessage('Password must be at least 8 characters with letters and numbers')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { token } = req.params;
            const { password } = req.body;

            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() },
            });

            if (!user) {
                return res.status(400).json({ error: { message: 'Invalid or expired reset token', code: 'INVALID_TOKEN' } });
            }

            user.password = await hashing(password);
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            await sendEmail(
                user.email,
                'Adem Baba - Password Reset Successful',
                'Your password has been successfully reset. You can now log in with your new password.',
                `<h1>Password Reset Successful</h1><p>Your password has been successfully reset.</p><p>You can now log in with your new password.</p>`
            );

            console.log('Password reset successful for:', user.email);
            res.json({ message: 'Password reset successful' });
        } catch (error) {
            console.error('❌ Reset Password Error:', error);
            res.status(500).json({ error: { message: 'Failed to reset password', code: 'SERVER_ERROR' } });
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
        body('deadline').isISO8601().toDate().withMessage('Invalid deadline date')
            .custom((value) => {
                const deadline = new Date(value);
                const now = new Date();
                if (deadline <= now) {
                    throw new Error('Deadline must be in the future');
                }
                return true;
            }),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { deadline } = req.body;

            // Check if there's an existing deadline
            let existingDeadline = await RegistrationDeadline.findOne();

            if (existingDeadline) {
                // Update existing deadline
                existingDeadline.deadline = deadline;
                existingDeadline.extended = false;
                existingDeadline.extendedDeadline = undefined;
                existingDeadline.updatedAt = new Date();
                await existingDeadline.save();
            } else {
                // Create new deadline
                existingDeadline = new RegistrationDeadline({ deadline });
                await existingDeadline.save();
            }

            res.json({
                message: 'Registration deadline set successfully',
                deadline: existingDeadline.deadline,
                extended: existingDeadline.extended,
                extendedDeadline: existingDeadline.extendedDeadline
            });
        } catch (error) {
            console.error('❌ Set Registration Deadline Error:', error);
            res.status(500).json({ error: { message: 'Failed to set registration deadline', code: 'SERVER_ERROR' } });
        }
    }
);

app.post(
    '/api/registration-deadline/extend',
    verifyToken,
    isAdmin,
    [
        body('extendedDeadline').isISO8601().toDate().withMessage('Invalid extended deadline date')
            .custom((value) => {
                const extendedDeadline = new Date(value);
                const now = new Date();
                if (extendedDeadline <= now) {
                    throw new Error('Extended deadline must be in the future');
                }
                return true;
            }),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
            }

            const { extendedDeadline } = req.body;

            let deadline = await RegistrationDeadline.findOne();
            if (!deadline) {
                return res.status(400).json({ error: { message: 'No registration deadline set', code: 'NO_DEADLINE' } });
            }

            deadline.extended = true;
            deadline.extendedDeadline = extendedDeadline;
            deadline.updatedAt = new Date();
            await deadline.save();

            res.json({
                message: 'Registration deadline extended successfully',
                deadline: deadline.deadline,
                extended: deadline.extended,
                extendedDeadline: deadline.extendedDeadline
            });
        } catch (error) {
            console.error('❌ Extend Registration Deadline Error:', error);
            res.status(500).json({ error: { message: 'Failed to extend registration deadline', code: 'SERVER_ERROR' } });
        }
    }
);

app.get(
    '/api/registration-deadline',
    verifyToken,
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

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});