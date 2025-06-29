import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import { sendEmail } from '../services/email.service.js';
import { generateOTP } from '../services/otp.service.js';
import { frontendUrl } from '../utils/constants.js';

const SALT_ROUNDS = 10;

export const register = async (req, res) => {
    try {
        const { email, password, userType, name, matricNumber, phone, gender, dateOfBirth, faculty, level, department } = req.body;

        const existingUser = await User.findOne({ $or: [{ email }, { matricNumber: matricNumber || null }] });
        if (existingUser) {
            return res.status(400).json({ error: { message: 'Email or matric number already exists', code: 'DUPLICATE' } });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
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
            // Send notification to admins
        } else {
            await sendEmail(
                email,
                'Welcome to Adem Baba – Admin Access Granted',
                `Hello ${name}, you have been successfully registered as an Admin for Adem Baba. Your account is now active.`,
                `<div>Welcome email HTML</div>`
            );
        }

        res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
        console.error('❌ Registration Error:', error);
        res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');
        
        if (!user) {
            return res.status(400).json({ error: { message: 'Invalid email', code: 'NOT_FOUND' } });
        }

        // Check user status and verification
        if (user.status === 'Pending' && user.userType === 'student') {
            return res.status(403).json({ error: { message: 'Account awaiting approval', code: 'PENDING' } });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: { message: 'Invalid password', code: 'INVALID_CREDENTIALS' } });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, userType: user.userType, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: { id: user._id, name: user.name, email: user.email, userType: user.userType }
        });
    } catch (error) {
        console.error('❌ Login Error:', error);
        res.status(500).json({ error: { message: 'Server error during login', code: 'SERVER_ERROR' } });
    }
};

// Other auth controller functions...