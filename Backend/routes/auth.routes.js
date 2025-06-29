// backend/routes/auth.js
import express from 'express';
import { body, validationResult } from 'express-validator';
import { hashing, generateOTP, generateToken } from '../utils/auth.js';
import { sendEmail } from '../config/email.js';
import User from '../models/User.js';
import RegistrationDeadline from '../models/RegistrationDeadline.js';
import Settings from '../models/Settings.js';
import { verifyToken } from '../middleware/auth.js';

const router = express.Router();

// Register Route
router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('userType').isIn(['admin', 'student']).withMessage('Invalid user type'),
    // ... other validations (same as original)
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: { message: 'Validation failed', details: errors.array(), code: 'VALIDATION_ERROR' } });
      }

      const { email, password, userType, name, matricNumber, phone, gender, dateOfBirth, faculty, level, department } = req.body;

      // Check registration deadline
      if (userType === 'student') {
        const deadline = await RegistrationDeadline.findOne();
        const now = new Date();
        if (deadline) {
          const currentDeadline = deadline.extended ? deadline.extendedDeadline : deadline.deadline;
          if (now > currentDeadline) {
            return res.status(400).json({
              error: {
                message: 'Registration is closed. The deadline has passed.',
                code: 'REGISTRATION_CLOSED',
                deadline: currentDeadline,
              },
            });
          }
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
              // ... email template (same as original)
            );
          }
        }
      } else {
        await sendEmail(
          email,
          'Welcome to Adem Baba – Admin Access Granted',
          `Hello ${name}, you have been successfully registered as an Admin for Adem Baba. Your account is now active.`,
          // ... email template (same as original)
        );
      }

      res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
      console.error('❌ Registration Error:', error);
      res.status(500).json({ error: { message: 'Server Error', code: 'SERVER_ERROR' } });
    }
  }
);

// Login, OTP, and password reset routes would follow a similar pattern
// ...

export default router;