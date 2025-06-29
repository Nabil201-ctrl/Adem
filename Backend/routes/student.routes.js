// backend/routes/student.js
import express from 'express';
import { verifyToken, isStudent } from '../middleware/auth.js';
import { validationResult } from 'express-validator';
import User from '../models/User.js';
import Event from '../models/Event.js';
import PaymentSlip from '../models/PaymentSlip.js';

const router = express.Router();

// Student Dashboard
router.get('/dashboard', verifyToken, isStudent, async (req, res) => {
  try {
    const paymentSlip = await PaymentSlip.findOne({
      student: req.user.id,
      status: 'Approved',
    }).lean();

    if (!paymentSlip) {
      return res.status(403).json({
        error: {
          message: 'Payment required. Please upload a payment slip.',
          code: 'PAYMENT_REQUIRED',
          redirect: '/login-form/payment-upload.html',
        },
      });
    }

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

export default router;