import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const verifyToken = (req, res, next) => {
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
};

export const isAdmin = (req, res, next) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: { message: 'Access denied. Admins only.', code: 'ADMIN_ONLY' } });
    }
    next();
};

export const isStudent = (req, res, next) => {
    if (req.user.userType !== 'student') {
        return res.status(403).json({ error: { message: 'Access denied. Students only.', code: 'STUDENT_ONLY' } });
    }
    next();// backend/middleware/auth.js
import jwt from 'jsonwebtoken';

export function verifyToken(req, res, next) {
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

export function isAdmin(req, res, next) {
  if (req.user.userType !== 'admin') {
    return res.status(403).json({ error: { message: 'Access denied. Admins only.', code: 'ADMIN_ONLY' } });
  }
  next();
}

export function isStudent(req, res, next) {
  if (req.user.userType !== 'student') {
    return res.status(403).json({ error: { message: 'Access denied. Students only.', code: 'STUDENT_ONLY' } });
  }
  next();
}
};