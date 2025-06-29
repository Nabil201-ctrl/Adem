// backend/utils/auth.js
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const SALT_ROUNDS = 10;

export async function hashing(plainPassword) {
  return await bcrypt.hash(plainPassword, SALT_ROUNDS);
}

export function generateOTP() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

export function generateToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, userType: user.userType, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}