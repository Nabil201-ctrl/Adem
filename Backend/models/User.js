// backend/models/User.js
import mongoose from 'mongoose';

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
    required: function () { return this.userType === 'student'; },
  },
  phone: {
    type: String,
    match: /^\+?[\d\s()-]{10,}$/,
    required: function () { return this.userType === 'student'; },
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other'],
    required: function () { return this.userType === 'student'; },
  },
  dateOfBirth: {
    type: Date,
    required: function () { return this.userType === 'student'; },
  },
  faculty: {
    type: String,
    trim: true,
    required: function () { return this.userType === 'student'; },
  },
  level: {
    type: String,
    enum: ['100', '200', '300', '400', '500'],
    required: function () { return this.userType === 'student'; },
  },
  department: {
    type: String,
    trim: true,
    required: function () { return this.userType === 'student'; },
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
});

export default mongoose.model('User', UserSchema);