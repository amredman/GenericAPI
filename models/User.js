const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    match: [/^\w+([+\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{1,3})+$/, 'Please add a valid email'],
  },
  role: {
    type: String,
    enum: ['user'], //Add any additional roles here.  Admin role exists, but cannot be added through API.
    default: 'user',
  },
  password: {
    type: String,
    required: false,
    minlength: 6,
    select: false,
  },
  googleId: {
    type: String,
    required: false,
    select: false,
  },
  facebookId: {
    type: String,
    required: false,
    select: false,
  },
  emailConfirmed: {
    type: Boolean,
    default: false,
  },
  confirmEmailToken: {
    type: String,
    select: false,
  },
  resetPasswordToken: {
    type: String,
    select: false,
  },
  resetPasswordExpire: {
    type: Date,
    select: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Encrypt password using bcrypt
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.pre('validate', async function (next) {
  if (!this.password && !this.googleId && !this.facebookId) {
    // block email verification
    if (!this.emailConfirmed) {
      next(new Error('Either provide a password or use a 3rd party login provider'));
    }
  }
});

// Sign JWT and return
UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function (enteredPassword) {
  if (this.googleId || this.facebookId) {
    // not a password sign on account
    return false
  }
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate and hash confirm email token
UserSchema.methods.getConfirmEmailToken = function () {
  // Generate token
  let confirmToken = crypto.randomBytes(20).toString('hex');

  // Return hashed version of token
  confirmToken = crypto.createHash('sha256').update(confirmToken).digest('hex');

  // Set confirmEmailToken field
  this.confirmEmailToken = confirmToken;

  return confirmToken;
};

// Generate and hash password token
UserSchema.methods.getResetPasswordToken = function () {
  // Generate token
  let resetToken = crypto.randomBytes(20).toString('hex');

  // Hash token and set to resetPasswordToken field
  resetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  // Set resetPasswordToken to hashed token
  this.resetPasswordToken = resetToken;

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  console.log(`Reset token: ${resetToken}`);

  return resetToken;
};

module.exports = mongoose.model('User', UserSchema);
