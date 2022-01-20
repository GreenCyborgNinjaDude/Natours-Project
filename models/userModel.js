const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    require: [true, 'User must have a name!'],
    trim: true,
    maxlength: [40, 'A username must have less or equal then 40 characters'],
    minlength: [3, 'A username must have more or equal then 3 characters']
  },
  email: {
    type: String,
    required: [true, 'Please enter your email!'],
    trim: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Plead enter a valid email']
  },
  photo: {
    type: String
  },
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please enter your password'],
    trim: true,
    minlength: [8, 'A password must have more or equal then 8 characters'],
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please re-enter your password'],
    trim: true,
    validate: {
      //Only work on user created or save
      validator: function(el) {
        return el === this.password;
      },
      message: 'Password you have put in is not the same! '
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  }
});

userSchema.pre('save', async function(next) {
  //Only run if password is modified
  if (!this.isModified('password')) return next();

  //hash the password of cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  this.passwordConfirm = undefined;
  next();
});

userSchema.pre(/^find/, async function(next) {
  //This point to current document
  this.find({ active: { $ne: false } });
  next();
});

userSchema.methods.correctPassword = async function(
  canidatePassword,
  userPassword
) {
  return await bcrypt.compare(canidatePassword, userPassword);
};

userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    console.log(changedTimestamp, JWTTimestamp);
    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
