const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
const sendEmail = require('../utils/sendEmail');

const User = require('../models/User');

const queryString = require('query-string');
const axios = require('axios');

// @desc     Register user
// @route    POST /api/v1/auth/register
// @access   Public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  //Create user
  let user = await User.create({
    name,
    email,
    password,
    role,
  });

  // Generate confirm email token and save user
  const confirmToken = user.getConfirmEmailToken();
  await user.save({ validateBeforeSave: false });
  if (!sendConfirmationEmail(req.protocol, req.get('host'), user.email, confirmToken)) {
    return next(new ErrorResponse('Email could not be sent', 500));
  }

  //Re-select user so we don't return the confirmEmailToken field
  user = await User.find({ email });

  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc     Confirm email address
// @route    GET /api/v1/auth/confirmemail
// @access   Public
exports.confirmEmailAddress = asyncHandler(async (req, res, next) => {
  // Get hashed token
  const confirmEmailToken = req.params.confirmtoken;
  const user = await User.findOne({ confirmEmailToken });

  if (!user) {
    return next(new ErrorResponse('Invalid Token', 400));
  }

  user.emailConfirmed = true;
  user.confirmEmailToken = undefined;
  await user.save();
  const redirectUrl = `http://${process.env.FRONTEND_HOST}/api/v1/auth/confirmemail/${confirmEmailToken}`;
  res.redirect(redirectUrl)
    /*
  res.status(200).json({
    success: true,
    data: {},
  });
  */
});

// @desc     Re-send confirmation email
// @route    POST /api/v1/auth/resendconfirmemail
// @access   Public
exports.resendConfirmationEmail = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  console.log(req.get('host'))
  console.log(process.env.FRONTEND_HOST)
  // Validate email & password
  if (!email) {
    return next(new ErrorResponse('Please provide an email', 400));
  }

  // Check for user and send email if user found
  const user = await User.findOne({ email }).select('+confirmEmailToken');
  if (user && !user.emailConfirmed) {
    if (!sendConfirmationEmail(req.protocol, req.get('host'), user.email, user.confirmEmailToken)) {
      return next(new ErrorResponse('Email could not be sent', 500));
    }
  }

  res.status(200).json({
    success: true,
    data: {},
  });
});

// @desc     Register user
// @route    POST /api/v1/auth/login
// @access   Public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  // Validate email & password
  if (!email || !password) {
    return next(new ErrorResponse('Please provide an email and password', 400));
  }

  // Check for user
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    return next(new ErrorResponse('Invalid Credentials', 401));
  }

  // Check if password matches
  const isMatch = await user.matchPassword(password);

  if (!isMatch) {
    return next(new ErrorResponse('Invalid Credentials', 401));
  }

  // Check if email address has been confirmed
  if (!user.emailConfirmed) {
    return next(new ErrorResponse('Email address has not been confirmed', 403));
  }

  sendTokenResponse(user, 200, res);
});

// @desc     Log user out / clear cookie
// @route    GET /api/v1/auth/logout
// @access   Private
exports.logout = asyncHandler(async (req, res, next) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({
    success: true,
    data: {},
  });
});

// @desc     Get current logged in user
// @route    POST /api/v1/auth/login
// @access   Private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc     Update user details
// @route    PUT /api/v1/auth/updatedetails
// @access   Private
exports.updateDetails = asyncHandler(async (req, res, next) => {
  const fieldsToUpdate = {
    name: req.body.name,
    email: req.body.email,
  };

  const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc     Update Password
// @route    PUT /api/v1/auth/updatepassword
// @access   Private
exports.updatePassword = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('+password');

  // Check current password
  if (!(await user.matchPassword(req.body.currentPassword))) {
    return next(new ErrorResponse('Password is incorrect', 401));
  }

  user.password = req.body.newPassword;
  await user.save();

  sendTokenResponse(user, 200, res);
});

// @desc     Forgot Password
// @route    POST /api/v1/auth/forgotpassword
// @access   Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (user) {
    if (!user.emailConfirmed) {
      return next(new ErrorResponse('Please confirm email address before resetting password', 401));
    }

    // Get reset token
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // Create reset url
    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/auth/resetpassword/${resetToken}`;

    const messageText = `To reset your password, please make a PUT request to: \n\n ${resetUrl}`;
    const messageHtml = `To confirm your email address, please make a PUT request to: \n\n ${resetUrl}`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Password Reset Token',
        message: messageText,
        html: messageHtml,
      });
    } catch (err) {
      console.log(err);

      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });
    }
  }

  res.status(200).json({ success: true, data: {} });
});

// @desc     Reset password
// @route    PUT /api/v1/auth/resetpassword/:resettoken
// @access   Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  // Get hashed token
  const resetPasswordToken = req.params.resettoken;

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ErrorResponse('Invalid Token', 400));
  }

  // Set new password
  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res.status(200).json({ success: true, data: {} });
});

// @desc     Delete Account
// @route    DELETE /api/v1/auth/me/:id
// @access   Private
exports.deleteUser = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  // Make sure user is current user or admin
  if (user.id.toString() !== req.user.id && req.user.role !== 'admin') {
    return next(new ErrorResponse(`User  ${user.id} is not authorized to delete this user`, 401));
  }

  user.remove();

  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({ success: true, data: {} });
});

// @desc     Login with Google.  This endpoint is hit from Google and should not be accessed from a front-end application.
// @route    POST /api/v1/auth/google/login
// @access   Public
exports.loginWithGoogle = asyncHandler(async (req, res, next) => {
  const urlParams = queryString.parse(req.originalUrl.replace('/api/v1/auth/google/login?', ''));

  //Create access token
  const { data } = await axios({
    url: `https://oauth2.googleapis.com/token`,
    method: 'post',
    data: {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${req.protocol}://${req.get('host')}/api/v1/auth/google/login`,
      grant_type: 'authorization_code',
      code: urlParams.code,
    },
  });

  //Select user information from Google
  const googleData = await axios({
    url: 'https://www.googleapis.com/oauth2/v2/userinfo',
    method: 'get',
    headers: {
      Authorization: `Bearer ${data.access_token}`,
    },
  });

  const email = googleData.data.email;
  let user = await User.findOne({ email }).select('+facebookId');

  if (!user) {
    user = await User.create({
      name: googleData.data.name,
      email,
      googleId: googleData.data.id,
    });
  } else if (user.facebookId) {
    //User has already logged in with Facebook
    return next(new ErrorResponse('User has already created an account with Facebook', 400));
  }

  sendTokenResponse(user, 200, res);
});

// @desc     Create URL to enable Login with Google
// @route    GET /api/v1/auth/google
// @access   Public
exports.createGoogleUrl = asyncHandler(async (req, res, next) => {
  const stringifiedParams = queryString.stringify({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: `${req.protocol}://${req.get('host')}/api/v1/auth/google/login`,
    scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'].join(' '),
    response_type: 'code',
    access_type: 'offline',
    prompt: 'consent',
  });

  const googleLoginUrl = `https://accounts.google.com/o/oauth2/v2/auth?${stringifiedParams}`;

  res.status(200).json({ success: true, data: { googleLoginUrl } });
});

// @desc     Login with Facebook.  This endpoint is hit from Facebook and should not be accessed from a front-end application.
// @route    GET /api/v1/auth/facebook/login
// @access   Private
exports.loginWithFacebook = asyncHandler(async (req, res, next) => {
  const urlParams = queryString.parse(req.originalUrl.replace('/api/v1/auth/facebook/login?', ''));

  //Create access token
  const { data } = await axios({
    url: 'https://graph.facebook.com/v4.0/oauth/access_token',
    method: 'get',
    params: {
      client_id: process.env.FACEBOOK_APP_ID,
      client_secret: process.env.FACEBOOK_APP_SECRET,
      redirect_uri: `${req.protocol}://${req.get('host')}/api/v1/auth/facebook/login`,
      code: urlParams.code,
    },
  });

  //Select user information from Facebook
  const facebookData = await axios({
    url: 'https://graph.facebook.com/me',
    method: 'get',
    params: {
      fields: ['id', 'email', 'first_name', 'last_name'].join(','),
      access_token: data.access_token,
    },
  });

  //Search for user and create if not found
  const email = facebookData.data.email;
  let user = await User.findOne({ email }).select('+googleId');

  if (!user) {
    user = await User.create({
      name: facebookData.data.first_name + ' ' + facebookData.data.last_name,
      email,
      facebookId: facebookData.data.id,
    });
  } else if (user.googleId) {
    //User has already logged in with Google
    return next(new ErrorResponse('User has already created an account with Google', 400));
  }

  //Log the user in and return a valid token
  sendTokenResponse(user, 200, res);
});

// @desc     Create URL to enable Login with Facebook
// @route    GET /api/v1/auth/facebook
// @access   Public
exports.createFacebookUrl = asyncHandler(async (req, res, next) => {
  const stringifiedParams = queryString.stringify({
    client_id: process.env.FACEBOOK_APP_ID,
    redirect_uri: `${req.protocol}://${req.get('host')}/api/v1/auth/facebook/login`,
    scope: ['email'],
    response_type: 'code',
    auth_type: 'rerequest',
    display: 'popup',
  });

  const facebookLoginUrl = `https://www.facebook.com/v4.0/dialog/oauth?${stringifiedParams}`;

  res.status(200).json({ success: true, data: { facebookLoginUrl } });
});

// Get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
  // Create token
  const token = user.getSignedJwtToken();

  const options = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }

  res.status(statusCode).cookie('token', token, options).json({ success: true, token });
};

const sendConfirmationEmail = async (protocol, host, email, confirmToken) => {
  // Create confirm email url
  const confirmUrl = `${protocol}://${host}/api/v1/auth/confirmemail/${confirmToken}`;

  const messageText = `To confirm your email address, please make a GET request to: \n\n ${confirmUrl}`;
  const messageHtml = `To confirm your email address, please make a GET request to: \n\n ${confirmUrl}`;

  try {
    await sendEmail({
      email,
      subject: 'User created',
      text: messageText,
      html: messageHtml,
    });
    return true;
  } catch (err) {
    console.log(err);
    return false;
  }
};
