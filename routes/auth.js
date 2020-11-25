const express = require('express');
const {
  register,
  confirmEmailAddress,
  resendConfirmationEmail,
  login,
  getMe,
  forgotPassword,
  resetPassword,
  updateDetails,
  updatePassword,
  logout,
  deleteUser,
  loginWithGoogle,
  createGoogleUrl,
  loginWithFacebook,
  createFacebookUrl,
} = require('../controllers/auth');

const router = express.Router();

const { protect } = require('../middleware/auth');

router.post('/register', register);
router.get('/confirmemail/:confirmtoken', confirmEmailAddress);
router.post('/resendconfirmemail', resendConfirmationEmail);
router.post('/login', login);
router.get('/me', protect, getMe);
router.get('/logout', logout);
router.put('/updatedetails', protect, updateDetails);
router.put('/updatepassword', protect, updatePassword);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resettoken', resetPassword);
router.delete('/me/:id', protect, deleteUser);
router.get('/google/login', loginWithGoogle);
router.get('/google', createGoogleUrl);
router.get('/facebook/login', loginWithFacebook);
router.get('/facebook', createFacebookUrl);

module.exports = router;
