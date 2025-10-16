import express from 'express';
import { userAuth } from '../Middleware/authMiddleware.js';
import { otpValidation } from '../validation/authValidation.js';
import { resetPassword, sendOtpToEmail, sendResetPasswordOtp, verifyEmailOtp } from '../Controllers/emailController.js';
import { isAuthenticated } from '../Controllers/authControllers.js';

const emailRouter = express.Router();

emailRouter.post('/send-otp', userAuth, sendOtpToEmail);
emailRouter.post('/verify-otp', userAuth, otpValidation, verifyEmailOtp);

// Authentication check
emailRouter.post('/isAuthenticated', userAuth, isAuthenticated);

// Password reset
emailRouter.post('/sendResetPasswordOtp', sendResetPasswordOtp);
emailRouter.post('/resetPassword', resetPassword);

export default emailRouter;
