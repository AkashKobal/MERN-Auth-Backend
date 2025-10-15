import express from 'express';
import {
    register,
    loginManual,
    loginGoogle,
    logout,
    resetPassword,
    sendOtpToEmail,
    sendResetPasswordOtp,
    verifyEmailOtp,
    isAuthenticated
} from '../Controllers/authControllers.js';
import { loginValidation, registerValidation, userAuth } from '../Middleware/authValidation.js';

const authRouter = express.Router();

// Registration (manual or Google can still use register endpoint if needed)
authRouter.post('/register', registerValidation, register);

// Login routes
authRouter.post('/login/manual', loginValidation, loginManual); // Manual email/password login
authRouter.post('/login/google', loginGoogle); // Google login

// Logout
authRouter.post('/logout', logout);

// OTP & verification routes
authRouter.post('/send-otp', userAuth, sendOtpToEmail);
authRouter.post('/verify-otp', userAuth, verifyEmailOtp);

// Authentication check
authRouter.post('/isAuthenticated', userAuth, isAuthenticated);

// Password reset
authRouter.post('/sendResetPasswordOtp', sendResetPasswordOtp);
authRouter.post('/resetPassword', resetPassword);

export default authRouter;
