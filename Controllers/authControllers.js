import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../Models/userModel.js";
import transporter from "../config/nodeMailer.js";


// Register endpoint
export const register = async (req, res) => {
    try {
        const { name, email, password, isGoogleUser } = req.body;

        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists with this email",
            });
        }

        let hashedPassword = password;
        if (!isGoogleUser) {
            const salt = await bcrypt.genSalt(10);
            hashedPassword = await bcrypt.hash(password, salt);
        }

        const newUser = await userModel.create({
            name,
            email,
            password: hashedPassword,
            isGoogleUser: !!isGoogleUser,
            isAccountVerified: !!isGoogleUser,
            roles: [{ authority: "USER" }],
        });

        const token = jwt.sign(
            { userId: newUser._id, roles: newUser.roles },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: newUser,
            token,
        });
    } catch (error) {
        console.error("Registration error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during registration",
        });
    }
};

// Manual login endpoint
export const loginManual = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found. Please register first.",
            });
        }

        if (user.isGoogleUser) {
            return res.status(400).json({
                success: false,
                message: "This is a Google account. Please log in with Google.",
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid password. Please try again.",
            });
        }

        const token = jwt.sign(
            { userId: user._id, roles: user.roles },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(200).json({
            success: true,
            message: "Manual login successful",
            user,
            token,
        });
    } catch (error) {
        console.error("Manual login error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during login",
        });
    }
};

// Google login endpoint
export const loginGoogle = async (req, res) => {
    try {
        const { email, googleId, name } = req.body; // googleId = decoded.sub

        let user = await userModel.findOne({ email });

        if (!user) {
            // First-time Google login → register
            user = await userModel.create({
                name,
                email,
                password: googleId, // optional, used internally, won't affect Google login
                isGoogleUser: true,
                isAccountVerified: true,
                roles: [{ authority: "USER" }],
            });
        } else if (!user.isGoogleUser) {
            return res.status(400).json({
                success: false,
                message: "This email is registered as manual account. Use normal login.",
            });
        }

        // Google login successful → issue token
        const token = jwt.sign(
            { userId: user._id, roles: user.roles },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(200).json({
            success: true,
            message: "Google login successful",
            user,
            token,
        });
    } catch (error) {
        console.error("Google login error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during Google login",
        });
    }
};


export const logout = async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 0,
        });
        return res.status(200).json({
            success: true,
            message: "Logout successful"
        });
    }
    catch (error) {
        console.error("Logout error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during logout. Please try again."
        });
    }
}

export const sendOtpToEmail = async (req, res) => {
    try {
        const { userId } = req.body;

        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.isAccountVerified) {
            return res.status(400).json({
                success: false,
                message: "Account is already verified"
            });
        }

        const otp = Math.floor(900000 * Math.random() + 100000).toString().padStart(6, '0');
        const otpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = otpExpireAt;
        await user.save();

        const mailMessage = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Verify your account",
            text: `Hello ${user.name}, your OTP is ${otp}`,
            html: `<p>Hello ${user.name},</p><p>Your OTP is: <strong>${otp}</strong></p><p>This OTP will expire in 10 minutes.</p>`,
        };

        await transporter.sendMail(mailMessage);

        return res.status(200).json({
            success: true,
            message: "OTP sent successfully to your email"
        });
    } catch (error) {
        console.error("Send OTP error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error sending OTP. Please try again later."
        });
    }
};

export const verifyEmailOtp = async (req, res) => {
    const { otp, userId } = req.body;

    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.verifyOtp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP. Please check and try again."
            });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP has expired. Please request a new one."
            });
        }

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Account verified successfully"
        });
    } catch (error) {
        console.error("Verify OTP error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error verifying OTP. Please try again later."
        });
    }
};

export const sendResetPasswordOtp = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found with this email address"
            });
        }

        const otp = Math.floor(900000 * Math.random() + 100000).toString().padStart(6, '0');
        const otpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes

        user.resetOtp = otp;
        user.resetOtpExpireAt = otpExpireAt;
        await user.save();

        const mailMessage = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Reset your password",
            text: `Hello ${user.name}, your OTP is ${otp}`,
            html: `<p>Hello ${user.name},</p><p>Your OTP for password reset is: <strong>${otp}</strong></p><p>This OTP will expire in 10 minutes.</p>`,
        };

        await transporter.sendMail(mailMessage);

        return res.status(200).json({
            success: true,
            message: "OTP sent successfully to your email"
        });
    }
    catch (error) {
        console.error("Send reset OTP error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error sending reset OTP. Please try again later."
        });
    }
}

export const resetPassword = async (req, res) => {
    const { otp, email, newPassword } = req.body;

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found with this email address"
            });
        }

        if (!user.resetOtp || user.resetOtp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP. Please check and try again."
            });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP has expired. Please request a new one."
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully"
        });
    }
    catch (error) {
        console.error("Reset password error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error resetting password. Please try again later."
        });
    }
};

export const getUserData = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        return res.status(200).json({
            success: true,
            message: "User data fetched successfully",
            userData: {
                id: user._id,
                name: user.name,
                email: user.email,
                isAccountVerified: user.isAccountVerified,
                roles: user.roles || [{ authority: "USER" }]
            }
        });
    } catch (error) {
        console.error("Get user data error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error fetching user data. Please try again later."
        });
    }
};

// isAuthenticated - Check if user is authenticated
export const isAuthenticated = async (req, res) => {
    try {
        // Get token from cookies
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Authentication token not found. Please log in."
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded || !decoded.userId) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token."
            });
        }

        // Get user from database
        const user = await userModel.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found."
            });
        }

        // Return user data
        return res.status(200).json({
            success: true,
            message: "User is authenticated",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isAccountVerified: user.isAccountVerified,
                roles: user.roles || [{ authority: "USER" }]
            }
        });
    } catch (error) {
        // Handle JWT errors
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token."
            });
        }

        // Handle token expiration
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: "Authentication token expired. Please log in again."
            });
        }

        console.error("Authentication error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during authentication check."
        });
    }
};

// Middleware to check if user is authenticated
export const authMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Authentication token not found. Please log in."
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded || !decoded.userId) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token."
            });
        }

        const user = await userModel.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found."
            });
        }

        // Add user to request object
        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token."
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: "Authentication token expired. Please log in again."
            });
        }

        console.error("Authentication middleware error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error during authentication check."
        });
    }
};

// Middleware to check if user is verified
export const isVerified = (req, res, next) => {
    if (!req.user.isAccountVerified) {
        return res.status(403).json({
            success: false,
            message: "Account not verified. Please verify your account first."
        });
    }
    next();
};

// Middleware to check if user has admin role
export const isAdmin = (req, res, next) => {
    const isAdmin = req.user.roles.some(role => role.authority === 'ADMIN');

    if (!isAdmin) {
        return res.status(403).json({
            success: false,
            message: "Access denied. Admin privileges required."
        });
    }
    next();
};