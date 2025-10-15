import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../Models/userModel.js";
import transporter from "../config/nodeMailer.js";
import logger from "../utils/logger.js";

// Generate JWT
const createToken = (user) =>
    jwt.sign(
        { userId: user._id, roles: user.roles },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
    );
// ---------- REGISTER ----------
export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await userModel.findOne({ email });
        if (existingUser)
            return res.status(409).json({ success: false, message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await userModel.create({
            name,
            email,
            password: hashedPassword,
            isAccountVerified: false, // always require email verification
            roles: [{ authority: "USER" }],
        });

        const token = createToken(newUser);
        logger.info(`User registered: ${email}`);

        return res.status(201).json({
            success: true,
            message: "Registration successful",
            user: { id: newUser._id, name: newUser.name, email: newUser.email },
            token,
        });
    } catch (err) {
        logger.error(`register: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- LOGIN ----------
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (!user.password) return res.status(400).json({ success: false, message: "User has no password set" });

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const token = createToken(user);
        logger.info(`Login successful: ${email}`);

        return res.status(200).json({
            success: true,
            message: "Login successful",
            user: { id: user._id, name: user.name, email: user.email },
            token,
        });
    } catch (err) {
        logger.error(`loginManual: ${err.stack}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};


// ---------- LOGOUT ----------
export const logout = async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });
        logger.info(`Logout successful`);
        return res.status(200).json({ success: true, message: "Logout successful" });
    } catch (err) {
        logger.error(`logout: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- SEND OTP (EMAIL VERIFY / RESET) ----------
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendOtpMail = async (user, otp, subject, htmlBody) => {
    const mail = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject,
        html: htmlBody,
    };
    await transporter.sendMail(mail);
};

// ---------- SEND VERIFICATION OTP ----------
export const sendOtpToEmail = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        if (user.isAccountVerified)
            return res.status(400).json({ success: false, message: "Account already verified" });

        const otp = generateOtp();
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000;
        await user.save();

        await sendOtpMail(
            user,
            otp,
            "Verify your account",
            `<p>Hello ${user.name}, your OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
        );
        logger.info(`OTP sent to ${user.email}`);

        return res.status(200).json({ success: true, message: "OTP sent" });
    } catch (err) {
        logger.error(`sendOtpToEmail: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- VERIFY EMAIL OTP ----------
export const verifyEmailOtp = async (req, res) => {
    try {
        const { otp, userId } = req.body;
        const user = await userModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (user.verifyOtp !== otp)
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        if (user.verifyOtpExpireAt < Date.now())
            return res.status(400).json({ success: false, message: "OTP expired" });

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;
        await user.save();

        logger.info(`Email verified: ${user.email}`);
        return res.status(200).json({ success: true, message: "Account verified" });
    } catch (err) {
        logger.error(`verifyEmailOtp: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- PASSWORD RESET ----------
export const sendResetPasswordOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({ email });
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });

        const otp = generateOtp();
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 10 * 60 * 1000;
        await user.save();

        await sendOtpMail(
            user,
            otp,
            "Reset your password",
            `<p>Hello ${user.name}, your reset OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
        );
        logger.info(`Password reset OTP sent: ${email}`);

        return res.status(200).json({ success: true, message: "Reset OTP sent" });
    } catch (err) {
        logger.error(`sendResetPasswordOtp: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { otp, email, newPassword } = req.body;
        const user = await userModel.findOne({ email });
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });

        if (user.resetOtp !== otp)
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        if (user.resetOtpExpireAt < Date.now())
            return res.status(400).json({ success: false, message: "OTP expired" });

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        await user.save();

        logger.info(`Password reset: ${email}`);
        return res.status(200).json({ success: true, message: "Password reset successful" });
    } catch (err) {
        logger.error(`resetPassword: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- AUTH CHECK ----------
export const isAuthenticated = async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token)
            return res.status(401).json({ success: false, message: "No token provided" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.userId).select("-password");
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });

        return res.status(200).json({
            success: true,
            message: "Authenticated",
            user: { id: user._id, name: user.name, email: user.email },
        });
    } catch (err) {
        const code = err.name === "TokenExpiredError" ? 401 : 500;
        logger.error(`isAuthenticated: ${err.message}`);
        return res.status(code).json({ success: false, message: "Unauthorized" });
    }
};

// ---------- MIDDLEWARE ----------
export const authMiddleware = async (req, res, next) => {
    try {
        const headerToken = req.headers.authorization?.split(" ")[1];
        const token = headerToken || req.cookies.token;
        if (!token) return res.status(401).json({ success: false, message: "No token" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.userId).select("-password");
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        req.user = user;
        next();
    } catch (err) {
        logger.error(`authMiddleware: ${err.message}`);
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
};

export const isVerified = (req, res, next) => {
    if (!req.user.isAccountVerified)
        return res.status(403).json({ success: false, message: "Account not verified" });
    next();
};

export const isAdmin = (req, res, next) => {
    const isAdmin = req.user.roles.some((r) => r.authority === "ADMIN");
    if (!isAdmin)
        return res.status(403).json({ success: false, message: "Admin access required" });
    next();
};
