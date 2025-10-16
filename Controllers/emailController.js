import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../Models/userModel.js";
import transporter from "../config/nodeMailer.js";
import logger from "../utils/logger.js";

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
        const { email } = req.body;
        const user = await userModel.findOne({ email });
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
        logger.info(`OTP for ${user.email}: ${otp}`);
        return res.status(200).json({ success: true, message: "OTP sent" });
    } catch (err) {
        logger.error(`sendOtpToEmail: ${err.message}`);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// ---------- VERIFY EMAIL OTP ----------
export const verifyEmailOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp)
            return res.status(400).json({ success: false, message: "Email and OTP required" });

        // explicitly select OTP fields
        const user = await userModel
            .findOne({ email })
            .select("+verifyOtp +verifyOtpExpireAt");
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        console.log(`DB OTP: "${user.verifyOtp}", Request OTP: "${otp}"`);

        if (!user.verifyOtp || user.verifyOtp.trim() !== otp.toString().trim())
            return res.status(400).json({ success: false, message: "Invalid OTP" });

        if (user.verifyOtpExpireAt < Date.now())
            return res.status(400).json({ success: false, message: "OTP expired" });

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;
        await user.save();

        return res.status(200).json({ success: true, message: "Account verified" });
    } catch (err) {
        console.error(`verifyEmailOtp: ${err.message}`);
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

        // explicitly select reset OTP fields
        const user = await userModel
            .findOne({ email })
            .select("+resetOtp +resetOtpExpireAt");
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });

        if (!user.resetOtp || user.resetOtp.trim() !== otp.toString().trim())
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
