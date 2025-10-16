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
            isAccountVerified: false,
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
