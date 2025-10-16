import bcrypt from "bcrypt";
import userModel from "../Models/userModel.js";
import { createToken } from "../utils/tokenUtils.js";

export const googleRegister = async (req, res) => {
    try {
        const { email, name, password, isGoogleUser } = req.body;
        if (!email || typeof email !== "string")
            return res.status(400).json({ success: false, message: "Email is required" });

        const existingUser = await userModel.findOne({ email });
        if (existingUser)
            return res.status(409).json({ success: false, message: "User already exists" });

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new userModel({
            email,
            name,
            password: hashedPassword,
            isGoogleUser,
            roles: [{ authority: "USER" }],
        });

        await newUser.save();

        const token = createToken(newUser);

        return res.status(201).json({
            success: true,
            message: "Registration successful",
            user: newUser,
            token,
        });
    } catch (err) {
        console.error("googleRegister error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};



export const googleLogin = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email is required" });

        const user = await userModel.findOne({ email, isGoogleUser: true });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const token = createToken(user);
        return res.status(200).json({ success: true, user, token });
    } catch (err) {
        console.error("googleLogin error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};