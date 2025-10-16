import jwt from "jsonwebtoken";
import userModel from "../Models/userModel.js";

export const userAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

        if (!token)
            return res.status(401).json({ success: false, message: "Unauthorized: Missing token" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await userModel.findById(decoded.userId).select("-password");
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });

        req.user = user; // Attach user to request
        next();
    } catch (err) {
        console.error("Auth error:", err.message);
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
    }
};



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
