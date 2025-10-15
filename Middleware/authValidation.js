import Joi from "joi";
import jwt from "jsonwebtoken";

/** ------------------ Helper for validation ------------------ **/
const validateSchema = (schema, req, res, next) => {
    const { error, value } = schema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true,
    });

    if (error) {
        const message = error.details.map(d => d.message).join(", ");
        return res.status(400).json({
            success: false,
            message: `Validation error: ${message}`,
        });
    }

    req.body = value;
    next();
};

/** ------------------ Register ------------------ **/
export const registerValidation = (req, res, next) => {
    const schema = Joi.object({
        name: Joi.string().trim().min(3).max(50).required(),
        email: Joi.string().trim().lowercase().email({ tlds: { allow: false } }).required(),
        password: Joi.string().min(3).max(50).required(),
        isGoogleUser: Joi.boolean().optional(),
    });
    validateSchema(schema, req, res, next);
};

/** ------------------ Login ------------------ **/
export const loginValidation = (req, res, next) => {
    const schema = Joi.object({
        email: Joi.string().trim().lowercase().email({ tlds: { allow: false } }).required(),
        password: Joi.string().min(3).max(50).required(),
    });
    validateSchema(schema, req, res, next);
};

/** ------------------ Verify OTP ------------------ **/
export const otpValidation = (req, res, next) => {
    const schema = Joi.object({
        userId: Joi.string().trim().required(),
        otp: Joi.string().length(6).pattern(/^\d{6}$/).required(),
    });
    validateSchema(schema, req, res, next);
};

/** ------------------ Reset Password ------------------ **/
export const resetPasswordValidation = (req, res, next) => {
    const schema = Joi.object({
        email: Joi.string().trim().lowercase().email({ tlds: { allow: false } }).required(),
    });
    validateSchema(schema, req, res, next);
};

/** ------------------ New Password ------------------ **/
export const newPasswordValidation = (req, res, next) => {
    const schema = Joi.object({
        otp: Joi.string().length(6).pattern(/^\d{6}$/).required(),
        email: Joi.string().trim().lowercase().email({ tlds: { allow: false } }).required(),
        newPassword: Joi.string().min(3).max(50).required(),
    });
    validateSchema(schema, req, res, next);
};

/** ------------------ User Auth Middleware ------------------ **/
export const userAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized: Missing token" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.body.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
    }
};
