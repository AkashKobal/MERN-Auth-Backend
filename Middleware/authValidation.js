import Joi from 'joi';
import jwt from "jsonwebtoken";

// Register validation
export const registerValidation = (req, res, next) => {
    const schema = Joi.object({
        name: Joi.string()
            .min(3)
            .max(50)
            .required()
            .messages({
                'string.min': 'Name must be at least 3 characters',
                'string.max': 'Name cannot exceed 50 characters',
                'any.required': 'Name is required'
            }),
        email: Joi.string()
            .email({ tlds: { allow: false } })
            .required()
            .messages({
                'string.email': 'Please provide a valid email address',
                'any.required': 'Email is required'
            }),
        password: Joi.string()
            .min(3)
            .max(50)
            .required()
            .messages({
                'string.min': 'Password must be at least 3 characters',
                'string.max': 'Password cannot exceed 50 characters',
                'any.required': 'Password is required'
            }),
        isGoogleUser: Joi.boolean().optional()
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');

        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`
        });
    }

    next();
};

// Login validation
export const loginValidation = (req, res, next) => {
    const schema = Joi.object({
        email: Joi.string()
            .email({ tlds: { allow: false } })
            .required()
            .messages({
                'string.email': 'Please provide a valid email address',
                'any.required': 'Email is required'
            }),
        password: Joi.string()
            .min(3)
            .max(50)
            .required()
            .messages({
                'string.min': 'Password must be at least 3 characters',
                'string.max': 'Password cannot exceed 50 characters',
                'any.required': 'Password is required'
            }),
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');

        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`
        });
    }

    next();
};

// OTP validation
export const otpValidation = (req, res, next) => {
    const schema = Joi.object({
        userId: Joi.string()
            .required()
            .messages({
                'any.required': 'User ID is required'
            }),
        otp: Joi.string()
            .length(6)
            .required()
            .messages({
                'string.length': 'OTP must be exactly 6 digits',
                'any.required': 'OTP is required'
            })
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');

        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`
        });
    }

    next();
};

// Reset password validation
export const resetPasswordValidation = (req, res, next) => {
    const schema = Joi.object({
        email: Joi.string()
            .email({ tlds: { allow: false } })
            .required()
            .messages({
                'string.email': 'Please provide a valid email address',
                'any.required': 'Email is required'
            })
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');

        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`
        });
    }

    next();
};

// New password validation
export const newPasswordValidation = (req, res, next) => {
    const schema = Joi.object({
        otp: Joi.string()
            .length(6)
            .required()
            .messages({
                'string.length': 'OTP must be exactly 6 digits',
                'any.required': 'OTP is required'
            }),
        email: Joi.string()
            .email({ tlds: { allow: false } })
            .required()
            .messages({
                'string.email': 'Please provide a valid email address',
                'any.required': 'Email is required'
            }),
        newPassword: Joi.string()
            .min(3)
            .max(50)
            .required()
            .messages({
                'string.min': 'Password must be at least 3 characters',
                'string.max': 'Password cannot exceed 50 characters',
                'any.required': 'New password is required'
            })
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');

        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`
        });
    }

    next();
};

// userAuth
export const userAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    console.log('Token:', token); // should show the actual token
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });

    try {
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded Token:', decodedToken);

        req.body.userId = decodedToken.userId;
        next();
    } catch (err) {
        console.error('JWT Error:', err.message);
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
};