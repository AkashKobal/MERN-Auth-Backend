import Joi from "joi";

// Update user validation
export const updateUserValidation = (req, res, next) => {
    const schema = Joi.object({
        name: Joi.string().min(3).max(50).optional(),
        email: Joi.string().email({ tlds: { allow: false } }).optional(),
        isAccountVerified: Joi.boolean().optional(),
        isGoogleUser: Joi.boolean().optional(),
        roles: Joi.array()
            .items(Joi.object({ authority: Joi.string().valid("USER", "ADMIN") }))
            .optional(),
    });

    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
        const errorMessage = error.details.map(d => d.message).join(", ");
        return res.status(400).json({
            success: false,
            message: `Validation error: ${errorMessage}`,
        });
    }

    next();
};
