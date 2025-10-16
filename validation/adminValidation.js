import Joi from "joi";

/**
 * Validate request body for user update.
 * Only allows controlled, sanitized fields.
 */
export const updateUserValidation = (req, res, next) => {
    const schema = Joi.object({
        name: Joi.string().trim().min(3).max(50).optional(),
        email: Joi.string()
            .trim()
            .lowercase()
            .email({ tlds: { allow: false } })
            .optional(),
        isAccountVerified: Joi.boolean().optional(),
        isGoogleUser: Joi.boolean().optional(),
        roles: Joi.array()
            .items(
                Joi.object({
                    authority: Joi.string().valid("USER", "ADMIN").required(),
                })
            )
            .optional(),
    }).min(1); // ensure at least one field is provided

    const { error } = schema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true, // remove any unknown fields
    });

    if (error) {
        const message = error.details.map(d => d.message).join(", ");
        return res.status(400).json({
            success: false,
            message: `Validation error: ${message}`,
        });
    }

    // sanitized input
    req.body = schema.validate(req.body, { stripUnknown: true }).value;
    next();
};
