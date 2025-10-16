import jwt from "jsonwebtoken";

/**
 * Generate a JWT token for a user.
 * @param {Object} user - Mongoose user document
 * @returns {string} JWT token
 */
export const createToken = (user) => {
    return jwt.sign(
        {
            userId: user._id,
            roles: user.roles,
        },
        process.env.JWT_SECRET,
        { expiresIn: "7d" } // token valid for 7 days
    );
};

/**
 * Verify a JWT token
 * @param {string} token
 * @returns {Object} decoded payload
 */
export const verifyToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        throw new Error("Invalid token");
    }
};
