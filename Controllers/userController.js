import userModel from "../Models/userModel.js";

/**
 * Fetch authenticated user's data.
 * Only accessible by logged-in users via middleware.
 */

export const getUserData = async (req, res) => {
    try {
        const user = req.user;
        return res.status(200).json({
            success: true,
            message: "User fetched successfully.",
            userData: {
                id: user._id,
                name: user.name,
                email: user.email,
                roles: user.roles,
                isAccountVerified: user.isAccountVerified,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
            },
        });
    } catch (error) {
        console.error("Get user data error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error while fetching user data.",
        });
    }
};
