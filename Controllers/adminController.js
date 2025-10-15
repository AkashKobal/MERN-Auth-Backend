import userModel from "../Models/userModel.js";
import logger from "../utils/logger.js";

// Get all users with optional search
export const getAllUsers = async (req, res) => {
    try {
        const { name, email } = req.query;
        const filter = {};

        if (name) filter.name = { $regex: name, $options: "i" };
        if (email) filter.email = { $regex: email, $options: "i" };

        const users = await userModel.find(filter).select("-password");

        logger.info(`Fetched ${users.length} users`);
        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            totalUsers: users.length,
            users,
        });
    } catch (error) {
        logger.error(`getAllUsers: ${error.message}`);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

// Get user by ID
export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await userModel.findById(userId).select("-password");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        return res.status(200).json({
            success: true,
            message: "User fetched successfully",
            user,
        });
    } catch (error) {
        logger.error(`getUserById: ${error.message}`);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

// Update user by ID
export const updateUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const updates = req.body;

        const user = await userModel
            .findByIdAndUpdate(userId, updates, { new: true })
            .select("-password");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        logger.info(`User updated: ${userId}`);
        return res.status(200).json({
            success: true,
            message: "User updated successfully",
            user,
        });
    } catch (error) {
        logger.error(`updateUser: ${error.message}`);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

// Delete user by ID
export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await userModel.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        logger.info(`User deleted: ${userId}`);
        return res.status(200).json({
            success: true,
            message: "User deleted successfully",
        });
    } catch (error) {
        logger.error(`deleteUser: ${error.message}`);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

// Search user by name or email
export const searchUsers = async (req, res) => {
    try {
        const { name, email } = req.query;
        if (!name && !email) {
            return res.status(400).json({
                success: false,
                message: "At least one search field (name/email) is required",
            });
        }

        const filter = {};
        if (name) filter.name = { $regex: name, $options: "i" };
        if (email) filter.email = { $regex: email, $options: "i" };

        const users = await userModel.find(filter).select("-password");

        logger.info(`Search found ${users.length} users`);
        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            totalUsers: users.length,
            users,
        });
    } catch (error) {
        logger.error(`searchUsers: ${error.message}`);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};
