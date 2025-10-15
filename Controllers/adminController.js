import e from "express";
import userModel from "../Models/userModel.js";

// Get all users with optional search
export const getAllUsers = async (req, res) => {
    try {
        const { name, email } = req.query;

        const filter = {};
        if (name) filter.name = { $regex: name, $options: "i" };
        if (email) filter.email = { $regex: email, $options: "i" };

        const users = await userModel.find(filter).select("-password");

        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            totalUsers: users.length,
            users,
        });
    } catch (error) {
        console.error("Get all users error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error fetching users",
        });
    }
};

// Get user by ID
export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await userModel.findById(userId).select("-password");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        return res.status(200).json({
            success: true,
            message: "User fetched successfully",
            user,
        });
    } catch (error) {
        console.error("Get user by ID error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error fetching user",
        });
    }
};

// Update user by ID
export const updateUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const updates = req.body;

        const user = await userModel.findByIdAndUpdate(userId, updates, { new: true }).select("-password");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        return res.status(200).json({
            success: true,
            message: "User updated successfully",
            user,
        });
    } catch (error) {
        console.error("Update user error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error updating user",
        });
    }
};

// Delete user by ID
export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await userModel.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        return res.status(200).json({
            success: true,
            message: "User deleted successfully",
        });
    } catch (error) {
        console.error("Delete user error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error deleting user",
        });
    }
};


// search user by name or email
export const searchUsers = async (req, res) => {
    try {
        const { name, email } = req.query;

        if (!name && !email) {
            return res.status(400).json({
                success: false,
                message: "Both name and email cannot be empty",
            });
        }
        const filter = {};
        if (name) filter.name = { $regex: name, $options: "i" };
        if (email) filter.email = { $regex: email, $options: "i" };
        const users = await userModel.find(filter).select("-password");
        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            totalUsers: users.length,
            users,
        });
    } catch (error) {
        console.error("Search users error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error searching users",
        });
    }
};