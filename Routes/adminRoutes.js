import express from "express";
import { authMiddleware, isAdmin } from "../Controllers/authControllers.js";
import {
    getAllUsers,
    getUserById,
    updateUser,
    deleteUser,
    searchUsers
} from "../Controllers/adminController.js";

const adminRouter = express.Router();

// Search user by name or email can be done via query params on getAllUsers route

adminRouter.get("/users/search", searchUsers);

// All routes protected: only ADMIN
adminRouter.use(authMiddleware, isAdmin);

// Get all users with optional filters
adminRouter.get("/users", getAllUsers);

// Get single user by ID
adminRouter.get("/users/:userId", getUserById);


// Update user
adminRouter.put("/users/:userId", updateUser);

// Delete user
adminRouter.delete("/users/:userId", deleteUser);

export default adminRouter;
