import userModel from "../Models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.status(200).json({
            success: true,
            message: "User fetched successfully",
            userData: {  /* created object to store user data and display*/
                userId: user._id,
                name: user.name,
                email: user.email,
                roles: user.roles,
                isAccountVerified: user.isAccountVerified,
            }
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ success: false, message: error.message });
    }
};