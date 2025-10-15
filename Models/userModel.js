import mongoose from "mongoose";
const availableRoles = ["DEVELOPER", "TESTER", "ADMIN", "USER", "MANAGER", "SUPPORT", "INTERN"];

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    phoneNumber: { type: String, default: "" },
    roles: [{
        authority: {
            type: String,
            enum: availableRoles,  // updated enum
            default: "USER"
        }
    }],
    isAdmin: { type: Boolean, default: false },
    active: { type: Boolean, default: true },
    blocked: { type: Boolean, default: false },
    isAccountVerified: { type: Boolean, default: false },
    isGoogleUser: { type: Boolean, default: false },
    authProvider: {
        type: String,
        enum: ["LOCAL", "GOOGLE", "FACEBOOK", "GITHUB"],
        default: "LOCAL",
    },
    verifyOtp: { type: String, default: "", select: false },
    verifyOtpExpireAt: { type: Number, default: 0, select: false },
    resetOtp: { type: String, default: "", select: false },
    resetOtpExpireAt: { type: Number, default: 0, select: false },
    isResetOtpVerified: { type: Boolean, default: false },
}, { timestamps: true });

// Index email for faster search/login
userSchema.index({ email: 1 });

const userModel = mongoose.models.User || mongoose.model("User", userSchema);
export default userModel;
