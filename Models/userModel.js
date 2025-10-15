import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phoneNumber: { type: String, default: "" }, // N/A if not provided
    roles: [{ authority: { type: String, default: "USER" } }],
    isAdmin: { type: Boolean, default: false }, // easier boolean instead of string
    active: { type: Boolean, default: true }, // Active status
    blocked: { type: Boolean, default: false }, // Blocked status
    isAccountVerified: { type: Boolean, default: false }, // Verification status
    isGoogleUser: { type: Boolean, default: false }, // Auth provider
    authProvider: {
        type: String,
        enum: ["LOCAL", "GOOGLE", "FACEBOOK", "GITHUB"],
        default: "LOCAL",
    },
    // OTP fields
    verifyOtp: { type: String, default: "" },
    verifyOtpExpireAt: { type: Number, default: 0 },
    resetOtp: { type: String, default: "" },
    resetOtpExpireAt: { type: Number, default: 0 },
    isResetOtpVerified: { type: Boolean, default: false },
}, { timestamps: true });

// Index email for faster search/login
userSchema.index({ email: 1 });

const userModel = mongoose.models.User || mongoose.model("User", userSchema);
export default userModel;
