const mongoose = require("mongoose");

const USER_ROLES = ["ADMIN", "SECURITY_ANALYST", "VIEWER", "ANALYST"];

const userSchema = new mongoose.Schema(
    {
        fullName: { type: String, required: true, trim: true },
        email: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        },
        passwordHash: { type: String, required: true, select: false },
        role: { type: String, required: true, enum: USER_ROLES },
        department: { type: String, required: true, trim: true },
        isActive: { type: Boolean, required: true, default: true },
        createdAt: { type: Date, required: true, default: Date.now }
    },
    {
        collection: "users",
        strict: "throw",
        timestamps: false,
        versionKey: false,
        toJSON: {
            transform(_document, value) {
                delete value.passwordHash;
                delete value.__v;
                return value;
            }
        }
    }
);

userSchema.statics.USER_ROLES = USER_ROLES;

module.exports =
    mongoose.models.User || mongoose.model("User", userSchema);
