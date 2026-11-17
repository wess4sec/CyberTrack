require("dotenv").config({
    path: require("node:path").resolve(__dirname, "..", ".env"),
    quiet: true
});

const bcrypt = require("bcryptjs");
const User = require("../models/User");
const {
    connectDatabase,
    disconnectDatabase
} = require("../config/database");

const BCRYPT_ROUNDS = 12;

async function run() {
    const email = process.env.BOOTSTRAP_ADMIN_EMAIL;
    const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw new Error("Set a valid BOOTSTRAP_ADMIN_EMAIL for this one-time command.");
    }
    if (
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 128 ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        throw new Error(
            "Set BOOTSTRAP_ADMIN_PASSWORD to 12-128 characters and at most 72 UTF-8 bytes."
        );
    }

    await connectDatabase();

    try {
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const user = await User.findOne({ email: email.trim().toLowerCase() })
            .select("+passwordHash")
            .exec();

        if (user) {
            user.passwordHash = passwordHash;
            user.role = "ADMIN";
            user.isActive = true;
            await user.save();
            console.log("Existing user promoted to administrator.");
        } else {
            await User.create({
                fullName:
                    process.env.BOOTSTRAP_ADMIN_NAME ||
                    "CyberTrack Administrator",
                email,
                passwordHash,
                role: "ADMIN",
                department:
                    process.env.BOOTSTRAP_ADMIN_DEPARTMENT || "Security",
                isActive: true
            });
            console.log("Administrator account created.");
        }
    } finally {
        await disconnectDatabase();
    }
}

run().catch(async error => {
    console.error("Administrator bootstrap failed:", error.name || "Error");
    await disconnectDatabase();
    process.exitCode = 1;
});
