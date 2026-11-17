const path = require("node:path");
const dotenv = require("dotenv");
const mongoose = require("mongoose");

dotenv.config({
    path: path.resolve(__dirname, "..", ".env"),
    quiet: true
});

const DATABASE_NAME = "cybertrack_db";

async function connectDatabase() {
    if (!process.env.MONGODB_URI) {
        throw new Error("MONGODB_URI is not configured in server/.env.");
    }

    await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 10000
    });

    const database = mongoose.connection.db;

    if (!database || database.databaseName !== DATABASE_NAME) {
        await mongoose.disconnect();
        throw new Error(
            `Refusing to operate on an unexpected database; expected ${DATABASE_NAME}.`
        );
    }

    return database;
}

async function disconnectDatabase() {
    if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect();
    }
}

module.exports = {
    connectDatabase,
    disconnectDatabase
};
