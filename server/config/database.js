const path = require("node:path");
const dotenv = require("dotenv");
const mongoose = require("mongoose");

dotenv.config({
    path: path.resolve(__dirname, "..", ".env"),
    quiet: true
});

async function connectDatabase({
    uri = process.env.MONGODB_URI,
    expectedDatabase = process.env.MONGODB_DATABASE || "cybertrack_db"
} = {}) {
    if (!uri) {
        throw new Error("MONGODB_URI is not configured in server/.env.");
    }

    await mongoose.connect(uri, {
        autoIndex: false,
        serverSelectionTimeoutMS: 10000
    });

    const database = mongoose.connection.db;

    if (!database || database.databaseName !== expectedDatabase) {
        await mongoose.disconnect();
        throw new Error(
            `Connected to an unexpected database; expected ${expectedDatabase}.`
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