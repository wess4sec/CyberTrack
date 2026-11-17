const mongoose = require("mongoose");

const assetSchema = new mongoose.Schema(
    {
        hostname: { type: String, required: true, trim: true },
        ipAddress: { type: String, required: true, trim: true },
        assetType: { type: String, required: true, trim: true },
        operatingSystem: { type: String, required: true, trim: true },
        environment: { type: String, required: true, trim: true },
        criticality: { type: String, required: true, trim: true },
        tags: { type: [String], required: true, default: [] },
        owner: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now },
        isActive: { type: Boolean, required: true, default: true }
    },
    {
        collection: "assets",
        strict: "throw",
        timestamps: false,
        versionKey: false
    }
);

module.exports =
    mongoose.models.Asset || mongoose.model("Asset", assetSchema);
