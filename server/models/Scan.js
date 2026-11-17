const mongoose = require("mongoose");

const scanResultSchema = new mongoose.Schema(
    {
        vulnerabilityId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Vulnerability",
            required: true
        },
        port: { type: Number, required: true, min: 0, max: 65535 },
        protocol: { type: String, required: true, trim: true },
        status: { type: String, required: true, trim: true },
        severitySnapshot: {
            type: String,
            required: true,
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        evidence: { type: String, required: true },
        detectedAt: { type: Date, required: true }
    },
    { _id: false, id: false, strict: "throw" }
);

const scanSchema = new mongoose.Schema(
    {
        assetId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Asset",
            required: true
        },
        scannedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        scanType: { type: String, required: true, trim: true },
        status: { type: String, required: true, trim: true },
        startedAt: { type: Date, required: true },
        completedAt: { type: Date, default: null },
        results: { type: [scanResultSchema], required: true, default: [] }
    },
    {
        collection: "scans",
        strict: "throw",
        timestamps: false,
        versionKey: false
    }
);

module.exports =
    mongoose.models.Scan || mongoose.model("Scan", scanSchema);
