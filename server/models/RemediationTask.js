const mongoose = require("mongoose");

const historyEntrySchema = new mongoose.Schema(
    {
        action: { type: String, required: true, trim: true },
        changedAt: { type: Date, required: true },
        note: { type: String, required: true }
    },
    { _id: false, id: false, strict: "throw" }
);

const remediationTaskSchema = new mongoose.Schema(
    {
        vulnerabilityId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Vulnerability",
            required: true
        },
        assetId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Asset",
            required: true
        },
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        title: { type: String, required: true, trim: true },
        description: { type: String, required: true, trim: true },
        priority: { type: String, required: true, trim: true },
        status: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now },
        dueDate: { type: Date, required: true },
        completedAt: { type: Date, default: null },
        history: { type: [historyEntrySchema], required: true, default: [] }
    },
    {
        collection: "remediation_tasks",
        strict: "throw",
        timestamps: false,
        versionKey: false
    }
);

module.exports =
    mongoose.models.RemediationTask ||
    mongoose.model("RemediationTask", remediationTaskSchema);
