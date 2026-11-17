const RemediationTask = require("../models/RemediationTask");
const Vulnerability = require("../models/Vulnerability");
const Asset = require("../models/Asset");
const User = require("../models/User");
const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const createResourceController = require("../utils/resourceController");
const {
    escapeRegex,
    getQueryString,
    parseObjectId,
    pickBodyFields,
    safeSerialize
} = require("../utils/requestValidation");
const { assertReferencesExist } = require("../utils/references");

const createFields = [
    "vulnerabilityId",
    "assetId",
    "assignedTo",
    "title",
    "description",
    "priority",
    "status",
    "dueDate"
];
const updateFields = [
    "vulnerabilityId",
    "assetId",
    "assignedTo",
    "title",
    "description",
    "priority",
    "status",
    "dueDate"
];
const references = [
    { field: "vulnerabilityId", model: Vulnerability },
    { field: "assetId", model: Asset },
    { field: "assignedTo", model: User },
    { field: "createdBy", model: User }
];

const populate = [
    {
        path: "vulnerabilityId",
        select: "cveId title severity cvss status"
    },
    {
        path: "assetId",
        select: "hostname ipAddress assetType environment criticality"
    },
    {
        path: "assignedTo",
        select: "fullName email role department isActive"
    },
    {
        path: "createdBy",
        select: "fullName email role department isActive"
    }
];

function buildFilter(query) {
    const filter = {};
    const status = getQueryString(query, "status", { maxLength: 40 });
    const priority = getQueryString(query, "priority", { maxLength: 40 });
    const search = getQueryString(query, "q", { maxLength: 120 });

    if (status) filter.status = status;
    if (priority) filter.priority = priority;
    if (search) {
        const expression = new RegExp(escapeRegex(search), "i");
        filter.$or = [{ title: expression }, { description: expression }];
    }
    if (query.assignedTo !== undefined) {
        filter.assignedTo = parseObjectId(query.assignedTo, "assignedTo");
    }
    if (query.vulnerabilityId !== undefined) {
        filter.vulnerabilityId = parseObjectId(
            query.vulnerabilityId,
            "vulnerabilityId"
        );
    }

    return filter;
}

const controller = createResourceController({
    Model: RemediationTask,
    writableFields: updateFields,
    queryFields: ["q", "status", "priority", "assignedTo", "vulnerabilityId"],
    sortFields: ["createdAt", "dueDate", "priority", "status", "_id"],
    defaultSort: "createdAt",
    populate,
    buildFilter,
    references
});

controller.create = asyncHandler(async (request, response) => {
    const input = pickBodyFields(request.body, createFields);
    const fields = input;
    const createdBy = request.currentUser._id;
    await assertReferencesExist({ ...fields, createdBy }, references);

    const now = new Date();
    const document = await RemediationTask.create({
        ...fields,
        createdBy,
        completedAt: fields.status === "COMPLETED" ? now : null,
        history: [
            {
                action: "CREATED",
                changedAt: now,
                note: "Task created."
            }
        ]
    });

    response.status(201).json({
        success: true,
        data: safeSerialize(await document.populate(populate))
    });
});

controller.update = asyncHandler(async (request, response) => {
    const id = parseObjectId(request.params.id);
    const fields = pickBodyFields(request.body, updateFields);
    await assertReferencesExist(fields, references);

    const document = await RemediationTask.findById(id).exec();
    if (!document) {
        throw new AppError(404, "Resource not found.");
    }

    const previousStatus = document.status;
    document.set(fields);
    const changedFields = Object.keys(fields).filter(field =>
        document.isModified(field)
    );

    if (changedFields.length > 0) {
        const now = new Date();
        const statusChanged = changedFields.includes("status");

        if (statusChanged) {
            const completed = document.status === "COMPLETED";
            document.completedAt = completed ? now : null;
            document.history.push({
                action: "STATUS_CHANGED",
                changedAt: now,
                note: `Status changed from ${previousStatus} to ${document.status}.`
            });
        } else {
            document.history.push({
                action: "UPDATED",
                changedAt: now,
                note: `Updated fields: ${changedFields.join(", ")}.`
            });
        }

        await document.save();
    }

    response.status(200).json({
        success: true,
        data: safeSerialize(
            await RemediationTask.findById(id).populate(populate).exec()
        )
    });
});

module.exports = controller;
