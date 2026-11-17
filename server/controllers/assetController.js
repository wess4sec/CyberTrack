const mongoose = require("mongoose");
const Asset = require("../models/Asset");
const Vulnerability = require("../models/Vulnerability");
const Scan = require("../models/Scan");
const RemediationTask = require("../models/RemediationTask");
const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const createResourceController = require("../utils/resourceController");
const {
    escapeRegex,
    getQueryString,
    parseObjectId,
    safeSerialize
} = require("../utils/requestValidation");
const { assertNoReferences } = require("../utils/references");

function buildFilter(query) {
    const filter = {};
    const search = getQueryString(query, "q", { maxLength: 120 });
    const environment = getQueryString(query, "environment", { maxLength: 80 });
    const criticality = getQueryString(query, "criticality", { maxLength: 40 });
    const isActive = getQueryString(query, "isActive", { maxLength: 5 });

    if (search) {
        const expression = new RegExp(escapeRegex(search), "i");
        filter.$or = [
            { hostname: expression },
            { ipAddress: expression },
            { owner: expression }
        ];
    }
    if (environment) filter.environment = environment;
    if (criticality) filter.criticality = criticality;
    if (isActive !== undefined) {
        if (isActive !== "true" && isActive !== "false") {
            throw new AppError(400, 'Query parameter "isActive" must be true or false.');
        }
        filter.isActive = isActive === "true";
    }

    return filter;
}

const controller = createResourceController({
    Model: Asset,
    writableFields: [
        "hostname",
        "ipAddress",
        "assetType",
        "operatingSystem",
        "environment",
        "criticality",
        "tags",
        "owner",
        "createdAt",
        "isActive"
    ],
    queryFields: ["q", "environment", "criticality", "isActive"],
    sortFields: ["hostname", "createdAt", "criticality", "_id"],
    defaultSort: "createdAt",
    buildFilter,
    beforeDelete: id =>
        assertNoReferences([
            {
                model: Scan,
                filter: { assetId: id },
                label: "scans"
            },
            {
                model: RemediationTask,
                filter: { assetId: id },
                label: "remediation tasks"
            }
        ])
});

controller.related = asyncHandler(async (request, response) => {
    const id = parseObjectId(request.params.id);
    const objectId = new mongoose.Types.ObjectId(id);
    const asset = await Asset.findById(id).select("_id").exec();
    if (!asset) {
        throw new AppError(404, "Resource not found.");
    }

    const [scans, tasks, scanVulnerabilities, taskVulnerabilityIds] =
        await Promise.all([
            Scan.find({ assetId: id })
                .select("scannedBy scanType status startedAt completedAt")
                .populate("scannedBy", "fullName email role")
                .sort({ startedAt: -1 })
                .limit(100)
                .exec(),
            RemediationTask.find({ assetId: id })
                .populate([
                    { path: "vulnerabilityId", select: "cveId title severity cvss" },
                    { path: "assignedTo", select: "fullName email role" }
                ])
                .sort({ createdAt: -1 })
                .limit(100)
                .exec(),
            Scan.aggregate([
                { $match: { assetId: objectId } },
                { $unwind: "$results" },
                {
                    $group: {
                        _id: "$results.vulnerabilityId",
                        findingCount: { $sum: 1 }
                    }
                },
                { $sort: { findingCount: -1, _id: 1 } },
                { $limit: 100 }
            ]),
            RemediationTask.distinct("vulnerabilityId", { assetId: id })
        ]);

    const findingCounts = new Map(
        scanVulnerabilities.map(item => [String(item._id), item.findingCount])
    );
    const vulnerabilityIds = [
        ...new Set([
            ...scanVulnerabilities.map(item => String(item._id)),
            ...taskVulnerabilityIds.map(String)
        ])
    ];
    const vulnerabilities = await Vulnerability.find({
        _id: { $in: vulnerabilityIds }
    })
        .select("cveId title severity cvss status")
        .sort({ cvss: -1, _id: 1 })
        .limit(100)
        .exec();
    const taskCounts = new Map();
    tasks.forEach(task => {
        const key = String(task.vulnerabilityId?._id || task.vulnerabilityId);
        taskCounts.set(key, (taskCounts.get(key) || 0) + 1);
    });

    response.status(200).json({
        success: true,
        data: {
            scans: safeSerialize(scans),
            remediationTasks: safeSerialize(tasks),
            vulnerabilities: safeSerialize(
                vulnerabilities.map(vulnerability => ({
                    ...vulnerability.toObject(),
                    findingCount: findingCounts.get(String(vulnerability._id)) || 0,
                    remediationTaskCount:
                        taskCounts.get(String(vulnerability._id)) || 0
                }))
            )
        }
    });
});

module.exports = controller;
