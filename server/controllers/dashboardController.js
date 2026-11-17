const Vulnerability = require("../models/Vulnerability");
const Asset = require("../models/Asset");
const Scan = require("../models/Scan");
const RemediationTask = require("../models/RemediationTask");
const asyncHandler = require("../utils/asyncHandler");
const { safeSerialize } = require("../utils/requestValidation");

const overview = asyncHandler(async (_request, response) => {
    const [
        totalVulnerabilities,
        severityCounts,
        activeAssets,
        totalScans,
        scanStatusCounts,
        openTasks,
        overdueTasks,
        completedTasks
    ] = await Promise.all([
        Vulnerability.countDocuments(),
        Vulnerability.aggregate([
            { $group: { _id: "$severity", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]),
        Asset.countDocuments({ isActive: true }),
        Scan.countDocuments(),
        Scan.aggregate([
            { $group: { _id: "$status", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]),
        RemediationTask.countDocuments({ status: "OPEN" }),
        RemediationTask.countDocuments({
            dueDate: { $lt: new Date() },
            completedAt: null
        }),
        RemediationTask.countDocuments({ completedAt: { $ne: null } })
    ]);

    response.status(200).json({
        success: true,
        data: {
            totalVulnerabilities,
            severityCounts: severityCounts.map(item => ({
                severity: item._id,
                count: item.count
            })),
            activeAssets,
            totalScans,
            scanStatusCounts: scanStatusCounts.map(item => ({
                status: item._id,
                count: item.count
            })),
            openRemediationTasks: openTasks,
            overdueRemediationTasks: overdueTasks,
            completedRemediationTasks: completedTasks
        }
    });
});

const severity = asyncHandler(async (_request, response) => {
    const data = await Vulnerability.aggregate([
        {
            $group: {
                _id: "$severity",
                count: { $sum: 1 },
                averageCvss: { $avg: "$cvss" }
            }
        },
        {
            $project: {
                _id: 0,
                severity: "$_id",
                count: 1,
                averageCvss: { $round: ["$averageCvss", 2] }
            }
        },
        { $sort: { count: -1 } }
    ]);

    response.status(200).json({ success: true, data });
});

const vulnerabilityStatus = asyncHandler(async (_request, response) => {
    const data = await Vulnerability.aggregate([
        {
            $group: {
                _id: "$status",
                count: { $sum: 1 }
            }
        },
        {
            $project: {
                _id: 0,
                status: "$_id",
                count: 1
            }
        },
        { $sort: { count: -1, status: 1 } }
    ]);

    response.status(200).json({ success: true, data });
});

const monthlyTrends = asyncHandler(async (_request, response) => {
    const data = await Vulnerability.aggregate([
        {
            $group: {
                _id: {
                    year: { $year: "$publishedAt" },
                    month: { $month: "$publishedAt" }
                },
                count: { $sum: 1 },
                averageCvss: { $avg: "$cvss" }
            }
        },
        {
            $project: {
                _id: 0,
                year: "$_id.year",
                month: "$_id.month",
                count: 1,
                averageCvss: { $round: ["$averageCvss", 2] }
            }
        },
        { $sort: { year: 1, month: 1 } }
    ]);

    response.status(200).json({ success: true, data });
});

const topVulnerabilities = asyncHandler(async (_request, response) => {
    const data = await Vulnerability.aggregate([
        { $sort: { cvss: -1, publishedAt: -1, _id: 1 } },
        { $limit: 10 },
        {
            $project: {
                _id: 1,
                cveId: 1,
                title: 1,
                severity: 1,
                cvss: 1,
                publishedAt: 1,
                status: 1
            }
        }
    ]);

    response.status(200).json({
        success: true,
        data: safeSerialize(data)
    });
});

const scans = asyncHandler(async (_request, response) => {
    const data = await Scan.aggregate([
        {
            $group: {
                _id: "$status",
                scanCount: { $sum: 1 },
                findingCount: {
                    $sum: { $size: { $ifNull: ["$results", []] } }
                },
                completedCount: {
                    $sum: {
                        $cond: [
                            { $ne: [{ $ifNull: ["$completedAt", null] }, null] },
                            1,
                            0
                        ]
                    }
                }
            }
        },
        {
            $project: {
                _id: 0,
                status: "$_id",
                scanCount: 1,
                findingCount: 1,
                completedCount: 1
            }
        },
        { $sort: { scanCount: -1, status: 1 } }
    ]);

    response.status(200).json({ success: true, data });
});

const topAssets = asyncHandler(async (_request, response) => {
    const data = await Scan.aggregate([
        { $unwind: "$results" },
        {
            $group: {
                _id: "$assetId",
                findingCount: { $sum: 1 },
                criticalFindingCount: {
                    $sum: {
                        $cond: [
                            { $eq: ["$results.severitySnapshot", "CRITICAL"] },
                            1,
                            0
                        ]
                    }
                }
            }
        },
        { $sort: { findingCount: -1, criticalFindingCount: -1, _id: 1 } },
        { $limit: 10 },
        {
            $lookup: {
                from: "assets",
                localField: "_id",
                foreignField: "_id",
                as: "asset"
            }
        },
        { $unwind: "$asset" },
        {
            $project: {
                _id: 0,
                assetId: "$asset._id",
                hostname: "$asset.hostname",
                ipAddress: "$asset.ipAddress",
                criticality: "$asset.criticality",
                findingCount: 1,
                criticalFindingCount: 1
            }
        }
    ]);

    response.status(200).json({ success: true, data: safeSerialize(data) });
});

const frequentCves = asyncHandler(async (_request, response) => {
    const data = await Scan.aggregate([
        { $unwind: "$results" },
        {
            $group: {
                _id: {
                    vulnerabilityId: "$results.vulnerabilityId",
                    scanId: "$_id"
                },
                occurrencesInScan: { $sum: 1 }
            }
        },
        {
            $group: {
                _id: "$_id.vulnerabilityId",
                scanCount: { $sum: 1 },
                occurrenceCount: { $sum: "$occurrencesInScan" }
            }
        },
        { $sort: { occurrenceCount: -1, scanCount: -1, _id: 1 } },
        { $limit: 10 },
        {
            $lookup: {
                from: "vulnerabilities",
                localField: "_id",
                foreignField: "_id",
                as: "vulnerability"
            }
        },
        { $unwind: "$vulnerability" },
        {
            $project: {
                _id: 0,
                vulnerabilityId: "$vulnerability._id",
                cveId: "$vulnerability.cveId",
                title: "$vulnerability.title",
                severity: "$vulnerability.severity",
                cvss: "$vulnerability.cvss",
                scanCount: 1,
                occurrenceCount: 1
            }
        }
    ]);

    response.status(200).json({ success: true, data: safeSerialize(data) });
});

module.exports = {
    frequentCves,
    overview,
    severity,
    vulnerabilityStatus,
    monthlyTrends,
    topAssets,
    topVulnerabilities,
    scans
};
