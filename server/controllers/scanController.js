const Scan = require("../models/Scan");
const Asset = require("../models/Asset");
const User = require("../models/User");
const Vulnerability = require("../models/Vulnerability");
const AppError = require("../utils/AppError");
const createResourceController = require("../utils/resourceController");
const {
    escapeRegex,
    getQueryString,
    parseObjectId
} = require("../utils/requestValidation");

const populate = [
    {
        path: "assetId",
        select: "hostname ipAddress assetType operatingSystem environment criticality isActive"
    },
    {
        path: "scannedBy",
        select: "fullName email role department isActive createdAt"
    },
    {
        path: "results.vulnerabilityId",
        select: "cveId title severity cvss status"
    }
];

function buildFilter(query) {
    const filter = {};
    const status = getQueryString(query, "status", { maxLength: 40 });
    const search = getQueryString(query, "q", { maxLength: 120 });

    if (status) filter.status = status;
    if (search) {
        const expression = new RegExp(escapeRegex(search), "i");
        filter.$or = [{ scanType: expression }, { status: expression }];
    }
    if (query.assetId !== undefined) {
        filter.assetId = parseObjectId(query.assetId, "assetId");
    }
    if (query.scannedBy !== undefined) {
        filter.scannedBy = parseObjectId(query.scannedBy, "scannedBy");
    }

    return filter;
}

module.exports = createResourceController({
    Model: Scan,
    writableFields: [
        "assetId",
        "scannedBy",
        "scanType",
        "status",
        "startedAt",
        "completedAt",
        "results"
    ],
    queryFields: ["q", "status", "assetId", "scannedBy"],
    sortFields: ["startedAt", "completedAt", "status", "_id"],
    defaultSort: "startedAt",
    populate,
    buildFilter,
    references: [
        { field: "assetId", model: Asset },
        { field: "scannedBy", model: User },
        {
            field: "results",
            nestedField: "vulnerabilityId",
            array: true,
            model: Vulnerability
        }
    ]
});
