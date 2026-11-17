const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Scan = require("../models/Scan");
const RemediationTask = require("../models/RemediationTask");
const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const createResourceController = require("../utils/resourceController");
const {
    assertAllowedQuery,
    escapeRegex,
    getQueryString,
    parseInteger,
    safeSerialize
} = require("../utils/requestValidation");
const { assertNoReferences } = require("../utils/references");

const BCRYPT_ROUNDS = 12;

async function prepareUserPayload(payload, passwordRequired) {
    const { password, ...userFields } = payload;

    if (password === undefined && !passwordRequired) {
        return userFields;
    }

    if (
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 128 ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        throw new AppError(
            400,
            "Password must contain 12 to 128 characters and at most 72 UTF-8 bytes."
        );
    }

    return {
        ...userFields,
        passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS)
    };
}

function buildFilter(query) {
    const filter = {};
    const search = getQueryString(query, "q", { maxLength: 120 });
    const role = getQueryString(query, "role", { maxLength: 40 });
    const isActive = getQueryString(query, "isActive", { maxLength: 5 });

    if (search) {
        const expression = new RegExp(escapeRegex(search), "i");
        filter.$or = [{ fullName: expression }, { email: expression }];
    }
    if (role) filter.role = role;
    if (isActive !== undefined) {
        if (isActive !== "true" && isActive !== "false") {
            throw new AppError(400, 'Query parameter "isActive" must be true or false.');
        }
        filter.isActive = isActive === "true";
    }

    return filter;
}

const controller = createResourceController({
    Model: User,
    writableFields: [
        "fullName",
        "email",
        "password",
        "role",
        "department",
        "isActive"
    ],
    queryFields: ["q", "role", "isActive"],
    sortFields: ["fullName", "email", "createdAt", "_id"],
    defaultSort: "fullName",
    buildFilter,
    prepareCreate: payload => prepareUserPayload(payload, true),
    prepareUpdate: payload => prepareUserPayload(payload, false),
    beforeDelete: id =>
        assertNoReferences([
            {
                model: Scan,
                filter: { scannedBy: id },
                label: "scans"
            },
            {
                model: RemediationTask,
                filter: {
                    $or: [{ assignedTo: id }, { createdBy: id }]
                },
                label: "remediation tasks"
            }
        ])
});

controller.listAssignees = asyncHandler(async (request, response) => {
    assertAllowedQuery(request.query, ["q", "page", "limit"]);
    const page = parseInteger(request.query.page, "page", {
        defaultValue: 1,
        min: 1,
        max: 1000000
    });
    const limit = parseInteger(request.query.limit, "limit", {
        defaultValue: 20,
        min: 1,
        max: 100
    });
    const search = getQueryString(request.query, "q", { maxLength: 120 });
    const filter = { isActive: true };

    if (search) {
        const expression = new RegExp(escapeRegex(search), "i");
        filter.fullName = expression;
    }

    const [users, total] = await Promise.all([
        User.find(filter)
            .select("fullName role department")
            .sort({ fullName: 1, _id: 1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .exec(),
        User.countDocuments(filter)
    ]);

    response.status(200).json({
        success: true,
        data: safeSerialize(users),
        pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit)
        }
    });
});

module.exports = controller;
