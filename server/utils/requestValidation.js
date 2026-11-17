const mongoose = require("mongoose");
const AppError = require("./AppError");

function requirePlainObject(value, message = "A JSON object is required.") {
    if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype
    ) {
        throw new AppError(400, message);
    }
}

function pickBodyFields(body, allowedFields) {
    requirePlainObject(body);
    const allowed = new Set(allowedFields);
    const unknownFields = Object.keys(body).filter(key => !allowed.has(key));

    if (unknownFields.length > 0) {
        throw new AppError(
            400,
            `Unsupported field(s): ${unknownFields.join(", ")}.`
        );
    }

    if (Object.keys(body).length === 0) {
        throw new AppError(400, "The request body must not be empty.");
    }

    return body;
}

function assertAllowedQuery(query, allowedFields) {
    const allowed = new Set(allowedFields);
    const unknownFields = Object.keys(query).filter(key => !allowed.has(key));

    if (unknownFields.length > 0) {
        throw new AppError(
            400,
            `Unsupported query parameter(s): ${unknownFields.join(", ")}.`
        );
    }
}

function getQueryString(query, key, { required = false, maxLength = 200 } = {}) {
    const value = query[key];

    if (value === undefined) {
        if (required) {
            throw new AppError(400, `Query parameter "${key}" is required.`);
        }
        return undefined;
    }

    if (typeof value !== "string" || value.length > maxLength) {
        throw new AppError(400, `Query parameter "${key}" is invalid.`);
    }

    const normalized = value.trim();

    if (required && normalized.length === 0) {
        throw new AppError(400, `Query parameter "${key}" is required.`);
    }

    return normalized;
}

function parseInteger(value, name, { defaultValue, min, max }) {
    if (value === undefined) {
        return defaultValue;
    }

    if (typeof value !== "string" || !/^\d+$/.test(value)) {
        throw new AppError(400, `Query parameter "${name}" must be an integer.`);
    }

    const parsed = Number(value);

    if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
        throw new AppError(
            400,
            `Query parameter "${name}" must be between ${min} and ${max}.`
        );
    }

    return parsed;
}

function parseObjectId(value, label = "id") {
    if (!mongoose.isObjectIdOrHexString(value)) {
        throw new AppError(400, `Invalid ${label}.`);
    }

    return value;
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeSerialize(value) {
    if (
        value === null ||
        typeof value !== "object" ||
        value instanceof Date ||
        Buffer.isBuffer(value) ||
        value._bsontype
    ) {
        return value;
    }

    const plainValue =
        typeof value.toObject === "function"
            ? value.toObject({ virtuals: false, getters: false })
            : value;

    if (Array.isArray(plainValue)) {
        return plainValue.map(safeSerialize);
    }

    const serialized = {};

    for (const [key, nestedValue] of Object.entries(plainValue)) {
        if (key !== "passwordHash" && key !== "__v") {
            serialized[key] = safeSerialize(nestedValue);
        }
    }

    return serialized;
}

module.exports = {
    assertAllowedQuery,
    escapeRegex,
    getQueryString,
    parseInteger,
    parseObjectId,
    pickBodyFields,
    requirePlainObject,
    safeSerialize
};
