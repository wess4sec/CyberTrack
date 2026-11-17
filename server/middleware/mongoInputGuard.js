const AppError = require("../utils/AppError");

const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function inspectValue(value) {
    if (Array.isArray(value)) {
        value.forEach(inspectValue);
        return;
    }

    if (!value || typeof value !== "object") {
        return;
    }

    for (const [key, nestedValue] of Object.entries(value)) {
        if (
            key.startsWith("$") ||
            key.includes(".") ||
            FORBIDDEN_KEYS.has(key)
        ) {
            throw new AppError(400, "Request contains an unsupported query operator or field.");
        }

        inspectValue(nestedValue);
    }
}

function mongoInputGuard(request, _response, next) {
    try {
        inspectValue(request.body);
        inspectValue(request.query);
        next();
    } catch (error) {
        next(error);
    }
}

module.exports = mongoInputGuard;
