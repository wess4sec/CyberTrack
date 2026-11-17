const AppError = require("../utils/AppError");
const { writeLog } = require("../utils/logger");

function validationDetails(error) {
    return Object.values(error.errors || {}).map(item => ({
        field: item.path,
        message: "Invalid value."
    }));
}

function errorHandler(error, _request, response, next) {
    if (response.headersSent) {
        return next(error);
    }

    let statusCode = error.statusCode || 500;
    let message = error.message || "Internal server error.";
    let details = error.details;

    if (error.type === "entity.parse.failed") {
        statusCode = 400;
        message = "Request body contains invalid JSON.";
        details = undefined;
    } else if (error.name === "ValidationError") {
        statusCode = 400;
        message = "Request validation failed.";
        details = validationDetails(error);
    } else if (error.name === "CastError") {
        statusCode = 400;
        message = `Invalid value for "${error.path}".`;
        details = undefined;
    } else if (error.name === "StrictModeError") {
        statusCode = 400;
        message = "Request contains an unsupported field.";
        details = undefined;
    } else if (error.code === 11000) {
        statusCode = 409;
        message = "A record with a unique value already exists.";
        details = undefined;
    } else if (error.code === 121) {
        statusCode = 400;
        message = "Document does not satisfy the MongoDB collection validator.";
        details = undefined;
    } else if (!(error instanceof AppError) && statusCode >= 500) {
        writeLog("error", "api_request_failed", {
            errorName: error.name || "Error",
            ...(typeof error.code === "number" ? { errorCode: error.code } : {})
        });
        message = "Internal server error.";
        details = undefined;
    }

    const payload = {
        success: false,
        error: {
            message
        }
    };

    if (details) {
        payload.error.details = details;
    }

    response.status(statusCode).json(payload);
}

module.exports = errorHandler;
