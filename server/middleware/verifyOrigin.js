const AppError = require("../utils/AppError");

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function verifyOrigin(allowedOrigins) {
    return function originGuard(request, _response, next) {
        const origin = request.get("origin");

        if (
            STATE_CHANGING_METHODS.has(request.method) &&
            origin &&
            !allowedOrigins.includes(origin)
        ) {
            next(new AppError(403, "Request origin is not allowed."));
            return;
        }

        next();
    };
}

module.exports = verifyOrigin;
