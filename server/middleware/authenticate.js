const jwt = require("jsonwebtoken");
const User = require("../models/User");
const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const {
    JWT_AUDIENCE,
    JWT_ISSUER,
    getJwtSecret
} = require("../config/auth");

function readAuthCookie(request) {
    const cookieHeader = request.get("cookie");

    if (!cookieHeader) {
        return undefined;
    }

    for (const part of cookieHeader.split(";")) {
        const separator = part.indexOf("=");

        if (separator < 0) continue;

        const name = part.slice(0, separator).trim();
        if (name === "cybertrack_token") {
            try {
                return decodeURIComponent(part.slice(separator + 1).trim());
            } catch {
                return undefined;
            }
        }
    }

    return undefined;
}

const authenticate = asyncHandler(async (request, _response, next) => {
    const token = readAuthCookie(request);

    if (!token) {
        throw new AppError(401, "Authentication is required.");
    }

    let payload;

    try {
        payload = jwt.verify(token, getJwtSecret(), {
            algorithms: ["HS256"],
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE
        });
    } catch {
        throw new AppError(401, "Authentication is invalid or expired.");
    }

    if (!payload || typeof payload.sub !== "string") {
        throw new AppError(401, "Authentication is invalid or expired.");
    }

    const user = await User.findById(payload.sub).exec();

    if (!user || !user.isActive) {
        throw new AppError(401, "Authentication is invalid or expired.");
    }

    request.currentUser = user;
    next();
});

function normalizeRole(role) {
    return role === "ANALYST" ? "SECURITY_ANALYST" : role;
}

function authorizeRoles(...allowedRoles) {
    const normalizedRoles = new Set(allowedRoles.map(normalizeRole));

    return function roleGuard(request, _response, next) {
        if (!request.currentUser) {
            next(new AppError(401, "Authentication is required."));
            return;
        }

        if (!normalizedRoles.has(normalizeRole(request.currentUser.role))) {
            next(new AppError(403, "You do not have permission to perform this action."));
            return;
        }

        next();
    };
}

module.exports = {
    authenticate,
    authorizeRoles
};
