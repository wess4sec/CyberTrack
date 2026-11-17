const bcrypt = require("bcryptjs");
const { randomBytes } = require("node:crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const {
    AUTH_COOKIE_NAME,
    JWT_AUDIENCE,
    JWT_ISSUER,
    getCookieOptions,
    getJwtSecret
} = require("../config/auth");
const {
    pickBodyFields,
    safeSerialize
} = require("../utils/requestValidation");

const BCRYPT_ROUNDS = 12;
let dummyHashPromise;

function getDummyHash() {
    if (!dummyHashPromise) {
        dummyHashPromise = bcrypt.hash(
            randomBytes(32).toString("hex"),
            BCRYPT_ROUNDS
        );
    }
    return dummyHashPromise;
}

function normalizeRole(role) {
    return role === "ANALYST" ? "SECURITY_ANALYST" : role;
}

const login = asyncHandler(async (request, response) => {
    const body = pickBodyFields(request.body, ["email", "password"]);

    if (
        typeof body.email !== "string" ||
        typeof body.password !== "string" ||
        body.email.length > 254 ||
        body.password.length > 128 ||
        Buffer.byteLength(body.password, "utf8") > 72 ||
        body.password.length === 0
    ) {
        throw new AppError(400, "Email or password is invalid.");
    }

    const user = await User.findOne({
        email: body.email.trim().toLowerCase()
    }).select("+passwordHash");
    const hash = user ? user.passwordHash : await getDummyHash();
    const passwordMatches = await bcrypt.compare(body.password, hash);

    if (!user || !user.isActive || !passwordMatches) {
        throw new AppError(401, "Email or password is incorrect.");
    }

    const token = jwt.sign(
        {
            sub: user.id,
            role: normalizeRole(user.role)
        },
        getJwtSecret(),
        {
            algorithm: "HS256",
            expiresIn: "15m",
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE
        }
    );

    response.cookie(AUTH_COOKIE_NAME, token, getCookieOptions(request));
    response.status(200).json({
        success: true,
        data: {
            user: safeSerialize(user)
        }
    });
});

const logout = asyncHandler(async (_request, response) => {
    const options = getCookieOptions(_request);
    delete options.maxAge;
    response.clearCookie(AUTH_COOKIE_NAME, options);
    response.status(200).json({
        success: true,
        data: { loggedOut: true }
    });
});

const currentUser = asyncHandler(async (request, response) => {
    response.status(200).json({
        success: true,
        data: { user: safeSerialize(request.currentUser) }
    });
});

module.exports = {
    currentUser,
    login,
    logout
};
