const JWT_ISSUER = "cybertrack-api";
const JWT_AUDIENCE = "cybertrack-client";
const AUTH_COOKIE_NAME = "cybertrack_token";
const AUTH_COOKIE_MAX_AGE_MS = 15 * 60 * 1000;

function getJwtSecret() {
    const secret = process.env.JWT_SECRET;

    if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
        throw new Error("JWT_SECRET must contain at least 32 bytes.");
    }

    return secret;
}

function getCookieOptions(request) {
    return {
        httpOnly: true,
        secure: request ? request.secure : process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/api",
        maxAge: AUTH_COOKIE_MAX_AGE_MS
    };
}

module.exports = {
    AUTH_COOKIE_MAX_AGE_MS,
    AUTH_COOKIE_NAME,
    JWT_AUDIENCE,
    JWT_ISSUER,
    getCookieOptions,
    getJwtSecret
};
