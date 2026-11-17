require("./config/database");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const authRoutes = require("./routes/authRoutes");
const vulnerabilityRoutes = require("./routes/vulnerabilityRoutes");
const assetRoutes = require("./routes/assetRoutes");
const userRoutes = require("./routes/userRoutes");
const scanRoutes = require("./routes/scanRoutes");
const remediationRoutes = require("./routes/remediationRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const { authenticate } = require("./middleware/authenticate");
const mongoInputGuard = require("./middleware/mongoInputGuard");
const notFound = require("./middleware/notFound");
const errorHandler = require("./middleware/errorHandler");
const verifyOrigin = require("./middleware/verifyOrigin");
const { requestLogger } = require("./utils/logger");

const app = express();
const trustProxyHopsValue = process.env.TRUST_PROXY_HOPS || "0";

if (!/^\d+$/.test(trustProxyHopsValue)) {
    throw new Error("TRUST_PROXY_HOPS must be a non-negative integer.");
}

const trustProxyHops = Number(trustProxyHopsValue);

if (!Number.isSafeInteger(trustProxyHops)) {
    throw new Error("TRUST_PROXY_HOPS must be a non-negative integer.");
}

app.set("trust proxy", trustProxyHops);

const allowedOrigins = (
    process.env.CORS_ORIGIN ||
    "http://localhost:5173,http://127.0.0.1:5173"
)
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.set("query parser", "simple");
app.disable("x-powered-by");
app.use(helmet());
app.use(
    cors({
        credentials: true,
        origin(origin, callback) {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
                return;
            }
            callback(null, false);
        }
    })
);
app.use(express.json({ limit: "1mb", strict: true }));
app.use(requestLogger);
app.use(mongoInputGuard);

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(_request, response) {
        response.status(429).json({
            success: false,
            error: { message: "Too many requests. Try again later." }
        });
    }
});

app.use("/api", apiLimiter);
app.use("/api", verifyOrigin(allowedOrigins));

app.get("/api/health", (_request, response) => {
    const connected = mongoose.connection.readyState === 1;
    response.status(connected ? 200 : 503).json({
        success: connected,
        data: {
            status: connected ? "ok" : "unavailable",
            database: connected ? "connected" : "disconnected"
        }
    });
});

app.use("/api/auth", authRoutes);
app.use("/api/vulnerabilities", authenticate, vulnerabilityRoutes);
app.use("/api/assets", authenticate, assetRoutes);
app.use("/api/users", authenticate, userRoutes);
app.use("/api/scans", authenticate, scanRoutes);
app.use("/api/remediation", authenticate, remediationRoutes);
app.use("/api/dashboard", authenticate, dashboardRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
