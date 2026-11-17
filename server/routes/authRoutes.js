const express = require("express");
const rateLimit = require("express-rate-limit");
const controller = require("../controllers/authController");
const { authenticate } = require("../middleware/authenticate");

const router = express.Router();
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(_request, response) {
        response.status(429).json({
            success: false,
            error: { message: "Too many login attempts. Try again later." }
        });
    }
});

router.post("/login", loginLimiter, controller.login);
router.post("/logout", controller.logout);
router.get("/me", authenticate, controller.currentUser);

module.exports = router;
