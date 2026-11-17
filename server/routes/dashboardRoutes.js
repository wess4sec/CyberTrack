const express = require("express");
const controller = require("../controllers/dashboardController");

const router = express.Router();
const { authorizeRoles } = require("../middleware/authenticate");

router.use(authorizeRoles("ADMIN", "SECURITY_ANALYST", "VIEWER"));

router.get("/overview", controller.overview);
router.get("/severity", controller.severity);
router.get("/vulnerability-status", controller.vulnerabilityStatus);
router.get("/monthly-trends", controller.monthlyTrends);
router.get("/top-vulnerabilities", controller.topVulnerabilities);
router.get("/scans", controller.scans);
router.get("/top-assets", controller.topAssets);
router.get("/frequent-cves", controller.frequentCves);

module.exports = router;
