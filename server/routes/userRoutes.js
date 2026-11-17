const express = require("express");
const controller = require("../controllers/userController");

const router = express.Router();
const { authorizeRoles } = require("../middleware/authenticate");

router.get(
    "/assignees",
    authorizeRoles("ADMIN", "SECURITY_ANALYST"),
    controller.listAssignees
);
router.use(authorizeRoles("ADMIN"));

router.get("/", controller.list);
router.get("/:id", controller.getById);
router.post("/", controller.create);
router.put("/:id", controller.update);
router.delete("/:id", controller.remove);

module.exports = router;
