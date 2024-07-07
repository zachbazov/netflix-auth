const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth-controller");

router.post("/signin", authController.signIn);
router.post("/signup", authController.signUp);
router.get("/signout", authController.signOut);
router.get("/refresh", authController.signRefreshToken);

module.exports = router;
