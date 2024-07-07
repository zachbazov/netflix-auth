const express = require("express");
const router = express.Router();
const APIRestrictor = require("../utils/APIRestrictor");
const authController = require("../controllers/auth-controller");

router.post("/signin", authController.signIn);
router.post("/signup", authController.signUp);
router.get("/signout", authController.signOut);
router.get("/refresh", authController.signRefreshToken);

router.post("/forgot-password", authController.forgotPassword);
router.patch("/reset-password", authController.resetPassword);
router.patch(
    "/update-password",
    APIRestrictor.verifyToken,
    authController.updatePassword
);

module.exports = router;
