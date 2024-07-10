// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const express = require("express");
const router = express.Router();
const APIRestrictor = require("../utils/APIRestrictor");
const authController = require("../controllers/auth-controller");
// ------------------------------------------------------------
// MARK: - ROUTE MOUNTING
// ------------------------------------------------------------
router.post("/signin", authController.signIn);
router.post("/signup", authController.signUp);
router.post("/signout", authController.signOut);
router.post("/refresh", authController.signRefreshToken);
router.post("/forgot-password", authController.forgotPassword);
router.patch("/reset-password", authController.resetPassword);
router.patch(
    "/update-password",
    APIRestrictor.verifyToken,
    authController.updatePassword
);
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = router;
