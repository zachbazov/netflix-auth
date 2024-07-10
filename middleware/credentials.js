// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const allowedOrigins = require("../config/allowed-origins");
// ------------------------------------------------------------
// MARK: - CREDENTIALS HANDLER
// ------------------------------------------------------------
const credentials = (req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin))
        res.header("Access-Control-Allow-Credentials", true);
    next();
};
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = credentials;
