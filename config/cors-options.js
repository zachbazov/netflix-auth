// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const allowedOrigins = require("./allowed-origins");
// ------------------------------------------------------------
// MARK: - CROSS-ORIGIN ALLOWED LIST
// ------------------------------------------------------------
// DETERMINE WHETHER THE INCOMING REQUEST'S ORIGIN IS ALLOWED
// ------------------------------
const corsOptions = {
    origin: (origin, callback) => {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error("Unexpected origin resource."));
        }
    },
    optionsSuccessStatus: 200
};
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = corsOptions;
