// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const AppError = require("../utils/AppError");
// ------------------------------------------------------------
// MARK: - ERROR HANDLERS
// ------------------------------------------------------------
// (DB) CASTING ERROR
// ------------------------------
const dbCastErrorResponse = (err) => {
    const message = `Invalid ${err.path}: ${err.value}.`;
    const appError = new AppError(message, 400); // Bad Request - 400
    return appError;
};
// ------------------------------
// (DB) VALIDATION ERROR
// ------------------------------
const dbValidationErrorResponse = (err) => {
    const message = `Invalid ${err.path}: ${err.value}.`;
    const appError = new AppError(message, 400); // Bad Request - 400

    return appError;
};
// ------------------------------
// (DB) DUPLICATION ERROR
// ------------------------------
const dbDuplicateFieldsErrorResponse = (err) => {
    const value = err.errmsg.match(/(["'])(\\?.)*?\1/);
    const message = `Duplicate field value: ${value}. Please use another value.`;
    const appError = new AppError(message, 400); // Bad Request - 400
    return appError;
};
// ------------------------------
// (DB) INVALID JWT ERROR
// ------------------------------
const dbJWTErrorResponse = (err) => {
    const message = "Invalid token. Please sign-in again.";
    const appError = new AppError(message, 401);
    return appError;
};
// ------------------------------
// (DB) EXPIRED JWT ERROR
// ------------------------------
const dbJWTExpiredErrorResponse = (err) => {
    const message = "Token has expired. Please sign-in again.";
    const appError = new AppError(message, 401);
    return appError;
};
// ------------------------------------------------------------
// MARK: - ERROR DISPATCH HANDLER (DEV)
// ------------------------------------------------------------
const sendErrorDev = (err, req, res) => {
    if (req.originalUrl.startsWith("/api")) {
        return res.status(err.statusCode).json({
            status: err.status,
            error: err,
            message: err.message,
            stack: err.stack
        });
    }
    res.status(err.statusCode).render("error", {
        title: "Internal Server Error",
        message: err.message
    });
};
// ------------------------------------------------------------
// MARK: - ERROR DISPATCH HANDLER (PROD)
// ------------------------------------------------------------
const sendErrorProd = (err, req, res) => {
    if (req.originalUrl.startsWith("/api")) {
        if (err.isOperational) {
            return res.status(err.statusCode).json({
                status: err.status,
                message: err.message
            });
        }
        console.log("[ERROR] 💥", err);
        return res.status(500).json({
            status: "error",
            message: "Something went wrong"
        });
    }

    if (err.isOperational) {
        return res.status(err.statusCode).render("error", {
            title: "Internal Server Error",
            message: err.message
        });
    }

    console.log("[ERROR] 💥", err);

    res.status(err.statusCode).render("error", {
        title: "Internal Server Error",
        message: "Please try again later."
    });
};
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "error";

    const nodeEnvironment = process.env.NODE_ENV;

    if (nodeEnvironment === "development") {
        sendErrorDev(err, req, res);
    } else if (nodeEnvironment === "production") {
        let error = Object.assign(err);

        if (error.name === "CastError") {
            error = dbCastErrorResponse(error);
        }

        if (error.name === "ValidationError") {
            error = dbValidationErrorResponse(error);
        }

        if (error.code === 11000) {
            error = dbDuplicateFieldsErrorResponse(error);
        }

        if (error.name === "JsonWebTokenError") {
            error = dbJWTErrorResponse(error);
        }

        if (error.name === "TokenExpiredError") {
            error = dbJWTExpiredErrorResponse(error);
        }

        sendErrorProd(error, req, res);
    }
};
