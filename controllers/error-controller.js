const AppError = require("../utils/AppError");

const dbCastErrorResponse = (err) => {
    const message = `Invalid ${err.path}: ${err.value}.`;
    const appError = new AppError(message, 400); // Bad Request - 400

    return appError;
};

const dbValidationErrorResponse = (err) => {
    const message = `Invalid ${err.path}: ${err.value}.`;
    const appError = new AppError(message, 400); // Bad Request - 400

    return appError;
};

const dbDuplicateFieldsErrorResponse = (err) => {
    const value = err.errmsg.match(/(["'])(\\?.)*?\1/);
    const message = `Duplicate field value: ${value}. Please use another value.`;
    const appError = new AppError(message, 400); // Bad Request - 400

    return appError;
};

const dbJWTTokenErrorResponse = (err) => {
    const message = "Invalid token. Please sign-in again.";
    const appError = new AppError(message, 401);

    return appError;
};

const dbJWTTokenExpiredErrorResponse = (err) => {
    const message = "Token has expired. Please sign-in again.";
    const appError = new AppError(message, 401);

    return appError;
};

const sendErrorDev = (err, req, res) => {
    if (req.originalUrl.startsWith("/api")) {
        return res.status(err.statusCode).json({
            status: err.status,
            error: err,
            message: err.message,
            stack: err.stack
        });
    }
};

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

    console.log("[ERROR] 💥", err);
};

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
            error = dbJWTTokenErrorResponse(error);
        }

        if (error.name === "TokenExpiredError") {
            error = dbJWTTokenExpiredErrorResponse(error);
        }

        sendErrorProd(error, req, res);
    }
};
