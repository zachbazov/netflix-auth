// ------------------------------------------------------------
// MARK: - CLASS DECLARATION
// ------------------------------------------------------------
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);

        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith("4")
            ? "failure"
            : "error";
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = AppError;
