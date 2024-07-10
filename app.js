// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const express = require("express");
const morgan = require("morgan");
const compression = require("compression");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");
const AppError = require("./utils/AppError");
const globalErrorHandler = require("./controllers/error-controller");
const corsOptions = require("./config/cors-options");
const credentials = require("./middleware/credentials");
const viewRouter = require("./routes/view-router");
const authRouter = require("./routes/auth-router");
// ------------------------------------------------------------
// MARK: - APPLICATION
// ------------------------------------------------------------
const app = express();
// ------------------------------------------------------------
// MARK: - EJS VIEW ENGINE
// ------------------------------------------------------------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
// ------------------------------------------------------------
// MARK: - JSON
// ------------------------------------------------------------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// ------------------------------------------------------------
// MARK: - COOKIE PARSER
// ------------------------------------------------------------
app.use(cookieParser());
// ------------------------------------------------------------
// MARK: - STATIC FILES
// ------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public")));
// ------------------------------------------------------------
// MARK: - TRUST PROXY
// ------------------------------------------------------------
app.enable("trust proxy");
// ------------------------------------------------------------
// MARK: - CREDENTIALS HEADER
// ------------------------------------------------------------
app.use(credentials);
// ------------------------------------------------------------
// MARK: - CORS
// ------------------------------------------------------------
app.use(cors(corsOptions));
// ------------------------------------------------------------
// MARK: - HELMET - SECURE HTTP HEADERS
// ------------------------------------------------------------
app.use(helmet());
// app.use(helmet.noSniff());
// ------------------------------------------------------------
// MARK: - MORGAN - DEVELOPMENT LOGGER
// ------------------------------------------------------------
if (process.env.NODE_ENV === "development") {
    app.use(morgan("dev"));
}
// ------------------------------------------------------------
// MARK: - BODY PARSER
// ------------------------------------------------------------
app.use(express.json({ limit: "100000kb" }));
// ------------------------------------------------------------
// MARK: - DATA SANITIZATION
// ------------------------------------------------------------
app.use(mongoSanitize());
// ------------------------------------------------------------
// MARK: - XSS PROTECTION
// ------------------------------------------------------------
app.use(xss());
// ------------------------------------------------------------
// MARK: - HPP
// ------------------------------------------------------------
app.use(
    hpp({
        whitelist: ["email", "password"]
    })
);
// ------------------------------------------------------------
// MARK: - COMPRESSION
// ------------------------------------------------------------
app.use(compression());
// ------------------------------------------------------------
// MARK: - ROUTE MOUNTING
// ------------------------------------------------------------
app.use("/", viewRouter);
app.use("/api/v1/auth", authRouter);
// ------------------------------------------------------------
// MARK: - UNEXPECTED ERROR HANDLING
// ------------------------------------------------------------
app.all("*", (req, res, next) => {
    const message = `Can't find ${req.originalUrl} on this server.`;
    const err = new AppError(message, 404);

    next(err);
});
// ------------------------------------------------------------
// MARK: - APPLICATION's ERROR HANDLER
// ------------------------------------------------------------
app.use(globalErrorHandler);
// ------------------------------------------------------------
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = app;
