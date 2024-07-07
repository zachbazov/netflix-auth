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

const viewRouter = require("./routes/view-router");
const authRouter = require("./routes/auth-router");

// MARK: - Error Handling
const AppError = require("./utils/AppError");
const globalErrorHandler = require("./controllers/error-controller");

// MARK: - Application
const app = express();

// MARK: - EJS View Engine

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// MARK: - JSON
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// MARK: - Serving Static Files
app.use(express.static(path.join(__dirname, "public")));

// MARK: - Trust Proxies
// Works with `req.headers('x-forwarded-proto')`
// for secure HTTPS Connections
app.enable("trust proxy");

// MARK: - CORS
app.use(cors());
app.options("*", cors());

// MARK: - Security HTTP Headers
app.use(helmet());
// app.use(helmet.noSniff());

// MARK: - Development Logging
if (process.env.NODE_ENV === "development") {
    app.use(morgan("dev"));
}

// MARK: - Body Parser
// reads data into 'req.body'
app.use(express.json({ limit: "100000kb" }));

// MARK: - Cookie Parser
// req.cookies
app.use(cookieParser());

// MARK: - Security - Data Sanitization
// against NoSQL query injection
app.use(mongoSanitize());

// MARK: - Security - Against XSS
// Cleans any user input from malicious HTML code
app.use(xss());

// MARK: - Prevent Parameter Pollution
// Clears the query string
app.use(
    hpp({
        whitelist: ["email", "password"]
    })
);

// MARK: - Compression
// Compresses the text that sent to the clients
app.use(compression());

// MARK: -
app.use((req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    next();
});

// MARK: - Route Mounting
app.use("/", viewRouter);
app.use("/api/v1/auth", authRouter);

// MARK: - Error Handling Routes
app.all("*", (req, res, next) => {
    const message = `Can't find ${req.originalUrl} on this server.`;
    const err = new AppError(message, 404);

    next(err);
});

// MARK: - Error Handling Middleware
app.use(globalErrorHandler);

module.exports = app;
