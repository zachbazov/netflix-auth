// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const MongoConnection = require("./utils/MongoConnection");
const app = require("./app");
// ------------------------------------------------------------
// MARK: - DOVENV CONFIG PATH
// ------------------------------------------------------------
dotenv.config({ path: "./config.env" });
// ------------------------------------------------------------
// MARK: - PORT
// ------------------------------------------------------------
const port = process.env.PORT || 4000;
// ------------------------------------------------------------
// MARK: - NODE ENVIRONMENT LOGGER
// ------------------------------------------------------------
console.log(`ENVIRONMENT: ${app.get("env")}`);
// ------------------------------------------------------------
// MARK: - MONGODB CONNECTION
// ------------------------------------------------------------
MongoConnection.connect();
mongoose.connection.once("open", () => {
    console.log(`DATABASE: online`);
    app.listen(port, () => console.log(`PORT: ${port}`));
});
// ------------------------------------------------------------
// MARK: - UNHANDLED REJECTION ERROR HANDLER
// ------------------------------------------------------------
process.on("unhandledRejection", (err) => {
    // console.log(err);
    console.log(`[UnhandledRejection] 💥 [${err.name}]`, err.message);
    server.close(() => process.exit(1));
});
// ------------------------------------------------------------
// MARK: - SIGTERM ERROR HANDLER
// ------------------------------------------------------------
process.on("SIGTERM", () => {
    console.log("[SIGTERM] 💥 received, shutting down...");
    server.close(() => console.log("[SIGTERM] 💥 process terminated."));
});
