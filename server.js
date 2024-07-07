const dotenv = require("dotenv");
const mongoose = require("mongoose");
const MongoConnection = require("./utils/MongoConnection");

dotenv.config({ path: "./config.env" });

MongoConnection.connect();

const app = require("./app");
const port = process.env.PORT || 4000;

console.log(`ENVIRONMENT: ${app.get("env")}`);

mongoose.connection.once("open", () => {
    console.log(`DATABASE: online`);

    app.listen(port, () => console.log(`PORT: ${port}`));
});

process.on("unhandledRejection", (err) => {
    console.log(`[UnhandledRejection] 💥 [${err.name}]`, err.message);
    server.close(() => process.exit(1));
});

process.on("SIGTERM", () => {
    console.log("[SIGTERM] 💥 received, shutting down...");
    server.close(() => console.log("[SIGTERM] 💥 process terminated."));
});
