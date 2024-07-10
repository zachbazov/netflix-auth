// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const mongoose = require("mongoose");
// ------------------------------------------------------------
// MARK: - STRICT QUERY
// ------------------------------------------------------------
// CONSIDER FIELDS DEFINED IN THE SCHEMA
// ------------------------------
mongoose.set("strictQuery", false);
// ------------------------------------------------------------
// MARK: - CLASS DECLARATION
// ------------------------------------------------------------
class MongoConnection {
    static async connect() {
        try {
            await mongoose.connect(process.env.DB_URI);
        } catch (e) {
            console.log(e);
        }
        return this;
    }
}
// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
module.exports = MongoConnection;
