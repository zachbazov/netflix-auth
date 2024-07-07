const mongoose = require("mongoose");

mongoose.set("strictQuery", false);

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

module.exports = MongoConnection;
