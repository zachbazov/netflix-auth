const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const validator = require("validator");
const bcrypt = require("bcrypt");

const userSchema = new Schema({
    name: String,
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: [validator.isEmail],
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        select: false,
    },
    passwordChangedAt: {
        type: Date,
        default: Date.now(),
    },
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user",
    },
    passwordResetToken: String,
    refreshToken: [String],
});

// MARK: - Document Middleware

// Password Encryption
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
        return next();
    }

    this.password = await bcrypt.hash(this.password, 10);

    next();
});

// Update Password Change Time
userSchema.pre("save", function (next) {
    if (!this.isModified("password") || this.isNew) {
        return next();
    }

    this.passwordChangedAt = Date.now() - 1000;

    next();
});

// MARK: - Instance Method

// Password Compare
userSchema.methods.correctPassword = async function (
    candidatePassword,
    userPassword
) {
    return await bcrypt.compare(
        candidatePassword,
        userPassword
    );
};

const User = mongoose.model("User", userSchema);

module.exports = User;
