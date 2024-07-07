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
        validate: [validator.isEmail]
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        select: false
    },
    passwordChangedAt: {
        type: Date,
        default: Date.now()
    },
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    },
    passwordResetToken: String,
    passwordResetExpirationPeriod: Date,
    refreshToken: [String]
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
    return await bcrypt.compare(candidatePassword, userPassword);
};

// Value JWT Timestamp for Password Changes
userSchema.methods.changedPasswordAfter = function (jwtTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(
            this.passwordChangedAt.getTime() / 1000,
            10
        );

        return jwtTimestamp < changedTimestamp;
    }

    return false;
};

// Generate Password Reset Token
userSchema.methods.generatePasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString("hex");

    this.passwordResetToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    this.passwordResetExpirationPeriod = Date.now() + 10 * 60 * 1000;

    return resetToken;
};

// MARK: - Improve Performance
// userSchema.index({ name: 1 });
// userSchema.index({ role: 1 });

const User = mongoose.model("User", userSchema);

module.exports = User;
