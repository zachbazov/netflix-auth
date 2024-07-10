// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/AppError");
const TokenService = require("../utils/TokenService");
// ------------------------------------------------------------
// MARK: - AUTH HANDLERS
// ------------------------------------------------------------
// SIGN IN HANDLER
// ------------------------------
const signIn = catchAsync(async (req, res, next) => {
    const cookies = req.cookies;
    const { email, password } = req.body;

    if (!email || !password) {
        const error = new AppError("Invalid username or password", 400);
        return next(error);
    }

    const foundUser = await User.findOne({ email }).select("+password");

    if (!foundUser) {
        const error = new AppError("Unauthorized", 401);
        return next(error);
    }

    const match = await foundUser.correctPassword(
        password,
        foundUser.password
    );

    if (match) {
        const role = foundUser.role;
        const accessToken = TokenService.signAccessToken(
            foundUser,
            foundUser.name,
            role
        );
        const newRefreshToken = TokenService.signRefreshToken(
            foundUser,
            foundUser.name,
            role
        );

        let newRefreshTokenArray = foundUser.refreshToken;
        if (newRefreshTokenArray.length >= 2) {
            const oldRefreshToken = newRefreshTokenArray.shift();
            await User.updateOne(
                { email: foundUser.email },
                { $pull: { refreshToken: oldRefreshToken } }
            );

            if (cookies.refreshToken === oldRefreshToken) {
                await TokenService.removeCookie(res);
            }
        }

        newRefreshTokenArray.push(newRefreshToken);
        foundUser.refreshToken = newRefreshTokenArray;

        await foundUser.save();
        await TokenService.setCookie(res, accessToken, newRefreshToken);

        res.json({ role, accessToken, refreshToken: newRefreshToken });
    } else {
        const error = new AppError("Unauthorized", 401);
        return next(error);
    }
});
// ------------------------------
// SIGN UP HANDLER
// ------------------------------
const signUp = catchAsync(async (req, res, next) => {
    const { name, email, password } = req.body;

    if (!email || !password) {
        const error = new AppError("Invalid username or password.", 400);
        return next(error);
    }

    const duplicate = await User.findOne({ email });

    if (duplicate) return res.sendStatus(409);

    try {
        const data = await User.create({ name, email, password });

        res.status(201).json({
            status: "success",
            data
        });
    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});
// ------------------------------
// SIGN OUT HANDLER
// ------------------------------
const signOut = async (req, res) => {
    const refreshToken = req.body.refreshToken;
    const decoded = jwt.decode(refreshToken);
    const foundUser = await User.findOne({ email: decoded.email });

    if (!foundUser) {
        await TokenService.removeCookie(res);
        return res.sendStatus(404);
    }

    const contains = await constainsValue(
        foundUser.refreshToken,
        refreshToken
    );

    if (contains) deleteValue(foundUser.refreshToken, refreshToken);

    await foundUser.save();
    await TokenService.removeCookie(res);

    return res.status(200).json({ message: "Signed out successfully." });
};
// ------------------------------
// REFRESH TOKEN HANDLER
// ------------------------------
const signRefreshToken = async (req, res) => {
    const refreshToken = req.body.refreshToken;
    const decodedUser = jwt.decode(refreshToken);

    await TokenService.removeCookie(res);

    const foundUser = await User.findOne({ email: decodedUser.email });

    if (!foundUser) {
        TokenService.verifyTokenForReuse(res, refreshToken);
        return res.sendStatus(403);
    }

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) await TokenService.removeCookie(res);

            if (err || foundUser.email !== decoded.email)
                return res.sendStatus(403);

            const role = foundUser.role;
            const accessToken = TokenService.signAccessToken(
                foundUser,
                foundUser.name,
                role
            );
            const newRefreshToken = TokenService.signRefreshToken(
                foundUser,
                foundUser.name,
                role
            );

            let newRefreshTokenArray = foundUser.refreshToken;
            if (newRefreshTokenArray.length >= 2) {
                const oldRefreshToken = newRefreshTokenArray.shift();
                await User.updateOne(
                    { email: foundUser.email },
                    { $pull: { refreshToken: oldRefreshToken } }
                );

                if (refreshToken === oldRefreshToken) {
                    await TokenService.removeCookie(res);
                }
            }

            newRefreshTokenArray.push(newRefreshToken);
            foundUser.refreshToken = newRefreshTokenArray;

            await foundUser.save();
            await TokenService.setCookie(
                res,
                accessToken,
                newRefreshToken
            );

            res.json({ role, accessToken, refreshToken: newRefreshToken });
        }
    );
};
// ------------------------------
// FORGOT PASSWORD HANDLER
// ------------------------------
const forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({
        email: req.body.email
    });

    if (!user) {
        const message = "No match.";
        const appError = new AppError(message, 404);

        return next(appError);
    }

    const resetToken = user.generatePasswordResetToken();

    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get(
        "host"
    )}/api/v1/users/reset-password?token=${resetToken}`;

    const message = `Forgot your password?\nin order to reset your password please visit:\n${resetURL}\nIf you didn't forget your password, ignore this message.`;

    try {
        await NodeMailer({
            email: user.email,
            subject: "Your password reset token. will be valid for 10min.",
            message
        });

        res.status(200).json({
            status: "success",
            message: "Password reset token has been to the provided email."
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpirationPeriod = undefined;

        await user.save({ validateBeforeSave: false });

        const message = "There was an error dispatching the email.";
        const appError = new AppError(message, 500);

        return next(appError);
    }
});
// ------------------------------
// RESET PASSWORD HANDLER
// ------------------------------
const resetPassword = catchAsync(async (req, res, next) => {
    const hashedToken = crypto
        .createHash("sha256")
        .update(req.query.token)
        .digest("hex");

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpirationPeriod: { $gt: Date.now() }
    });

    if (!user) {
        const message = "Token is invalid or has expired.";
        const appError = new AppError(message, 400);

        return next(appError);
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpirationPeriod = undefined;

    await user.save();

    dispatchSignToken(user, 200, req, res);
});
// ------------------------------
// UPDATE PASSWORD HANDLER
// ------------------------------
const updatePassword = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).select("+password");

    if (
        !(await user.correctPassword(
            req.body.passwordCurrent,
            user.password
        ))
    ) {
        const message = "Current password incorrect";
        const appError = new AppError(message, 401);

        return next(appError);
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    await user.save();

    dispatchSignToken(user, 200, req, res);
});
// ------------------------------------------------------------
// MARK: - PRIVATE METHODS
// ------------------------------------------------------------
const constainsValue = async (array, value) => {
    return await array.includes(value);
};
const deleteValue = async (array, value) => {
    const index = array.indexOf(value);
    if (index !== -1) {
        await array.splice(index, 1);
        return true;
    }
    return false;
};
// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
module.exports = {
    signIn,
    signUp,
    signOut,
    signRefreshToken,
    updatePassword,
    resetPassword,
    forgotPassword
};
