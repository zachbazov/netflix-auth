const User = require("../models/User");
const jwt = require("jsonwebtoken");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/AppError");
const TokenService = require("../utils/TokenService");

const signIn = catchAsync(async (req, res, next) => {
    const cookies = req.cookies;

    const { email, password } = req.body;

    if (!email || !password) {
        const error = new AppError("Invalid username or password", 400);
        return next(error);
    }

    const foundUser = await User.findOne({ email }).select("+password");

    if (!foundUser) return res.sendStatus(401);

    const match = await foundUser.correctPassword(
        password,
        foundUser.password
    );

    if (match) {
        const role = foundUser.role;
        // Reuse Detector
        const accessToken = TokenService.signAccessToken(foundUser, role);
        const newRefreshToken = TokenService.signRefreshToken(
            foundUser,
            role
        );

        let newRefreshTokenArray = !cookies?.jwt
            ? foundUser.refreshToken
            : foundUser.refreshToken.filter((rt) => rt !== cookies.jwt);

        if (cookies?.jwt) {
            const refreshToken = cookies.jwt;
            const foundToken = await User.findOne({ refreshToken });

            if (!foundToken) newRefreshTokenArray = [];

            await TokenService.removeCookie(res);
        }

        foundUser.refreshToken = [
            ...newRefreshTokenArray,
            newRefreshToken
        ];

        await foundUser.save();
        await TokenService.setCookie(res, newRefreshToken);

        res.json({ role, accessToken });
    } else {
        res.sendStatus(401);
    }
});

const signUp = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        const error = new AppError("Invalid username or password.", 400);
        return next(error);
    }

    const duplicate = await User.findOne({ email });

    if (duplicate) return res.sendStatus(409);

    try {
        const data = await User.create({ email, password });

        res.status(201).json({
            status: "success",
            data
        });
    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});

const signOut = async (req, res) => {
    const cookies = req.cookies;

    if (!cookies?.jwt) return res.sendStatus(204);

    const refreshToken = cookies.jwt;
    const foundUser = await User.findOne({ refreshToken });

    if (!foundUser) {
        await TokenService.removeCookie(res);

        return res.sendStatus(204);
    }

    foundUser.refreshToken = foundUser.refreshToken.filter(
        (rt) => rt !== refreshToken
    );

    await foundUser.save();
    await TokenService.removeCookie(res);

    return res.sendStatus(204);
};

const signRefreshToken = async (req, res) => {
    const cookies = req.cookies;

    if (!cookies?.jwt) return res.sendStatus(401);

    const refreshToken = cookies.jwt;

    await TokenService.removeCookie(res);

    const foundUser = await User.findOne({ refreshToken });

    if (!foundUser) {
        TokenService.verifyTokenForReuse(res, refreshToken);

        return res.sendStatus(403);
    }

    const newRefreshTokenArray = foundUser.refreshToken.filter(
        (rt) => rt !== refreshToken
    );

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) {
                foundUser.refreshToken = [...newRefreshTokenArray];

                await foundUser.save();
            }

            if (err || foundUser.email !== decoded.email)
                return res.sendStatus(403);

            const role = foundUser.role;
            const accessToken = TokenService.signAccessToken(
                decoded,
                role
            );
            const newRefreshToken = TokenService.signRefreshToken(
                decoded,
                role
            );

            foundUser.refreshToken = [
                ...newRefreshTokenArray,
                newRefreshToken
            ];

            await foundUser.save();
            await TokenService.setCookie(res, newRefreshToken);

            res.json({ role, accessToken });
        }
    );
};

const verifyToken = (req, res) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader) return res.sendStatus(401);

    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);

        req.verifiedEmail = decoded.email;
        req.verifiedRole = decoded.role;

        next();
    });
};

// Dispatch an Email for a forgotten password
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

// Request a new User password and reset it's token
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

// Update User Password
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

module.exports = {
    signIn,
    signUp,
    signOut,
    signRefreshToken,
    verifyToken,
    updatePassword,
    resetPassword,
    forgotPassword
};
