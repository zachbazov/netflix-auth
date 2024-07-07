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
    // const match = await bcrypt.compare(password, foundUser.password);

    if (match) {
        // Reuse Detector
        const accessToken = TokenService.signAccessToken(foundUser);
        const newRefreshToken = TokenService.signRefreshToken(foundUser);

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

        res.json({ accessToken });
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

            const accessToken = TokenService.signAccessToken(decoded);
            const newRefreshToken = TokenService.signRefreshToken(decoded);

            foundUser.refreshToken = [
                ...newRefreshTokenArray,
                newRefreshToken
            ];

            await foundUser.save();
            await TokenService.setCookie(res, newRefreshToken);

            res.json({ accessToken });
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

        next();
    });
};

module.exports = {
    signIn,
    signUp,
    signOut,
    signRefreshToken,
    verifyToken
};
