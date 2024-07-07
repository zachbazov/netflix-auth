const jwt = require("jsonwebtoken");
const User = require("../models/User");

const accessTokenExpireTime = "12h";
const refreshTokenExpireTime = "1d";

class TokenService {
    static async setCookie(res, refreshToken) {
        res.cookie("jwt", refreshToken, {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        });
    }

    static async removeCookie(res) {
        await res.clearCookie("jwt", {
            httpOnly: true,
            sameSite: "None",
            secure: true
        });
    }

    static async verifyTokenForReuse(res, refreshToken) {
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403);

                const refreshedUser = await User.findOne({
                    email: decoded.email
                });

                refreshedUser.refreshToken = [];

                await refreshedUser.save();
            }
        );
    }

    static signAccessToken(user, role) {
        return jwt.sign(
            { email: user.email, role },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: accessTokenExpireTime }
        );
    }

    static signRefreshToken(user, role) {
        return jwt.sign(
            { email: user.email, role },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: refreshTokenExpireTime }
        );
    }
}

module.exports = TokenService;
