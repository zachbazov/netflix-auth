// ------------------------------------------------------------
// MARK: - MODULE INJECTION
// ------------------------------------------------------------
const jwt = require("jsonwebtoken");
const User = require("../models/User");
// ------------------------------------------------------------
// MARK: - PROPERTIES
// ------------------------------------------------------------
const accessTokenExpireTime = "5s";
const refreshTokenExpireTime = "10s";
// ------------------------------------------------------------
// MARK: - CLASS DECLARATION
// ------------------------------------------------------------
class TokenService {
    // ------------------------------
    // SET COOKIE HANDLER
    // ------------------------------
    static async setCookie(res, token, refreshToken) {
        res.cookie("jwt", token, {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        });
    }
    // ------------------------------
    // REMOVE COOKIE HANDLER
    // ------------------------------
    static async removeCookie(res) {
        await res.clearCookie("jwt", {
            httpOnly: true,
            sameSite: "None",
            secure: true
        });
        await res.clearCookie("refreshToken", {
            httpOnly: true,
            sameSite: "None",
            secure: true
        });
    }
    // ------------------------------
    // VERIFY TOKEN HANDLER
    // ------------------------------
    static async verifyTokenForReuse(res, refreshToken) {
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403);
                const foundUser = await User.findOne({
                    email: decoded.email
                });
                const contains = await containsValue(
                    foundUser.refreshToken,
                    refreshToken
                );
                if (contains)
                    deleteValue(foundUser.refreshToken, refreshToken);
            }
        );
    }
    // ------------------------------
    // SIGN ACCESS TOKEN HANDLER
    // ------------------------------
    static signAccessToken(user, name, role) {
        return jwt.sign(
            { email: user.email, name, role },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: accessTokenExpireTime }
        );
    }
    // ------------------------------
    // SIGN REFRESH TOKEN HANDLER
    // ------------------------------
    static signRefreshToken(user, name, role) {
        const t = jwt.sign(
            { email: user.email, name, role },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: refreshTokenExpireTime }
        );
        return t;
    }
}
// ------------------------------------------------------------
// MARK: - PRIVATE METHODS
// ------------------------------------------------------------
const containsValue = async (array, value) => {
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
// MARK: - MODULE EXPORT
// ------------------------------------------------------------
module.exports = TokenService;
