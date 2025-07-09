const { COOKIE_SETTINGS } = require("../config/constants");

/**
 * Cookie utility class for handling authentication cookies
 */
class CookieUtils {
  /**
   * Gets secure cookie options based on request and environment
   * @param {Object} req - Express request object
   * @param {Object} customOptions - Custom cookie options
   * @returns {Object} Secure cookie options
   */
  static getSecureCookieOptions(req, customOptions = {}) {
    const baseOptions = {
      ...COOKIE_SETTINGS,
      secure: req.secure || req.headers["x-forwarded-proto"] === "https",
      domain: process.env.COOKIE_DOMAIN || undefined,
    };

    // In development, allow non-secure cookies
    if (process.env.NODE_ENV === "development") {
      baseOptions.secure = false;
    }

    return {
      ...baseOptions,
      ...customOptions,
    };
  }

  /**
   * Sets authentication cookies with proper security settings
   * @param {Object} res - Express response object
   * @param {string} accessToken - Access token
   * @param {string} refreshToken - Refresh token
   * @param {Object} req - Express request object
   */
  static setAuthCookies(res, accessToken, refreshToken, req) {
    try {
      // Access token cookie (shorter expiration)
      const accessTokenExpires = new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
      );

      // Refresh token cookie (longer expiration)
      const refreshTokenExpires = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
      );

      // Set access token cookie
      res.cookie("access_token", accessToken, {
        ...this.getSecureCookieOptions(req),
        expires: accessTokenExpires,
        maxAge: process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
      });

      // Set refresh token cookie
      res.cookie("refresh_token", refreshToken, {
        ...this.getSecureCookieOptions(req),
        expires: refreshTokenExpires,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Set additional security cookie to track authentication state
      res.cookie("auth_state", "authenticated", {
        ...this.getSecureCookieOptions(req),
        expires: accessTokenExpires,
        httpOnly: false, // This can be read by frontend for UI state
      });
    } catch (error) {
      throw new Error(`Failed to set authentication cookies: ${error.message}`);
    }
  }

  /**
   * Clears all authentication cookies
   * @param {Object} res - Express response object
   */
  static clearAuthCookies(res) {
    try {
      const clearOptions = {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        domain: process.env.COOKIE_DOMAIN || undefined,
      };

      // Clear all authentication-related cookies
      res.clearCookie("access_token", clearOptions);
      res.clearCookie("refresh_token", clearOptions);
      res.clearCookie("auth_state", { ...clearOptions, httpOnly: false });
    } catch (error) {
      throw new Error(
        `Failed to clear authentication cookies: ${error.message}`
      );
    }
  }

  /**
   * Extracts token from request (cookies or headers)
   * @param {Object} req - Express request object
   * @param {string} tokenType - Type of token ('access' or 'refresh')
   * @returns {string|null} Token string or null if not found
   */
  static extractToken(req, tokenType = "access") {
    try {
      let token = null;

      // Check Authorization header first (Bearer token)
      if (
        tokenType === "access" &&
        req.headers.authorization?.startsWith("Bearer ")
      ) {
        token = req.headers.authorization.split(" ")[1];
      }

      // Check cookies
      if (!token) {
        const cookieName =
          tokenType === "access" ? "access_token" : "refresh_token";
        token = req.cookies[cookieName];
      }

      return token || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Validates cookie security settings
   * @param {Object} req - Express request object
   * @returns {boolean} True if cookies can be set securely
   */
  static validateCookieSecurity(req) {
    // In production, ensure HTTPS is used
    if (process.env.NODE_ENV === "production") {
      return req.secure || req.headers["x-forwarded-proto"] === "https";
    }

    // In development, allow non-secure cookies
    return true;
  }

  /**
   * Gets cookie expiration time
   * @param {string} tokenType - Type of token ('access' or 'refresh')
   * @returns {Date} Expiration date
   */
  static getCookieExpiration(tokenType = "access") {
    if (tokenType === "refresh") {
      return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    }

    return new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    );
  }

  /**
   * Sets a temporary cookie (for CSRF protection or similar)
   * @param {Object} res - Express response object
   * @param {string} name - Cookie name
   * @param {string} value - Cookie value
   * @param {Object} req - Express request object
   * @param {number} expirationMinutes - Expiration in minutes
   */
  static setTemporaryCookie(res, name, value, req, expirationMinutes = 15) {
    try {
      const expires = new Date(Date.now() + expirationMinutes * 60 * 1000);

      res.cookie(name, value, {
        ...this.getSecureCookieOptions(req),
        expires,
        maxAge: expirationMinutes * 60 * 1000,
      });
    } catch (error) {
      throw new Error(`Failed to set temporary cookie: ${error.message}`);
    }
  }
}

module.exports = CookieUtils;
