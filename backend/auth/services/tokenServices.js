const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

class TokenService {
  constructor() {
    // Use environment variables for secrets
    this.accessTokenSecret =
      process.env.JWT_ACCESS_SECRET || crypto.randomBytes(64).toString("hex");
    this.refreshTokenSecret =
      process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString("hex");
    this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRY || "15m";
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRY || "7d";
    this.issuer = process.env.JWT_ISSUER || "your-app-name";
    this.audience = process.env.JWT_AUDIENCE || "your-app-users";
  }

  /**
   * Generate access token with minimal payload
   */
  generateAccessToken(payload) {
    try {
      // Sanitize payload - only include necessary claims
      const sanitizedPayload = {
        userId: payload.userId,
        role: payload.role,
        permissions: payload.permissions || [],
        sessionId: payload.sessionId,
      };

      return jwt.sign(sanitizedPayload, this.accessTokenSecret, {
        expiresIn: this.accessTokenExpiry,
        issuer: this.issuer,
        audience: this.audience,
        algorithm: "HS256",
        jwtid: crypto.randomUUID(), // Unique token ID for tracking
      });
    } catch (error) {
      throw new Error(`Token generation failed: ${error.message}`);
    }
  }

  /**
   * Generate refresh token with minimal payload
   */
  generateRefreshToken(payload) {
    try {
      const refreshPayload = {
        userId: payload.userId,
        sessionId: payload.sessionId,
        tokenFamily: crypto.randomUUID(), // For refresh token rotation
      };

      return jwt.sign(refreshPayload, this.refreshTokenSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: this.issuer,
        audience: this.audience,
        algorithm: "HS256",
        jwtid: crypto.randomUUID(),
      });
    } catch (error) {
      throw new Error(`Refresh token generation failed: ${error.message}`);
    }
  }

  /**
   * Generate token pair (access + refresh)
   */
  generateTokenPair(payload) {
    const sessionId = crypto.randomUUID();
    const tokenPayload = { ...payload, sessionId };

    return {
      accessToken: this.generateAccessToken(tokenPayload),
      refreshToken: this.generateRefreshToken(tokenPayload),
      sessionId,
      expiresIn: this.accessTokenExpiry,
    };
  }

  /**
   * Verify access token
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, this.accessTokenSecret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["HS256"],
      });
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        throw new Error("Access token expired");
      }
      if (error.name === "JsonWebTokenError") {
        throw new Error("Invalid access token");
      }
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Verify refresh token
   */
  verifyRefreshToken(token) {
    try {
      return jwt.verify(token, this.refreshTokenSecret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["HS256"],
      });
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        throw new Error("Refresh token expired");
      }
      if (error.name === "JsonWebTokenError") {
        throw new Error("Invalid refresh token");
      }
      throw new Error(`Refresh token verification failed: ${error.message}`);
    }
  }

  /**
   * Decode token without verification (for extracting claims)
   */
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      throw new Error(`Token decode failed: ${error.message}`);
    }
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new Error("Invalid authorization header format");
    }
    return authHeader.substring(7);
  }

  /**
   * Get token expiration time
   */
  getTokenExpiration(token) {
    try {
      const decoded = this.decodeToken(token);
      return new Date(decoded.payload.exp * 1000);
    } catch (error) {
      throw new Error(`Cannot extract expiration: ${error.message}`);
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token) {
    try {
      const expiration = this.getTokenExpiration(token);
      return Date.now() >= expiration.getTime();
    } catch (error) {
      return true; // Treat invalid tokens as expired
    }
  }

  /**
   * Generate secure random token for password reset, etc.
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString("hex");
  }

  /**
   * Hash sensitive token for storage
   */
  async hashToken(token) {
    const saltRounds = 12;
    return await bcrypt.hash(token, saltRounds);
  }

  /**
   * Verify hashed token
   */
  async verifyHashedToken(token, hashedToken) {
    return await bcrypt.compare(token, hashedToken);
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Validate token structure without verification
   */
  isValidTokenStructure(token) {
    try {
      const parts = token.split(".");
      return parts.length === 3 && parts.every((part) => part.length > 0);
    } catch (error) {
      return false;
    }
  }

  /**
   * Get token claims safely
   */
  getTokenClaims(token) {
    try {
      const decoded = this.decodeToken(token);
      return decoded.payload;
    } catch (error) {
      return null;
    }
  }

  /**
   * Rotate refresh token (for enhanced security)
   */
  rotateRefreshToken(oldRefreshToken) {
    try {
      const decoded = this.verifyRefreshToken(oldRefreshToken);

      // Generate new refresh token with same user data but new family
      const newTokenPayload = {
        userId: decoded.userId,
        sessionId: decoded.sessionId,
        tokenFamily: crypto.randomUUID(),
      };

      return this.generateRefreshToken(newTokenPayload);
    } catch (error) {
      throw new Error(`Token rotation failed: ${error.message}`);
    }
  }
}

module.exports = new TokenService();
