const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const crypto = require("crypto");

class AuthMiddleware {
  constructor(options = {}) {
    this.jwtSecret = options.jwtSecret || process.env.JWT_SECRET;
    this.jwtExpiry = options.jwtExpiry || process.env.JWT_EXPIRES_IN || "7d";
    this.cookieName = options.cookieName || "jwt";
    this.refreshTokenSecret =
      options.refreshTokenSecret || process.env.REFRESH_TOKEN_SECRET;

    if (!this.jwtSecret) {
      throw new Error("JWT secret is required");
    }
  }

  // Generate JWT token
  generateToken(userId, expiresIn = this.jwtExpiry) {
    return jwt.sign({ id: userId }, this.jwtSecret, { expiresIn });
  }

  // Generate refresh token
  generateRefreshToken() {
    return crypto.randomBytes(64).toString("hex");
  }

  // Verify JWT token
  async verifyToken(token) {
    try {
      const decoded = await promisify(jwt.verify)(token, this.jwtSecret);
      return decoded;
    } catch (error) {
      throw new Error("Invalid token");
    }
  }

  // Extract token from request
  extractToken(req) {
    let token;

    // Check Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer ")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }
    // Check cookie
    else if (req.cookies && req.cookies[this.cookieName]) {
      token = req.cookies[this.cookieName];
    }
    // Check query parameter (less secure, use with caution)
    else if (req.query && req.query.token) {
      token = req.query.token;
    }

    return token;
  }

  // Main authentication middleware
  protect = async (req, res, next) => {
    try {
      // 1. Extract token
      const token = this.extractToken(req);

      if (!token) {
        return res.status(401).json({
          status: "fail",
          message:
            "You are not logged in. Please log in to access this resource.",
        });
      }

      // 2. Verify token
      const decoded = await this.verifyToken(token);

      // 3. Check if user still exists (implement based on your user model)
      const user = await this.getUserById(decoded.id);
      if (!user) {
        return res.status(401).json({
          status: "fail",
          message: "The user belonging to this token no longer exists.",
        });
      }

      // 4. Check if user changed password after token was issued
      if (this.changedPasswordAfter(user, decoded.iat)) {
        return res.status(401).json({
          status: "fail",
          message: "User recently changed password. Please log in again.",
        });
      }

      // 5. Check if user is active
      if (!user.active) {
        return res.status(401).json({
          status: "fail",
          message: "Your account has been deactivated. Please contact support.",
        });
      }

      // 6. Set user in request object
      req.user = user;
      next();
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({
          status: "fail",
          message: "Invalid token. Please log in again.",
        });
      } else if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          status: "fail",
          message: "Token has expired. Please log in again.",
        });
      }

      return res.status(500).json({
        status: "error",
        message: "Authentication failed",
        error:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      });
    }
  };

  // Role-based access control
  restrictTo = (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          status: "fail",
          message: "You are not logged in.",
        });
      }

      if (!roles.includes(req.user.role)) {
        return res.status(403).json({
          status: "fail",
          message: "You do not have permission to perform this action.",
        });
      }

      next();
    };
  };

  // Optional authentication (doesn't fail if no token)
  optionalAuth = async (req, res, next) => {
    try {
      const token = this.extractToken(req);

      if (token) {
        const decoded = await this.verifyToken(token);
        const user = await this.getUserById(decoded.id);

        if (
          user &&
          user.active &&
          !this.changedPasswordAfter(user, decoded.iat)
        ) {
          req.user = user;
        }
      }
    } catch (error) {
      // Silent failure for optional auth
    }

    next();
  };

  // Check if user is owner of resource
  checkOwnership = (getResourceUserId) => {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            status: "fail",
            message: "You are not logged in.",
          });
        }

        const resourceUserId = await getResourceUserId(req);

        if (req.user.id !== resourceUserId && req.user.role !== "admin") {
          return res.status(403).json({
            status: "fail",
            message: "You can only access your own resources.",
          });
        }

        next();
      } catch (error) {
        return res.status(500).json({
          status: "error",
          message: "Failed to check ownership",
          error:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        });
      }
    };
  };

  // Helper methods (implement based on your user model)
  async getUserById(id) {
    // Implement based on your database/user model
    // Example with mongoose:
    // return await User.findById(id);
    throw new Error("getUserById method must be implemented");
  }

  changedPasswordAfter(user, jwtTimestamp) {
    // Check if user changed password after JWT was issued
    if (user.passwordChangedAt) {
      const changedTimestamp = parseInt(
        user.passwordChangedAt.getTime() / 1000,
        10
      );
      return jwtTimestamp < changedTimestamp;
    }
    return false;
  }

  // Method to invalidate token (logout)
  invalidateToken = (req, res, next) => {
    res.cookie(this.cookieName, "logged-out", {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    next();
  };

  // Session-based authentication cleanup
  destroySession = (req, res, next) => {
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({
            status: "error",
            message: "Failed to destroy session",
          });
        }
        res.clearCookie("connect.sid");
        next();
      });
    } else {
      next();
    }
  };
}

module.exports = AuthMiddleware;
