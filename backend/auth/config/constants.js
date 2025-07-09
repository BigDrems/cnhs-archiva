module.exports = {
  // Security settings
  MAX_LOGIN_ATTEMPTS: 5,
  LOCK_TIME: 15 * 60 * 1000, // 15 minutes in milliseconds
  TOKEN_ISSUER: "your-app-name",
  AUDIENCE: "your-app-client",
  TOKEN_BLACKLIST_CACHE_SIZE: 10000,

  // Token settings
  REFRESH_TOKEN_EXPIRY: "7d",
  ACCESS_TOKEN_TYPE: "access",
  REFRESH_TOKEN_TYPE: "refresh",

  // Cookie settings
  COOKIE_SETTINGS: {
    httpOnly: true,
    sameSite: "strict",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  },

  // Rate limiting
  RATE_LIMIT: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: {
      error:
        "Too many authentication attempts from this IP, please try again later.",
    },
  },

  // Security headers
  SECURITY_HEADERS: {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
  },

  // Token validation
  TOKEN_VALIDATION: {
    MIN_LENGTH: 10,
    MAX_LENGTH: 2048,
    JWT_REGEX: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  },
};
