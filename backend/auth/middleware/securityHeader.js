const helmet = require("helmet");
const hpp = require("hpp");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss");

class SecurityHeaders {
  constructor(options = {}) {
    this.environment =
      options.environment || process.env.NODE_ENV || "development";
    this.trustedDomains = options.trustedDomains || [];
    this.apiBaseUrl =
      options.apiBaseUrl ||
      process.env.API_BASE_URL ||
      "https://api.example.com";
  }

  // Main security headers setup
  setupHelmet() {
    return helmet({
      // Enable most security headers
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: [
            "'self'",
            "'unsafe-inline'", // Required for some CSS frameworks
            "https://fonts.googleapis.com",
            "https://cdnjs.cloudflare.com",
          ],
          scriptSrc: [
            "'self'",
            "'unsafe-inline'", // Use with caution, better to use nonces
            "https://cdnjs.cloudflare.com",
            "https://apis.google.com",
          ],
          fontSrc: [
            "'self'",
            "https://fonts.gstatic.com",
            "https://cdnjs.cloudflare.com",
          ],
          imgSrc: ["'self'", "data:", "https:", "blob:"],
          connectSrc: ["'self'", this.apiBaseUrl, ...this.trustedDomains],
          mediaSrc: ["'self'", "blob:"],
          objectSrc: ["'none'"],
          frameSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          manifestSrc: ["'self'"],
        },
        reportOnly: this.environment === "development",
      },
      // Prevent clickjacking
      frameguard: {
        action: "deny",
      },
      // Remove X-Powered-By header
      hidePoweredBy: true,
      // Set X-Content-Type-Options to nosniff
      noSniff: true,
      // Set X-XSS-Protection
      xssFilter: true,
      // Set Referrer-Policy
      referrerPolicy: {
        policy: "strict-origin-when-cross-origin",
      },
      // HTTP Strict Transport Security (HSTS)
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      // Expect-CT header
      expectCt: {
        maxAge: 86400, // 24 hours
        enforce: this.environment === "production",
      },
      // Feature Policy/Permissions Policy
      permissionsPolicy: {
        camera: [],
        microphone: [],
        geolocation: [],
        browserPayment: [],
        usb: [],
        magnetometer: [],
        gyroscope: [],
        accelerometer: [],
        midi: [],
        autoplay: ["self"],
        fullscreen: ["self"],
      },
    });
  }

  // Custom CSP middleware for more control
  customCSP() {
    return (req, res, next) => {
      const nonce = this.generateNonce();
      res.locals.cspNonce = nonce;

      const cspPolicy = [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com`,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        "img-src 'self' data: https: blob:",
        `connect-src 'self' ${this.apiBaseUrl} ${this.trustedDomains.join(
          " "
        )}`,
        "media-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests",
      ].join("; ");

      res.setHeader("Content-Security-Policy", cspPolicy);
      next();
    };
  }

  // Generate nonce for CSP
  generateNonce() {
    return Buffer.from(require("crypto").randomBytes(16)).toString("base64");
  }

  // Additional security headers
  additionalHeaders() {
    return (req, res, next) => {
      // Custom security headers
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-XSS-Protection", "1; mode=block");
      res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
      res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
      res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
      res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

      // Remove server information
      res.removeHeader("Server");
      res.removeHeader("X-Powered-By");

      // Cache control for sensitive pages
      if (req.path.includes("/admin") || req.path.includes("/dashboard")) {
        res.setHeader(
          "Cache-Control",
          "no-cache, no-store, must-revalidate, private"
        );
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
      }

      next();
    };
  }

  // CORS configuration
  corsOptions() {
    return {
      origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        const allowedOrigins = [
          "http://localhost:3000",
          "http://localhost:5000",
          "https://yourdomain.com",
          "https://api.yourdomain.com",
          ...this.trustedDomains,
        ];

        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error("Not allowed by CORS"));
        }
      },
      credentials: true, // Allow cookies to be sent
      optionsSuccessStatus: 200, // Some legacy browsers choke on 204
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
      allowedHeaders: [
        "Origin",
        "X-Requested-With",
        "Content-Type",
        "Accept",
        "Authorization",
        "X-API-Key",
        "X-CSRF-Token",
      ],
      exposedHeaders: ["X-Total-Count", "X-Rate-Limit-Remaining"],
    };
  }

  // Data sanitization middleware
  sanitizeData() {
    return [
      // NoSQL injection prevention
      mongoSanitize({
        replaceWith: "_",
        onSanitize: ({ req, key }) => {
          console.warn(`Sanitized key: ${key} from ${req.ip}`);
        },
      }),

      // XSS prevention
      (req, res, next) => {
        if (req.body) {
          req.body = this.sanitizeObject(req.body);
        }
        if (req.query) {
          req.query = this.sanitizeObject(req.query);
        }
        if (req.params) {
          req.params = this.sanitizeObject(req.params);
        }
        next();
      },
    ];
  }

  // Sanitize object recursively
  sanitizeObject(obj) {
    if (typeof obj !== "object" || obj === null) {
      return typeof obj === "string" ? xss(obj) : obj;
    }

    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const cleanKey = xss(key);
        if (Array.isArray(obj[key])) {
          sanitized[cleanKey] = obj[key].map((item) =>
            this.sanitizeObject(item)
          );
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          sanitized[cleanKey] = this.sanitizeObject(obj[key]);
        } else {
          sanitized[cleanKey] =
            typeof obj[key] === "string" ? xss(obj[key]) : obj[key];
        }
      }
    }
    return sanitized;
  }

  // HTTP Parameter Pollution (HPP) protection
  hppProtection() {
    return hpp({
      whitelist: ["sort", "fields", "page", "limit", "filter"], // Allow these parameters to be arrays
    });
  }

  // Request size limiting
  requestSizeLimit() {
    return (req, res, next) => {
      const maxSize = 10 * 1024 * 1024; // 10MB default
      const contentLength = parseInt(req.headers["content-length"] || "0");

      if (contentLength > maxSize) {
        return res.status(413).json({
          status: "error",
          message: "Request entity too large",
        });
      }

      next();
    };
  }

  // IP validation middleware
  ipValidation() {
    return (req, res, next) => {
      const forbiddenIPs = (process.env.FORBIDDEN_IPS || "")
        .split(",")
        .filter((ip) => ip.trim());
      const allowedIPs = (process.env.ALLOWED_IPS || "")
        .split(",")
        .filter((ip) => ip.trim());

      if (forbiddenIPs.length > 0 && forbiddenIPs.includes(req.ip)) {
        return res.status(403).json({
          status: "error",
          message: "Forbidden",
        });
      }

      if (allowedIPs.length > 0 && !allowedIPs.includes(req.ip)) {
        return res.status(403).json({
          status: "error",
          message: "Forbidden",
        });
      }

      next();
    };
  }

  // Content type validation
  contentTypeValidation(
    allowedTypes = ["application/json", "multipart/form-data"]
  ) {
    return (req, res, next) => {
      if (
        req.method === "POST" ||
        req.method === "PUT" ||
        req.method === "PATCH"
      ) {
        const contentType = req.get("Content-Type");

        if (
          !contentType ||
          !allowedTypes.some((type) => contentType.includes(type))
        ) {
          return res.status(415).json({
            status: "error",
            message: "Unsupported Media Type",
          });
        }
      }
      next();
    };
  }

  // Security logging middleware
  securityLogger() {
    return (req, res, next) => {
      const startTime = Date.now();
      const originalSend = res.send;

      res.send = function (data) {
        const duration = Date.now() - startTime;
        const logData = {
          timestamp: new Date().toISOString(),
          method: req.method,
          url: req.originalUrl,
          ip: req.ip,
          userAgent: req.get("User-Agent"),
          statusCode: res.statusCode,
          duration: duration,
          size: Buffer.byteLength(data),
          referer: req.get("Referer") || "",
          userId: req.user?.id || "anonymous",
        };

        // Log suspicious activities
        if (res.statusCode >= 400 || duration > 5000) {
          console.warn("Security Alert:", logData);
        }

        // Log to file or external service in production
        if (process.env.NODE_ENV === "production") {
          // Example: winston.info(logData);
        }

        return originalSend.call(this, data);
      };

      next();
    };
  }

  // File upload security
  fileUploadSecurity() {
    return (req, res, next) => {
      if (req.files || req.file) {
        const files = req.files || [req.file];

        for (const file of files) {
          // Check file size (example: 5MB limit)
          if (file.size > 5 * 1024 * 1024) {
            return res.status(413).json({
              status: "error",
              message: "File too large",
            });
          }

          // Check file type
          const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
          ];
          if (!allowedTypes.includes(file.mimetype)) {
            return res.status(415).json({
              status: "error",
              message: "File type not allowed",
            });
          }

          // Check for malicious file names
          if (
            file.originalname.includes("..") ||
            file.originalname.includes("\\") ||
            file.originalname.includes("/")
          ) {
            return res.status(400).json({
              status: "error",
              message: "Invalid file name",
            });
          }

          // Check for executable extensions
          const dangerousExtensions = [
            ".exe",
            ".bat",
            ".cmd",
            ".com",
            ".pif",
            ".scr",
            ".vbs",
            ".js",
            ".jar",
            ".zip",
          ];
          const extension = file.originalname.toLowerCase().split(".").pop();
          if (dangerousExtensions.includes(`.${extension}`)) {
            return res.status(400).json({
              status: "error",
              message: "Dangerous file extension",
            });
          }
        }
      }
      next();
    };
  }

  // API key validation
  apiKeyValidation() {
    return (req, res, next) => {
      const apiKey = req.headers["x-api-key"];

      if (!apiKey) {
        return res.status(401).json({
          status: "error",
          message: "API key required",
        });
      }

      // Validate API key format (example: 32 character hex)
      if (!/^[a-f0-9]{32}$/i.test(apiKey)) {
        return res.status(401).json({
          status: "error",
          message: "Invalid API key format",
        });
      }

      // Check API key in database/cache
      // This is a placeholder - implement according to your storage
      if (!this.isValidApiKey(apiKey)) {
        return res.status(401).json({
          status: "error",
          message: "Invalid API key",
        });
      }

      next();
    };
  }

  // Placeholder for API key validation
  isValidApiKey(apiKey) {
    // Implement your API key validation logic here
    // Example: check against database, cache, or environment variables
    return process.env.VALID_API_KEYS?.split(",").includes(apiKey);
  }

  // Request timeout middleware
  requestTimeout(timeout = 30000) {
    return (req, res, next) => {
      const timer = setTimeout(() => {
        if (!res.headersSent) {
          res.status(408).json({
            status: "error",
            message: "Request timeout",
          });
        }
      }, timeout);

      const originalSend = res.send;
      res.send = function (data) {
        clearTimeout(timer);
        return originalSend.call(this, data);
      };

      const originalJson = res.json;
      res.json = function (data) {
        clearTimeout(timer);
        return originalJson.call(this, data);
      };

      next();
    };
  }

  // Security middleware composition
  getAllSecurityMiddleware() {
    return [
      this.setupHelmet(),
      this.additionalHeaders(),
      this.sanitizeData(),
      this.hppProtection(),
      this.requestSizeLimit(),
      this.ipValidation(),
      this.securityLogger(),
      this.requestTimeout(),
    ];
  }

  // Development-specific security (more lenient)
  getDevelopmentSecurity() {
    return [
      helmet({
        contentSecurityPolicy: false, // Disable CSP in development
        crossOriginEmbedderPolicy: false,
      }),
      this.additionalHeaders(),
      this.sanitizeData(),
      this.hppProtection(),
      this.requestSizeLimit(),
      this.securityLogger(),
    ];
  }

  // Production-specific security (strict)
  getProductionSecurity() {
    return [
      this.setupHelmet(),
      this.additionalHeaders(),
      this.sanitizeData(),
      this.hppProtection(),
      this.requestSizeLimit(),
      this.ipValidation(),
      this.securityLogger(),
      this.requestTimeout(15000), // Shorter timeout in production
    ];
  }

  // Emergency security lockdown
  emergencyLockdown() {
    return (req, res, next) => {
      // Only allow specific safe endpoints
      const allowedPaths = ["/health", "/status"];

      if (!allowedPaths.includes(req.path)) {
        return res.status(503).json({
          status: "error",
          message: "Service temporarily unavailable",
        });
      }

      next();
    };
  }

  // Admin-only security restrictions
  adminOnlyRestrictions() {
    return (req, res, next) => {
      // Additional checks for admin endpoints
      if (req.path.startsWith("/admin")) {
        // Check for admin-specific headers
        const adminToken = req.headers["x-admin-token"];
        if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
          return res.status(403).json({
            status: "error",
            message: "Admin access required",
          });
        }

        // Restrict to specific IP ranges for admin
        const adminIPs = (process.env.ADMIN_ALLOWED_IPS || "").split(",");
        if (adminIPs.length > 0 && !adminIPs.includes(req.ip)) {
          return res.status(403).json({
            status: "error",
            message: "Admin access not allowed from this IP",
          });
        }
      }

      next();
    };
  }
}

module.exports = SecurityHeaders;
