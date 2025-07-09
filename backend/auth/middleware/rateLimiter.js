const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const RedisStore = require("rate-limit-redis");
const redis = require("redis");

class RateLimiter {
  constructor(options = {}) {
    this.redisClient = options.redisClient || this.createRedisClient();
    this.trustProxy = options.trustProxy || false;
  }

  createRedisClient() {
    if (process.env.REDIS_URL) {
      return redis.createClient({
        url: process.env.REDIS_URL,
        retry_strategy: (options) => {
          if (options.error && options.error.code === "ECONNREFUSED") {
            return new Error("Redis server refused connection");
          }
          if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error("Retry time exhausted");
          }
          if (options.attempt > 10) {
            return undefined;
          }
          return Math.min(options.attempt * 100, 3000);
        },
      });
    }
    return null;
  }

  // General rate limiter
  general(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "rate_limit:general:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 100, // limit each IP to 100 requests per windowMs
      message: {
        status: "error",
        message: "Too many requests from this IP, please try again later.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      skip: (req) => {
        // Skip rate limiting for certain IPs (whitelist)
        const whitelist = (process.env.RATE_LIMIT_WHITELIST || "").split(",");
        return whitelist.includes(req.ip);
      },
      keyGenerator: (req) => {
        // Use user ID if authenticated, otherwise use IP
        return req.user ? `user:${req.user.id}` : req.ip;
      },
    });
  }

  // Stricter rate limiter for sensitive endpoints
  strict(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "rate_limit:strict:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 5, // limit each IP to 5 requests per windowMs
      message: {
        status: "error",
        message:
          "Too many requests for this sensitive endpoint, please try again later.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      skipSuccessfulRequests: true,
      keyGenerator: (req) => (req.user ? `user:${req.user.id}` : req.ip),
    });
  }

  // Authentication rate limiter
  auth(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "rate_limit:auth:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 10, // limit each IP to 10 login attempts per windowMs
      message: {
        status: "error",
        message:
          "Too many login attempts from this IP, please try again after 15 minutes.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      skipSuccessfulRequests: true,
      keyGenerator: (req) => {
        // Use email or username if provided, otherwise use IP
        const identifier = req.body?.email || req.body?.username || req.ip;
        return `auth:${identifier}`;
      },
    });
  }

  // Password reset rate limiter
  passwordReset(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "rate_limit:password_reset:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 60 * 60 * 1000, // 1 hour
      max: options.max || 3, // limit each IP to 3 password reset requests per hour
      message: {
        status: "error",
        message:
          "Too many password reset requests, please try again after an hour.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      keyGenerator: (req) => `password_reset:${req.body?.email || req.ip}`,
    });
  }

  // API rate limiter with different tiers
  api(tier = "basic") {
    const configs = {
      basic: { windowMs: 60 * 1000, max: 20 }, // 20 requests per minute
      premium: { windowMs: 60 * 1000, max: 100 }, // 100 requests per minute
      enterprise: { windowMs: 60 * 1000, max: 1000 }, // 1000 requests per minute
    };

    const config = configs[tier] || configs.basic;
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: `rate_limit:api:${tier}:`,
        })
      : undefined;

    return rateLimit({
      windowMs: config.windowMs,
      max: config.max,
      message: {
        status: "error",
        message: `API rate limit exceeded for ${tier} tier. Please upgrade your plan or try again later.`,
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      keyGenerator: (req) => {
        // Use API key if available, otherwise use user ID or IP
        return (
          req.headers["x-api-key"] ||
          (req.user ? `user:${req.user.id}` : req.ip)
        );
      },
    });
  }

  // Slow down middleware for progressive delays
  slowDown(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "slow_down:",
        })
      : undefined;

    return slowDown({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      delayAfter: options.delayAfter || 50, // allow 50 requests per windowMs without delay
      delayMs: options.delayMs || 500, // add 500ms delay per request after delayAfter
      maxDelayMs: options.maxDelayMs || 20000, // max delay of 20 seconds
      store,
      keyGenerator: (req) => (req.user ? `user:${req.user.id}` : req.ip),
    });
  }

  // Dynamic rate limiter based on user role
  roleBasedLimiter(limits = {}) {
    const defaultLimits = {
      admin: { windowMs: 60 * 1000, max: 1000 },
      moderator: { windowMs: 60 * 1000, max: 200 },
      user: { windowMs: 60 * 1000, max: 50 },
      guest: { windowMs: 60 * 1000, max: 10 },
    };

    const combinedLimits = { ...defaultLimits, ...limits };

    return (req, res, next) => {
      const userRole = req.user?.role || "guest";
      const limit = combinedLimits[userRole] || combinedLimits.guest;

      const store = this.redisClient
        ? new RedisStore({
            client: this.redisClient,
            prefix: `rate_limit:role:${userRole}:`,
          })
        : undefined;

      const limiter = rateLimit({
        windowMs: limit.windowMs,
        max: limit.max,
        message: {
          status: "error",
          message: `Rate limit exceeded for ${userRole} role.`,
        },
        standardHeaders: true,
        legacyHeaders: false,
        store,
        keyGenerator: (req) => (req.user ? `user:${req.user.id}` : req.ip),
      });

      limiter(req, res, next);
    };
  }

  // Upload rate limiter
  upload(options = {}) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: "rate_limit:upload:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 60 * 60 * 1000, // 1 hour
      max: options.max || 10, // 10 uploads per hour
      message: {
        status: "error",
        message: "Upload rate limit exceeded, please try again later.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      keyGenerator: (req) => (req.user ? `user:${req.user.id}` : req.ip),
    });
  }

  // Create custom rate limiter
  custom(options) {
    const store = this.redisClient
      ? new RedisStore({
          client: this.redisClient,
          prefix: options.prefix || "rate_limit:custom:",
        })
      : undefined;

    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000,
      max: options.max || 100,
      message: options.message || {
        status: "error",
        message: "Rate limit exceeded.",
      },
      standardHeaders: true,
      legacyHeaders: false,
      store,
      keyGenerator: options.keyGenerator || ((req) => req.ip),
      skip: options.skip,
      skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    });
  }

  // Middleware to handle rate limit errors
  errorHandler() {
    return (err, req, res, next) => {
      if (err.status === 429) {
        return res.status(429).json({
          status: "error",
          message: "Too many requests, please try again later.",
          retryAfter: err.retryAfter,
        });
      }
      next(err);
    };
  }

  // Method to manually check rate limit
  async checkLimit(key, windowMs = 15 * 60 * 1000, max = 100) {
    if (!this.redisClient) {
      return { allowed: true, remaining: max };
    }

    const multi = this.redisClient.multi();
    const now = Date.now();
    const window = Math.floor(now / windowMs);
    const redisKey = `manual_limit:${key}:${window}`;

    multi.incr(redisKey);
    multi.expire(redisKey, Math.ceil(windowMs / 1000));

    const results = await multi.exec();
    const count = results[0][1];

    return {
      allowed: count <= max,
      remaining: Math.max(0, max - count),
      resetTime: (window + 1) * windowMs,
    };
  }
}

module.exports = RateLimiter;
