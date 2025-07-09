// blacklistService.js
const crypto = require("crypto");

class BlacklistService {
  constructor(redisClient) {
    this.redis = redisClient;
    this.blacklistPrefix = "blacklist:";
    this.userBlacklistPrefix = "user_blacklist:";
    this.cleanupInterval = process.env.BLACKLIST_CLEANUP_INTERVAL || 3600000; // 1 hour
    this.maxBlacklistSize = process.env.MAX_BLACKLIST_SIZE || 100000;

    // Start cleanup routine
    this.startCleanupRoutine();
  }

  /**
   * Add token to blacklist
   */
  async addToBlacklist(token, reason = "revoked", expiresAt = null) {
    try {
      if (!token) {
        throw new Error("Token is required");
      }

      // Generate token hash for storage (more secure than storing raw token)
      const tokenHash = this.hashToken(token);

      // Extract token info
      const tokenInfo = this.extractTokenInfo(token);

      // Calculate expiry time
      const expiry = expiresAt || this.calculateExpiry(tokenInfo);

      const blacklistEntry = {
        tokenHash,
        userId: tokenInfo.userId,
        jti: tokenInfo.jti, // JWT ID
        reason,
        blacklistedAt: new Date().toISOString(),
        expiresAt: expiry.toISOString(),
        tokenType: tokenInfo.tokenType || "access",
      };

      // Store in main blacklist
      await this.redis.setex(
        `${this.blacklistPrefix}${tokenHash}`,
        this.getSecondsUntilExpiry(expiry),
        JSON.stringify(blacklistEntry)
      );

      // Add to user-specific blacklist for faster lookups
      if (tokenInfo.userId) {
        await this.redis.sadd(
          `${this.userBlacklistPrefix}${tokenInfo.userId}`,
          tokenHash
        );
        await this.redis.expire(
          `${this.userBlacklistPrefix}${tokenInfo.userId}`,
          this.getSecondsUntilExpiry(expiry)
        );
      }

      return {
        success: true,
        tokenHash,
        expiresAt: expiry,
      };
    } catch (error) {
      throw new Error(`Failed to blacklist token: ${error.message}`);
    }
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(token) {
    try {
      if (!token) {
        return false;
      }

      const tokenHash = this.hashToken(token);
      const blacklistEntry = await this.redis.get(
        `${this.blacklistPrefix}${tokenHash}`
      );

      if (!blacklistEntry) {
        return false;
      }

      const entry = JSON.parse(blacklistEntry);

      // Check if blacklist entry has expired
      if (new Date(entry.expiresAt) < new Date()) {
        await this.removeFromBlacklist(tokenHash);
        return false;
      }

      return {
        blacklisted: true,
        reason: entry.reason,
        blacklistedAt: entry.blacklistedAt,
        expiresAt: entry.expiresAt,
      };
    } catch (error) {
      // If there's an error checking blacklist, assume token is not blacklisted
      // but log the error for monitoring
      console.error("Blacklist check error:", error);
      return false;
    }
  }

  /**
   * Remove token from blacklist
   */
  async removeFromBlacklist(tokenOrHash) {
    try {
      const tokenHash = this.isValidHash(tokenOrHash)
        ? tokenOrHash
        : this.hashToken(tokenOrHash);

      // Get blacklist entry to extract user ID
      const blacklistEntry = await this.redis.get(
        `${this.blacklistPrefix}${tokenHash}`
      );

      if (blacklistEntry) {
        const entry = JSON.parse(blacklistEntry);

        // Remove from user-specific blacklist
        if (entry.userId) {
          await this.redis.srem(
            `${this.userBlacklistPrefix}${entry.userId}`,
            tokenHash
          );
        }
      }

      // Remove from main blacklist
      const result = await this.redis.del(
        `${this.blacklistPrefix}${tokenHash}`
      );

      return result > 0;
    } catch (error) {
      throw new Error(`Failed to remove from blacklist: ${error.message}`);
    }
  }

  /**
   * Blacklist all tokens for a user
   */
  async blacklistUserTokens(userId, reason = "user_logout") {
    try {
      const userTokens = await this.redis.smembers(
        `${this.userBlacklistPrefix}${userId}`
      );
      let blacklistedCount = 0;

      // This is a simplified approach - in production, you'd want to track active tokens
      // For now, we'll mark the user as having all tokens blacklisted
      const userBlacklistKey = `${this.userBlacklistPrefix}${userId}:all`;

      await this.redis.setex(
        userBlacklistKey,
        86400 * 7, // 7 days
        JSON.stringify({
          userId,
          allTokensBlacklisted: true,
          reason,
          blacklistedAt: new Date().toISOString(),
        })
      );

      return {
        success: true,
        blacklistedCount,
        userId,
      };
    } catch (error) {
      throw new Error(`Failed to blacklist user tokens: ${error.message}`);
    }
  }

  /**
   * Check if all user tokens are blacklisted
   */
  async areAllUserTokensBlacklisted(userId) {
    try {
      const userBlacklistKey = `${this.userBlacklistPrefix}${userId}:all`;
      const result = await this.redis.get(userBlacklistKey);

      if (!result) {
        return false;
      }

      const entry = JSON.parse(result);
      return {
        allBlacklisted: entry.allTokensBlacklisted,
        reason: entry.reason,
        blacklistedAt: entry.blacklistedAt,
      };
    } catch (error) {
      return false;
    }
  }

  /**
   * Get blacklist statistics
   */
  async getBlacklistStats() {
    try {
      const pattern = `${this.blacklistPrefix}*`;
      const keys = await this.redis.keys(pattern);

      const stats = {
        totalBlacklisted: 0,
        byReason: {},
        byUser: {},
        expired: 0,
      };

      for (const key of keys) {
        const entry = await this.redis.get(key);
        if (entry) {
          const data = JSON.parse(entry);
          stats.totalBlacklisted++;

          // Count by reason
          stats.byReason[data.reason] = (stats.byReason[data.reason] || 0) + 1;

          // Count by user
          if (data.userId) {
            stats.byUser[data.userId] = (stats.byUser[data.userId] || 0) + 1;
          }

          // Count expired
          if (new Date(data.expiresAt) < new Date()) {
            stats.expired++;
          }
        }
      }

      return stats;
    } catch (error) {
      throw new Error(`Failed to get blacklist stats: ${error.message}`);
    }
  }

  /**
   * Cleanup expired blacklist entries
   */
  async cleanupExpiredEntries() {
    try {
      const pattern = `${this.blacklistPrefix}*`;
      const keys = await this.redis.keys(pattern);
      let cleanedCount = 0;

      for (const key of keys) {
        const entry = await this.redis.get(key);
        if (entry) {
          const data = JSON.parse(entry);
          if (new Date(data.expiresAt) < new Date()) {
            await this.removeFromBlacklist(data.tokenHash);
            cleanedCount++;
          }
        }
      }

      return cleanedCount;
    } catch (error) {
      throw new Error(`Cleanup failed: ${error.message}`);
    }
  }

  /**
   * Get blacklisted tokens for a user
   */
  async getUserBlacklistedTokens(userId) {
    try {
      const tokenHashes = await this.redis.smembers(
        `${this.userBlacklistPrefix}${userId}`
      );
      const tokens = [];

      for (const tokenHash of tokenHashes) {
        const entry = await this.redis.get(
          `${this.blacklistPrefix}${tokenHash}`
        );
        if (entry) {
          const data = JSON.parse(entry);
          tokens.push({
            tokenHash,
            reason: data.reason,
            blacklistedAt: data.blacklistedAt,
            expiresAt: data.expiresAt,
          });
        }
      }

      return tokens;
    } catch (error) {
      throw new Error(
        `Failed to get user blacklisted tokens: ${error.message}`
      );
    }
  }

  /**
   * Check blacklist size and enforce limits
   */
  async enforceBlacklistSize() {
    try {
      const pattern = `${this.blacklistPrefix}*`;
      const keys = await this.redis.keys(pattern);

      if (keys.length > this.maxBlacklistSize) {
        // Remove oldest entries
        const entries = [];

        for (const key of keys) {
          const entry = await this.redis.get(key);
          if (entry) {
            const data = JSON.parse(entry);
            entries.push({
              key,
              blacklistedAt: new Date(data.blacklistedAt),
              tokenHash: data.tokenHash,
            });
          }
        }

        // Sort by blacklisted date (oldest first)
        entries.sort((a, b) => a.blacklistedAt - b.blacklistedAt);

        // Remove excess entries
        const toRemove = entries.slice(
          0,
          entries.length - this.maxBlacklistSize
        );

        for (const entry of toRemove) {
          await this.removeFromBlacklist(entry.tokenHash);
        }

        return toRemove.length;
      }

      return 0;
    } catch (error) {
      throw new Error(`Failed to enforce blacklist size: ${error.message}`);
    }
  }

  /**
   * Bulk blacklist tokens
   */
  async bulkBlacklistTokens(tokens, reason = "bulk_revoke") {
    try {
      const results = [];
      const pipeline = this.redis.pipeline();

      for (const token of tokens) {
        try {
          const tokenHash = this.hashToken(token);
          const tokenInfo = this.extractTokenInfo(token);
          const expiry = this.calculateExpiry(tokenInfo);

          const blacklistEntry = {
            tokenHash,
            userId: tokenInfo.userId,
            jti: tokenInfo.jti,
            reason,
            blacklistedAt: new Date().toISOString(),
            expiresAt: expiry.toISOString(),
            tokenType: tokenInfo.tokenType || "access",
          };

          pipeline.setex(
            `${this.blacklistPrefix}${tokenHash}`,
            this.getSecondsUntilExpiry(expiry),
            JSON.stringify(blacklistEntry)
          );

          if (tokenInfo.userId) {
            pipeline.sadd(
              `${this.userBlacklistPrefix}${tokenInfo.userId}`,
              tokenHash
            );
          }

          results.push({ success: true, tokenHash });
        } catch (error) {
          results.push({ success: false, error: error.message });
        }
      }

      await pipeline.exec();
      return results;
    } catch (error) {
      throw new Error(`Bulk blacklist failed: ${error.message}`);
    }
  }

  /**
   * Hash token for secure storage
   */
  hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  /**
   * Extract token information from JWT
   */
  extractTokenInfo(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("Invalid token format");
      }

      const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());

      return {
        userId: payload.userId || payload.sub,
        jti: payload.jti,
        exp: payload.exp,
        iat: payload.iat,
        tokenType: payload.type || "access",
      };
    } catch (error) {
      throw new Error(`Token parsing failed: ${error.message}`);
    }
  }

  /**
   * Calculate expiry time from token info
   */
  calculateExpiry(tokenInfo) {
    if (tokenInfo.exp) {
      return new Date(tokenInfo.exp * 1000);
    }

    // Default to 1 hour from now if no expiry
    return new Date(Date.now() + 3600000);
  }

  /**
   * Get seconds until expiry
   */
  getSecondsUntilExpiry(expiryDate) {
    return Math.max(1, Math.floor((expiryDate - new Date()) / 1000));
  }

  /**
   * Check if string is a valid hash
   */
  isValidHash(str) {
    return /^[a-f0-9]{64}$/.test(str);
  }

  /**
   * Start cleanup routine
   */
  startCleanupRoutine() {
    setInterval(async () => {
      try {
        await this.cleanupExpiredEntries();
        await this.enforceBlacklistSize();
      } catch (error) {
        console.error("Blacklist cleanup error:", error);
      }
    }, this.cleanupInterval);
  }

  /**
   * Stop cleanup routine (for testing or shutdown)
   */
  stopCleanupRoutine() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Emergency blacklist all tokens
   */
  async emergencyBlacklistAll(reason = "security_breach") {
    try {
      const emergencyKey = "emergency_blacklist:all";

      await this.redis.setex(
        emergencyKey,
        86400, // 24 hours
        JSON.stringify({
          allTokensBlacklisted: true,
          reason,
          activatedAt: new Date().toISOString(),
        })
      );

      return {
        success: true,
        message: "Emergency blacklist activated - all tokens will be rejected",
      };
    } catch (error) {
      throw new Error(`Emergency blacklist failed: ${error.message}`);
    }
  }

  /**
   * Check if emergency blacklist is active
   */
  async isEmergencyBlacklistActive() {
    try {
      const result = await this.redis.get("emergency_blacklist:all");
      return result ? JSON.parse(result) : false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Disable emergency blacklist
   */
  async disableEmergencyBlacklist() {
    try {
      await this.redis.del("emergency_blacklist:all");
      return { success: true, message: "Emergency blacklist disabled" };
    } catch (error) {
      throw new Error(
        `Failed to disable emergency blacklist: ${error.message}`
      );
    }
  }
}

module.exports = BlacklistService;
