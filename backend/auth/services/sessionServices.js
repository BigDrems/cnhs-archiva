// sessionService.js
const crypto = require("crypto");
const { promisify } = require("util");

class SessionService {
  constructor(redisClient) {
    this.redis = redisClient;
    this.sessionPrefix = "session:";
    this.userSessionPrefix = "user_sessions:";
    this.sessionTimeout = process.env.SESSION_TIMEOUT || 3600; // 1 hour default
    this.maxSessions = process.env.MAX_SESSIONS_PER_USER || 5;
    this.cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: this.sessionTimeout * 1000,
      domain: process.env.COOKIE_DOMAIN || undefined,
    };
  }

  /**
   * Create a new session
   */
  async createSession(userId, additionalData = {}) {
    try {
      const sessionId = this.generateSessionId();
      const sessionData = {
        userId,
        sessionId,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        ipAddress: additionalData.ipAddress || null,
        userAgent: additionalData.userAgent || null,
        isActive: true,
        loginMethod: additionalData.loginMethod || "standard",
        deviceFingerprint: additionalData.deviceFingerprint || null,
        ...additionalData,
      };

      // Store session data
      await this.redis.setex(
        `${this.sessionPrefix}${sessionId}`,
        this.sessionTimeout,
        JSON.stringify(sessionData)
      );

      // Track user sessions for concurrent session management
      await this.addUserSession(userId, sessionId);

      // Enforce maximum sessions per user
      await this.enforceMaxSessions(userId);

      return {
        sessionId,
        expiresAt: new Date(Date.now() + this.sessionTimeout * 1000),
        cookieOptions: this.cookieOptions,
      };
    } catch (error) {
      throw new Error(`Session creation failed: ${error.message}`);
    }
  }

  /**
   * Get session data
   */
  async getSession(sessionId) {
    try {
      if (!sessionId) {
        throw new Error("Session ID is required");
      }

      const sessionData = await this.redis.get(
        `${this.sessionPrefix}${sessionId}`
      );

      if (!sessionData) {
        return null;
      }

      return JSON.parse(sessionData);
    } catch (error) {
      throw new Error(`Failed to retrieve session: ${error.message}`);
    }
  }

  /**
   * Update session activity
   */
  async updateSessionActivity(sessionId, additionalData = {}) {
    try {
      const session = await this.getSession(sessionId);

      if (!session) {
        throw new Error("Session not found");
      }

      const updatedSession = {
        ...session,
        lastActivity: new Date().toISOString(),
        ...additionalData,
      };

      // Extend session expiry
      await this.redis.setex(
        `${this.sessionPrefix}${sessionId}`,
        this.sessionTimeout,
        JSON.stringify(updatedSession)
      );

      return updatedSession;
    } catch (error) {
      throw new Error(`Failed to update session: ${error.message}`);
    }
  }

  /**
   * Validate session
   */
  async validateSession(sessionId) {
    try {
      const session = await this.getSession(sessionId);

      if (!session) {
        return { valid: false, reason: "Session not found" };
      }

      if (!session.isActive) {
        return { valid: false, reason: "Session is inactive" };
      }

      // Check for session timeout based on last activity
      const lastActivity = new Date(session.lastActivity);
      const now = new Date();
      const timeDiff = (now - lastActivity) / 1000; // seconds

      if (timeDiff > this.sessionTimeout) {
        await this.invalidateSession(sessionId);
        return { valid: false, reason: "Session expired due to inactivity" };
      }

      return { valid: true, session };
    } catch (error) {
      return { valid: false, reason: `Validation error: ${error.message}` };
    }
  }

  /**
   * Invalidate a specific session
   */
  async invalidateSession(sessionId) {
    try {
      const session = await this.getSession(sessionId);

      if (session) {
        // Remove from user's session list
        await this.removeUserSession(session.userId, sessionId);
      }

      // Remove session data
      await this.redis.del(`${this.sessionPrefix}${sessionId}`);

      return true;
    } catch (error) {
      throw new Error(`Failed to invalidate session: ${error.message}`);
    }
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateAllUserSessions(userId) {
    try {
      const sessionIds = await this.getUserSessions(userId);

      const pipeline = this.redis.pipeline();

      // Remove all session data
      sessionIds.forEach((sessionId) => {
        pipeline.del(`${this.sessionPrefix}${sessionId}`);
      });

      // Remove user session list
      pipeline.del(`${this.userSessionPrefix}${userId}`);

      await pipeline.exec();

      return sessionIds.length;
    } catch (error) {
      throw new Error(`Failed to invalidate user sessions: ${error.message}`);
    }
  }

  /**
   * Get all sessions for a user
   */
  async getUserSessions(userId) {
    try {
      const sessionIds = await this.redis.smembers(
        `${this.userSessionPrefix}${userId}`
      );
      const sessions = [];

      for (const sessionId of sessionIds) {
        const sessionData = await this.getSession(sessionId);
        if (sessionData) {
          sessions.push(sessionData);
        } else {
          // Clean up orphaned session reference
          await this.removeUserSession(userId, sessionId);
        }
      }

      return sessions;
    } catch (error) {
      throw new Error(`Failed to get user sessions: ${error.message}`);
    }
  }

  /**
   * Add session to user's session list
   */
  async addUserSession(userId, sessionId) {
    try {
      await this.redis.sadd(`${this.userSessionPrefix}${userId}`, sessionId);
      // Set expiry for user session list
      await this.redis.expire(
        `${this.userSessionPrefix}${userId}`,
        this.sessionTimeout * 2
      );
    } catch (error) {
      throw new Error(`Failed to add user session: ${error.message}`);
    }
  }

  /**
   * Remove session from user's session list
   */
  async removeUserSession(userId, sessionId) {
    try {
      await this.redis.srem(`${this.userSessionPrefix}${userId}`, sessionId);
    } catch (error) {
      throw new Error(`Failed to remove user session: ${error.message}`);
    }
  }

  /**
   * Enforce maximum sessions per user
   */
  async enforceMaxSessions(userId) {
    try {
      const sessionIds = await this.redis.smembers(
        `${this.userSessionPrefix}${userId}`
      );

      if (sessionIds.length > this.maxSessions) {
        // Get full session data to find oldest sessions
        const sessionsWithData = [];

        for (const sessionId of sessionIds) {
          const sessionData = await this.getSession(sessionId);
          if (sessionData) {
            sessionsWithData.push(sessionData);
          }
        }

        // Sort by creation time (oldest first)
        sessionsWithData.sort(
          (a, b) => new Date(a.createdAt) - new Date(b.createdAt)
        );

        // Remove excess sessions
        const sessionsToRemove = sessionsWithData.slice(
          0,
          sessionsWithData.length - this.maxSessions
        );

        for (const session of sessionsToRemove) {
          await this.invalidateSession(session.sessionId);
        }
      }
    } catch (error) {
      throw new Error(`Failed to enforce max sessions: ${error.message}`);
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions() {
    try {
      const pattern = `${this.sessionPrefix}*`;
      const keys = await this.redis.keys(pattern);
      let cleanedCount = 0;

      for (const key of keys) {
        const sessionData = await this.redis.get(key);
        if (sessionData) {
          const session = JSON.parse(sessionData);
          const lastActivity = new Date(session.lastActivity);
          const now = new Date();
          const timeDiff = (now - lastActivity) / 1000;

          if (timeDiff > this.sessionTimeout) {
            await this.invalidateSession(session.sessionId);
            cleanedCount++;
          }
        }
      }

      return cleanedCount;
    } catch (error) {
      throw new Error(`Session cleanup failed: ${error.message}`);
    }
  }

  /**
   * Generate secure session ID
   */
  generateSessionId() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Get session statistics
   */
  async getSessionStats(userId) {
    try {
      const sessions = await this.getUserSessions(userId);

      return {
        totalSessions: sessions.length,
        activeSessions: sessions.filter((s) => s.isActive).length,
        lastActivity: sessions.reduce((latest, session) => {
          const sessionTime = new Date(session.lastActivity);
          return sessionTime > latest ? sessionTime : latest;
        }, new Date(0)),
        devices: [
          ...new Set(sessions.map((s) => s.deviceFingerprint).filter(Boolean)),
        ].length,
      };
    } catch (error) {
      throw new Error(`Failed to get session stats: ${error.message}`);
    }
  }

  /**
   * Check for suspicious activity
   */
  async checkSuspiciousActivity(userId, currentSession) {
    try {
      const sessions = await this.getUserSessions(userId);
      const flags = [];

      // Check for multiple locations
      const locations = [
        ...new Set(sessions.map((s) => s.ipAddress).filter(Boolean)),
      ];
      if (locations.length > 3) {
        flags.push("multiple_locations");
      }

      // Check for rapid session creation
      const recentSessions = sessions.filter((s) => {
        const created = new Date(s.createdAt);
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        return created > fiveMinutesAgo;
      });

      if (recentSessions.length > 3) {
        flags.push("rapid_session_creation");
      }

      // Check for unusual user agent
      const userAgents = [
        ...new Set(sessions.map((s) => s.userAgent).filter(Boolean)),
      ];
      if (userAgents.length > 5) {
        flags.push("multiple_user_agents");
      }

      return {
        suspicious: flags.length > 0,
        flags,
        confidence: flags.length * 0.3, // Simple confidence score
      };
    } catch (error) {
      throw new Error(`Suspicious activity check failed: ${error.message}`);
    }
  }

  /**
   * Extend session expiry
   */
  async extendSession(sessionId, additionalTime = 3600) {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        throw new Error("Session not found");
      }

      const newExpiry = this.sessionTimeout + additionalTime;
      await this.redis.expire(`${this.sessionPrefix}${sessionId}`, newExpiry);

      return {
        sessionId,
        expiresAt: new Date(Date.now() + newExpiry * 1000),
      };
    } catch (error) {
      throw new Error(`Failed to extend session: ${error.message}`);
    }
  }
}

module.exports = SessionService;
