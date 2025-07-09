const logger = require("../../utils/logger");
const { validateIPAddress } = require("./securityUtils");

/**
 * Security event types
 */
const SecurityEvents = {
  SUCCESSFUL_LOGIN: "SUCCESSFUL_LOGIN",
  FAILED_LOGIN: "FAILED_LOGIN",
  UNAUTHORIZED_ACCESS: "UNAUTHORIZED_ACCESS",
  TOKEN_USER_NOT_FOUND: "TOKEN_USER_NOT_FOUND",
  INVALID_SESSION: "INVALID_SESSION",
  PASSWORD_CHANGED_AFTER_TOKEN: "PASSWORD_CHANGED_AFTER_TOKEN",
  ACCOUNT_LOCKED_ACCESS: "ACCOUNT_LOCKED_ACCESS",
  INACTIVE_USER_ACCESS: "INACTIVE_USER_ACCESS",
  UNAUTHORIZED_ROLE_ACCESS: "UNAUTHORIZED_ROLE_ACCESS",
  INVALID_REFRESH_TOKEN: "INVALID_REFRESH_TOKEN",
  SUCCESSFUL_LOGOUT: "SUCCESSFUL_LOGOUT",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  INVALID_TOKEN: "INVALID_TOKEN",
  BRUTE_FORCE_ATTEMPT: "BRUTE_FORCE_ATTEMPT",
  SUSPICIOUS_ACTIVITY: "SUSPICIOUS_ACTIVITY",
};

/**
 * Logs security events with standardized format
 * @param {string} event - Security event type
 * @param {string} userId - User ID (if available)
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent string
 * @param {Object} additionalData - Additional event data
 */
const logSecurityEvent = (
  event,
  userId = null,
  ip = null,
  userAgent = null,
  additionalData = {}
) => {
  try {
    // Validate inputs
    if (!event || typeof event !== "string") {
      logger.error("Invalid security event type provided");
      return;
    }

    // Sanitize IP address
    const sanitizedIP = validateIPAddress(ip) ? ip : "unknown";

    // Sanitize user agent
    const sanitizedUserAgent =
      userAgent && typeof userAgent === "string"
        ? userAgent.substring(0, 200) // Limit length
        : "unknown";

    // Create standardized log entry
    const logEntry = {
      type: "SECURITY_EVENT",
      event,
      userId: userId || "anonymous",
      ip: sanitizedIP,
      userAgent: sanitizedUserAgent,
      timestamp: new Date().toISOString(),
      severity: getSeverityLevel(event),
      ...additionalData,
    };

    // Log based on severity
    switch (logEntry.severity) {
      case "HIGH":
        logger.error("High Severity Security Event", logEntry);
        break;
      case "MEDIUM":
        logger.warn("Medium Severity Security Event", logEntry);
        break;
      case "LOW":
        logger.info("Low Severity Security Event", logEntry);
        break;
      default:
        logger.info("Security Event", logEntry);
    }

    // Alert on critical events
    if (shouldTriggerAlert(event)) {
      triggerSecurityAlert(logEntry);
    }
  } catch (error) {
    logger.error("Failed to log security event:", error);
  }
};

/**
 * Determines severity level based on event type
 * @param {string} event - Security event type
 * @returns {string} Severity level
 */
const getSeverityLevel = (event) => {
  const highSeverityEvents = [
    SecurityEvents.BRUTE_FORCE_ATTEMPT,
    SecurityEvents.SUSPICIOUS_ACTIVITY,
    SecurityEvents.ACCOUNT_LOCKED_ACCESS,
    SecurityEvents.INVALID_REFRESH_TOKEN,
  ];

  const mediumSeverityEvents = [
    SecurityEvents.FAILED_LOGIN,
    SecurityEvents.UNAUTHORIZED_ACCESS,
    SecurityEvents.UNAUTHORIZED_ROLE_ACCESS,
    SecurityEvents.INVALID_SESSION,
    SecurityEvents.PASSWORD_CHANGED_AFTER_TOKEN,
  ];

  if (highSeverityEvents.includes(event)) {
    return "HIGH";
  } else if (mediumSeverityEvents.includes(event)) {
    return "MEDIUM";
  } else {
    return "LOW";
  }
};

/**
 * Determines if event should trigger an alert
 * @param {string} event - Security event type
 * @returns {boolean} True if alert should be triggered
 */
const shouldTriggerAlert = (event) => {
  const alertEvents = [
    SecurityEvents.BRUTE_FORCE_ATTEMPT,
    SecurityEvents.SUSPICIOUS_ACTIVITY,
    SecurityEvents.ACCOUNT_LOCKED_ACCESS,
  ];

  return alertEvents.includes(event);
};

/**
 * Triggers security alert (placeholder for actual alerting system)
 * @param {Object} logEntry - Security log entry
 */
const triggerSecurityAlert = (logEntry) => {
  // In production, this would integrate with:
  // - Email alerts
  // - Slack notifications
  // - Security monitoring systems
  // - SIEM systems

  logger.error("SECURITY ALERT TRIGGERED", {
    alert: true,
    ...logEntry,
  });

  // TODO: Implement actual alerting mechanism
  // Example: emailService.sendAlert(logEntry);
  // Example: slackService.sendAlert(logEntry);
};

/**
 * Logs authentication failure with additional context
 * @param {string} userId - User ID
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent
 * @param {string} reason - Failure reason
 * @param {number} attemptCount - Number of attempts
 */
const logAuthenticationFailure = (
  userId,
  ip,
  userAgent,
  reason,
  attemptCount = 1
) => {
  logSecurityEvent(SecurityEvents.FAILED_LOGIN, userId, ip, userAgent, {
    reason,
    attemptCount,
    timestamp: new Date().toISOString(),
  });

  // Check for brute force pattern
  if (attemptCount >= 3) {
    logSecurityEvent(
      SecurityEvents.BRUTE_FORCE_ATTEMPT,
      userId,
      ip,
      userAgent,
      {
        attemptCount,
        reason: "Multiple failed login attempts detected",
      }
    );
  }
};

/**
 * Logs successful authentication
 * @param {string} userId - User ID
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent
 * @param {Object} additionalData - Additional login data
 */
const logSuccessfulAuthentication = (
  userId,
  ip,
  userAgent,
  additionalData = {}
) => {
  logSecurityEvent(SecurityEvents.SUCCESSFUL_LOGIN, userId, ip, userAgent, {
    ...additionalData,
    timestamp: new Date().toISOString(),
  });
};

module.exports = {
  SecurityEvents,
  logSecurityEvent,
  logAuthenticationFailure,
  logSuccessfulAuthentication,
  getSeverityLevel,
};
