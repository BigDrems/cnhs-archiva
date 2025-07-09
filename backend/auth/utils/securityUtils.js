const logger = require("../../utils/logger");

/**
 * Validates that all required environment variables are present
 * @throws {Error} If any required environment variable is missing
 */
const validateEnvironment = () => {
  const requiredEnvVars = [
    "JWT_SECRET",
    "JWT_REFRESH_SECRET",
    "JWT_EXPIRES_IN",
    "JWT_COOKIE_EXPIRES_IN",
  ];

  const missingVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

  if (missingVars.length > 0) {
    const errorMessage = `Missing required environment variables: ${missingVars.join(
      ", "
    )}`;
    logger.error(errorMessage);
    throw new Error(errorMessage);
  }

  logger.info("Environment validation passed");
};

/**
 * Validates that JWT secrets meet minimum security requirements
 * @throws {Error} If secrets don't meet requirements
 */
const validateSecrets = () => {
  const minSecretLength = 32;

  if (process.env.JWT_SECRET.length < minSecretLength) {
    throw new Error(
      `JWT_SECRET must be at least ${minSecretLength} characters long`
    );
  }

  if (process.env.JWT_REFRESH_SECRET.length < minSecretLength) {
    throw new Error(
      `JWT_REFRESH_SECRET must be at least ${minSecretLength} characters long`
    );
  }

  // Ensure refresh secret is different from access secret
  if (process.env.JWT_SECRET === process.env.JWT_REFRESH_SECRET) {
    throw new Error("JWT_SECRET and JWT_REFRESH_SECRET must be different");
  }

  logger.info("Secret validation passed");
};

/**
 * Validates JWT expiration format
 * @throws {Error} If expiration format is invalid
 */
const validateExpirationFormats = () => {
  const validFormats = /^(\d+[smhd]|\d+)$/;

  if (!validFormats.test(process.env.JWT_EXPIRES_IN)) {
    throw new Error(
      'JWT_EXPIRES_IN must be in valid format (e.g., "15m", "1h", "7d")'
    );
  }

  if (!Number.isInteger(Number(process.env.JWT_COOKIE_EXPIRES_IN))) {
    throw new Error("JWT_COOKIE_EXPIRES_IN must be a valid number (days)");
  }

  logger.info("Expiration format validation passed");
};

/**
 * Initializes and validates all configuration
 */
const initializeConfig = () => {
  try {
    validateEnvironment();
    validateSecrets();
    validateExpirationFormats();
    logger.info("Authentication configuration initialized successfully");
  } catch (error) {
    logger.error("Configuration initialization failed:", error.message);
    process.exit(1);
  }
};

module.exports = {
  validateEnvironment,
  validateSecrets,
  validateExpirationFormats,
  initializeConfig,
};
