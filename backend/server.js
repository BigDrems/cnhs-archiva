const connectDB = require("./config/db");
const logger = require("./utils/logger");
const app = require("./app");
const mongoose = require("mongoose");
const PORT = process.env.PORT || 3000;

connectDB();

const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received, starting graceful shutdown`);

  server.close(async () => {
    logger.info("HTTP server closed");

    try {
      await mongoose.connection.close();
      logger.info("Database connection closed");

      logger.info("Graceful shutdown complete");
      process.exit(0);
    } catch (error) {
      logger.error("Error during graceful shutdown", error);
      process.exit(1);
    }
  });

  setTimeout(() => {
    logger.error("Graceful shutdown timed out, forcing exit");
    process.exit(1);
  }, 10000);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("UNHANDLED_REJECTION");
});

module.exports = server;
