require("dotenv").config();
const mongoose = require("mongoose");
const logger = require("../utils/logger");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 30000,
      heartbeatFrequencyMS: 10000,
      retryWrites: true,
      w: "majority",
    });

    logger.info(`MongoDB connected:${conn.connection.host}`);
  } catch (error) {
    logger.error(`Error:${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
