const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const compression = require("compression");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const rateLimit = require("express-rate-limit");

const logger = require("./utils/logger");
const errorHandler = require("./middleware/errorHandler");
const requestLogger = require("./middleware/requestLogger");

const authRoutes = require("./routes/authRoutes");
const studentRoutes = require("./routes/studentRoutess");
const documentRoutes = require("./routes/documentRoutes");
const requestRoutes = require("./routes/requestRoutes");

const app = express();
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);

const limiter = rateLimit({
  windowMS: 15 * 30 * 1000,
  max: 100,
});

app.use("/api/", limiter);

//Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

//Data Sanitization
app.use(mongoSanitize());
app.use(xss());

app.use(compression());

ap.use(requestLogger);

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "sucess",
    message: "API is healthy",
    Timestamp: new Date().toISOString,
  });
});

app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/students", studentRoutes);
app.use("/api/v1/documents", documentRoutes);
app.use("/api/v1/requests", requestRoutes);

app.all("*", (req, res, next) => {
  const error = new Error(`Route ${req.originalUrl} not found`);
  error.statusCode = 404;
  next(error);
});

app.use(errorHandler);
module.exports = app;
