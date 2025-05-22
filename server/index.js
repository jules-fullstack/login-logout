require("dotenv").config();
const express = require("express");
const cookieParser = require('cookie-parser');
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require('helmet');
const securityHeaders = require('./middleware/securityHeaders');

const isDev = process.env.NODE_ENV !== 'production';

const requiredEnvVars = [
  "MONGO_URI",
  "JWT_SECRET",
  "GMAIL_USER",
  "GMAIL_APP_PASSWORD",
  "CLIENT_URL",
];
const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.warn(`Missing environment variables: ${missingEnvVars.join(", ")}`);

  if (!process.env.CLIENT_URL) {
    process.env.CLIENT_URL = "http://localhost:5173";
  }
}

const app = express();

app.use(express.json());
app.use(cookieParser());

const corsOptions = {
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-auth-token']
};

app.use(cors(corsOptions));

const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", process.env.CLIENT_URL || 'http://localhost:5173'],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isDev ? [] : [true],
      reportUri: '/api/csp-report'
    },
  },
  // Only enable HSTS in production
  hsts: isDev ? false : {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  // Other helmet options can be configured here
  xssFilter: true,
  noSniff: true,
  frameguard: { action: 'deny' }
};

// Apply Helmet with configuration
app.use(helmet(helmetConfig));

// Apply custom headers after Helmet
app.use(securityHeaders);

app.use("/api/auth", require("./routes/auth"));

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error("Database connection error"));
