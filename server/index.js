require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

// Verify required environment variables
const requiredEnvVars = [
  "MONGO_URI",
  "JWT_SECRET",
  "GMAIL_USER",
  "GMAIL_APP_PASSWORD",
  "CLIENT_URL",
];
const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.warn(
    `Warning: Missing environment variables: ${missingEnvVars.join(", ")}`
  );
  console.warn("Setting default CLIENT_URL to http://localhost:5173");
  // Set default value for CLIENT_URL if missing
  if (!process.env.CLIENT_URL) {
    process.env.CLIENT_URL = "http://localhost:5173";
  }
}

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", require("./routes/auth"));

// Connect DB & start
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB connected");
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error(err));
