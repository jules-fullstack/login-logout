const mongoose = require("mongoose");

const tokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User",
  },
  token: {
    type: String,
    required: true,
  },
  type: {
    type: String,
    required: true,
    enum: [
      "emailVerification",
      "passwordReset",
      "reset",
      "verification",
      "welcomeEmail",
    ],
  },
  expires: {
    type: Date,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 86400, // Automatically remove after 24 hours
  },
});

// Compound index for userId and type
tokenSchema.index({ userId: 1, type: 1 });

// Unique index for token
tokenSchema.index({ token: 1 }, { unique: true });

module.exports = mongoose.model("Token", tokenSchema);
