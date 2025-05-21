const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");
const {
  sendPasswordResetEmail,
  sendWelcomeEmail,
} = require("../utils/emailService");

// POST /api/auth/signup
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // check if exists
    if (await User.findOne({ email })) {
      return res.status(400).json({ msg: "User already exists" });
    }
    // hash
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    // create
    const user = new User({ name, email, password: hash });
    await user.save();
    // sign
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Send welcome email
    try {
      await sendWelcomeEmail(user.name, user.email);
      console.log(`Welcome email sent to ${user.email}`);
    } catch (emailError) {
      console.error("Failed to send welcome email:", emailError);
      // Continue with signup process even if email fails
    }

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// GET /api/auth/user  (protected)
const authMiddleware = (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token) return res.status(401).json({ msg: "No token, auth denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ msg: "Token is not valid" });
  }
};
router.get("/user", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// POST /api/auth/forgot-password
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString("hex");

    // Hash token and set to resetPasswordToken field
    user.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Set expire time (1 hour)
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    // Save the user
    await user.save();

    try {
      // Send password reset email
      const emailSent = await sendPasswordResetEmail(user.email, resetToken);

      if (emailSent) {
        return res.json({ msg: "Password reset email sent" });
      } else {
        // Reset the token if email sending fails
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        return res.status(500).json({ msg: "Failed to send reset email" });
      }
    } catch (emailError) {
      console.error("Email sending error:", emailError);
      // Reset the token if email sending fails
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      return res
        .status(500)
        .json({ msg: "Failed to send reset email: " + emailError.message });
    }
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ msg: "Server error: " + err.message });
  }
});

// POST /api/auth/reset-password/:token
router.post("/reset-password/:token", async (req, res) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    // Find user with matching token and valid expiration
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ msg: "Invalid or expired token" });
    }

    // Set new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(req.body.password, salt);

    // Clear reset token fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // Save updated user
    await user.save();

    res.json({ msg: "Password has been reset" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// DELETE /api/auth/delete-account (protected)
router.delete("/delete-account", authMiddleware, async (req, res) => {
  try {
    // Find and delete the user
    const user = await User.findByIdAndDelete(req.user.id);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.json({ msg: "Account successfully deleted" });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
