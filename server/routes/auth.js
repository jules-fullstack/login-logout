const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");
const {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendVerificationEmail,
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

    // Generate verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(verificationToken)
      .digest("hex");

    // create unverified user
    const user = new User({
      name,
      email,
      password: hash,
      isVerified: false,
      verificationToken: hashedToken,
      verificationExpires: new Date(Date.now() + 86400000), // 24 hours
    });
    await user.save();

    // Send verification email
    try {
      const emailSent = await sendVerificationEmail(
        user.name,
        user.email,
        verificationToken
      );

      if (emailSent) {
        return res.json({
          msg: "Registration pending. Verification email sent.",
          email: user.email,
        });
      } else {
        return res
          .status(500)
          .json({ msg: "Failed to send verification email" });
      }
    } catch (emailError) {
      console.error("Failed to send verification email:", emailError);
      return res.status(500).json({
        msg: "Failed to send verification email",
        error: emailError.message,
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(401).json({
        msg: "Please verify your email before logging in",
        pendingVerification: true,
        email: user.email,
      });
    }

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

// POST /api/auth/resend-verification
router.post("/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    // Check if already verified
    if (user.isVerified) {
      return res.status(400).json({ msg: "Email already verified" });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(verificationToken)
      .digest("hex"); // Update user's verification token and expiry
    user.verificationToken = hashedToken;
    user.verificationExpires = new Date(Date.now() + 86400000); // 24 hours
    await user.save();

    // Send verification email
    try {
      const emailSent = await sendVerificationEmail(
        user.name,
        user.email,
        verificationToken
      );

      if (emailSent) {
        return res.json({ msg: "Verification email resent successfully" });
      } else {
        return res
          .status(500)
          .json({ msg: "Failed to resend verification email" });
      }
    } catch (emailError) {
      console.error("Failed to resend verification email:", emailError);
      return res.status(500).json({
        msg: "Failed to resend verification email",
        error: emailError.message,
      });
    }
  } catch (err) {
    console.error("Resend verification error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
  }
});

// POST /api/auth/verify-email/:token
router.post("/verify-email/:token", async (req, res) => {
  try {
    console.log(`Verifying token: ${req.params.token}`);

    // Get hashed token
    const verificationToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    console.log(`Hashed token: ${verificationToken}`); // Find user with matching token
    const user = await User.findOne({
      verificationToken,
    });

    if (!user) {
      console.log("No user found with matching token");
      console.log("Searched for token hash:", verificationToken);
      return res.status(400).json({
        msg: "Invalid verification token. Please sign up again.",
      });
    }

    console.log(`Found user: ${user.email}, isVerified: ${user.isVerified}`);
    console.log(`User verification token: ${user.verificationToken}`);
    console.log(
      `User verification expires: ${
        user.verificationExpires
          ? new Date(user.verificationExpires).toISOString()
          : "Not set"
      }`
    );
    console.log(`Current time: ${new Date().toISOString()}`);

    // Check if already verified
    if (user.isVerified) {
      console.log("User already verified");

      // Generate JWT token for automatic login
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      return res.json({
        msg: "Email already verified. You can now log in.",
        token,
        user: { id: user._id, name: user.name, email: user.email },
      });
    } // Check if token is expired
    if (user.verificationExpires && user.verificationExpires < Date.now()) {
      console.log("Token expired:", user.verificationExpires, Date.now());
      console.log(
        "Difference in milliseconds:",
        Date.now() - user.verificationExpires
      );
      console.log(
        "Expiration date:",
        new Date(user.verificationExpires).toISOString()
      );
      console.log("Current date:", new Date().toISOString());
      return res.status(400).json({
        msg: "Verification link has expired. Please request a new one.",
      });
    }

    // Update user verification status
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    console.log(`User ${user.email} verified successfully`);

    // Send welcome email after verification
    try {
      await sendWelcomeEmail(user.name, user.email);
      console.log(`Welcome email sent to ${user.email}`);
    } catch (emailError) {
      console.error("Failed to send welcome email:", emailError);
      // Continue with verification process even if welcome email fails
    }

    // Generate JWT token for automatic login
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      msg: "Email verification successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Email verification error:", err);
    res.status(500).json({ msg: "Server error", error: err.message });
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
