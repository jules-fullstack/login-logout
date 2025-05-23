const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../models/User");
const Token = require("../models/Token");
const mongoose = require("mongoose");
const authMiddleware = require("../middleware/auth");
const { jwtHelpers } = require("../config/jwt");
const apiAuth = require("../middleware/apiAuth");
const {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendVerificationEmail,
  sendOtpEmail,
} = require("../utils/emailService");

const rateLimit = require("express-rate-limit");
const Joi = require("joi");

const validationSchemas = require("../utils/validationSchemas");
const validateRequest = require("../middleware/validateRequest");

class CustomMemoryStore {
  constructor() {
    this.hits = new Map();
  }

  init() {
    return Promise.resolve();
  }

  // Get hits for a key
  get(key) {
    return Promise.resolve({
      totalHits: this.hits.get(key) || 0,
      resetTime: Date.now() + 60 * 1000, // This can be any time in the future
    });
  }

  // Increment key hit count
  increment(key) {
    const current = this.hits.get(key) || 0;
    this.hits.set(key, current + 1);
    return Promise.resolve({
      totalHits: current + 1, // Include totalHits in the response
    });
  }

  // Decrement is optional but good to have
  decrement(key) {
    const current = this.hits.get(key) || 0;
    if (current > 0) {
      this.hits.set(key, current - 1);
    }
    return Promise.resolve({
      totalHits: Math.max(0, current - 1), // Return updated hits
    });
  }

  // Reset key hit count
  resetKey(key) {
    this.hits.delete(key);
    return Promise.resolve();
  }

  // Reset all keys
  resetAll() {
    this.hits.clear();
    return Promise.resolve();
  }
}

// Create store instances
const authLimitStore = new CustomMemoryStore();
const otpLimitStore = new CustomMemoryStore();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { msg: "Too many login attempts, please try again later" },
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { msg: "Too many password reset requests, please try again later" },
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: {
    msg: "Too many OTP verification attempts, please try again later",
  },
});

const resetUserRateLimits = (email, userId) => {
  if (email) authLimitStore.resetKey(email);
  if (userId) otpLimitStore.resetKey(userId);
};

router.post(
  "/signup",
  validateRequest(validationSchemas.signup),
  async (req, res) => {
    try {
      const { name, email, password } = req.body;
      if (await User.findOne({ email })) {
        return res.status(400).json({ msg: "User already exists" });
      }

      const salt = await bcrypt.genSalt(12);
      const hash = await bcrypt.hash(password, salt);

      // Create user first
      const user = new User({
        name,
        email,
        password: hash,
        isVerified: false,
        refreshTokens: [],
      });

      await user.save();

      // Generate verification token - use more entropy to avoid collisions
      const verificationToken = crypto.randomBytes(48).toString("hex");
      const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");

      // Delete any existing tokens for this user
      await Token.deleteMany({ userId: user._id, type: "emailVerification" });

      // Create new token with unique index
      try {
        const token = new Token({
          userId: user._id,
          token: hashedToken,
          type: "emailVerification",
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });

        await token.save();
      } catch (tokenError) {
        console.error("Token creation error:", tokenError);
        // If there's a duplicate token (extremely unlikely with proper entropy)
        // Generate a new one with even more entropy
        if (tokenError.code === 11000) {
          const retryToken = crypto.randomBytes(64).toString("hex");
          const hashedRetryToken = crypto
            .createHash("sha256")
            .update(retryToken)
            .digest("hex");

          const token = new Token({
            userId: user._id,
            token: hashedRetryToken,
            type: "emailVerification",
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
          });

          await token.save();

          // Update the verification token to use
          verificationToken = retryToken;
        } else {
          throw tokenError; // Re-throw if it's not a duplicate error
        }
      }

      // Send verification email
      const emailSent = await sendVerificationEmail(
        user.name,
        user.email,
        verificationToken
      );

      if (!emailSent) {
        return res
          .status(500)
          .json({ msg: "Failed to send verification email" });
      }

      res.status(201).json({
        success: true,
        msg: "User created. Please verify your email to complete registration.",
      });
    } catch (err) {
      console.error("Email verification error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post(
  "/login",
  validateRequest(validationSchemas.login),
  authLimiter,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ msg: "Invalid credentials" });

      if (!user.isVerified) {
        return res.status(401).json({
          msg: "Please verify your email before logging in",
          pendingVerification: true,
          email: user.email,
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

      user.otpCode = hashedOtp;
      user.otpExpires = Date.now() + 10 * 60 * 1000;
      await user.save();

      const emailSent = await sendOtpEmail(user.email, otp);

      if (!emailSent) {
        user.otpCode = undefined;
        user.otpExpires = undefined;
        await user.save();
        return res
          .status(500)
          .json({ msg: "Failed to send verification code" });
      }

      res.json({
        msg: "Verification code sent to your email",
        requiresOtp: true,
        userId: user._id,
      });
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).send("Server error");
    }
  }
);

router.post(
  "/verify-otp",
  validateRequest(validationSchemas.verifyOtp),
  otpLimiter,
  async (req, res) => {
    try {
      const { userId, otp } = req.body;

      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ msg: "Invalid user ID format" });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(400).json({ msg: "Invalid verification attempt" });
      }

      if (!user.otpCode || !user.otpExpires) {
        return res
          .status(400)
          .json({ msg: "Verification code has not been requested" });
      }

      if (user.otpExpires < Date.now()) {
        user.otpCode = undefined;
        user.otpExpires = undefined;
        await user.save();

        return res.status(400).json({ msg: "Verification code has expired" });
      }

      const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

      if (hashedOtp !== user.otpCode) {
        return res.status(400).json({ msg: "Invalid verification code" });
      }

      user.otpCode = undefined;
      user.otpExpires = undefined;

      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);

      user.refreshTokens = user.refreshTokens || [];

      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date(),
      });

      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }

      await user.save();

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        user: { id: user._id, name: user.name, email: user.email },
        msg: "Authentication successful",
      });
    } catch (err) {
      console.error("OTP verification error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post(
  "/resend-otp",
  validateRequest(validationSchemas.resendOtp),
  otpLimiter,
  async (req, res) => {
    try {
      const { userId } = req.body;

      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ msg: "Invalid user ID format" });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(400).json({ msg: "Invalid user" });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

      user.otpCode = hashedOtp;
      user.otpExpires = Date.now() + 10 * 60 * 1000;
      await user.save();

      const emailSent = await sendOtpEmail(user.email, otp);

      if (!emailSent) {
        user.otpCode = undefined;
        user.otpExpires = undefined;
        await user.save();
        return res
          .status(500)
          .json({ msg: "Failed to send verification code" });
      }

      res.json({
        msg: "Verification code resent successfully",
        email: user.email,
      });
    } catch (err) {
      console.error("Resend OTP error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.get("/user", authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
      return res.status(400).json({ msg: "Invalid user ID format" });
    }

    const user = await User.findById(req.user.id).select(
      "-password -refreshTokens"
    );
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

router.post(
  "/forgot-password",
  validateRequest(validationSchemas.forgotPassword),
  forgotPasswordLimiter,
  async (req, res) => {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.json({
          msg: "If your email is registered, you will receive a password reset link shortly",
        });
      }

      // Generate a random token
      const resetToken = crypto.randomBytes(32).toString("hex");

      // Hash the token for storage in the database
      const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      // Store the hashed token in the user document
      user.resetPasswordToken = hashedToken;
      user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour expiry

      await user.save();

      try {
        // Send the UNHASHED token to the user (this is what's in the email link)
        const emailSent = await sendPasswordResetEmail(user.email, resetToken);

        if (emailSent) {
          return res.json({ msg: "Password reset email sent" });
        } else {
          user.resetPasswordToken = undefined;
          user.resetPasswordExpires = undefined;
          await user.save();
          return res.status(500).json({ msg: "Failed to send reset email" });
        }
      } catch (emailError) {
        console.error("Email sending error:", emailError);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        return res.status(500).json({ msg: "Failed to send reset email" });
      }
    } catch (err) {
      console.error("Forgot password error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post(
  "/reset-password",
  validateRequest(validationSchemas.resetPassword),
  async (req, res) => {
    try {
      const { token, password } = req.body;

      // Hash the reset token to match how it's stored in the database
      const resetPasswordToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      // Check if token has been used before
      const usedToken = await Token.findOne({
        token: resetPasswordToken,
        type: "passwordReset",
      });

      if (usedToken) {
        return res
          .status(400)
          .json({ msg: "This reset link has already been used" });
      }

      // Find user with the hashed token
      const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({ msg: "Invalid or expired reset token" });
      }

      // Save this token as used before proceeding (use hashed token)
      await new Token({
        token: resetPasswordToken,
        type: "passwordReset",
        userId: user._id,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      }).save();

      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(password, salt);

      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);

      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date(),
      });

      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }

      await user.save();

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        msg: "Password reset successful",
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (err) {
      console.error("Reset password error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post(
  "/resend-verification",
  validateRequest(validationSchemas.resendVerification),
  async (req, res) => {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ msg: "User not found" });
      }

      if (user.isVerified) {
        return res.status(400).json({ msg: "Email already verified" });
      }

      const verificationToken = crypto.randomBytes(32).toString("hex");
      const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");
      user.verificationToken = hashedToken;
      user.verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await user.save();

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
        });
      }
    } catch (err) {
      console.error("Resend verification error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post("/verify-email/:token", async (req, res) => {
  try {
    const originalToken = req.params.token;
    // IMPORTANT: Remove this flag entirely, we won't use it
    // let welcomeEmailSent = false; // Flag to track if welcome email was sent

    if (
      !originalToken ||
      typeof originalToken !== "string" ||
      originalToken.length < 16
    ) {
      return res.status(400).json({
        msg: "Invalid verification token format",
      });
    }

    // Hash the token
    const hashedToken = crypto
      .createHash("sha256")
      .update(originalToken)
      .digest("hex");

    // First path: Check if token exists in Token collection
    const tokenDoc = await Token.findOne({
      token: hashedToken,
      type: "emailVerification",
    });

    if (tokenDoc) {
      const user = await User.findById(tokenDoc.userId);

      if (!user) {
        return res.status(400).json({
          msg: "User not found for this verification token.",
        });
      }

      // Handle already verified users
      if (user.isVerified) {
        // Generate authentication tokens for already verified users
        const accessToken = jwtHelpers.generateAccessToken(user._id);
        const refreshToken = jwtHelpers.generateRefreshToken(user._id);

        user.refreshTokens = user.refreshTokens || [];
        user.refreshTokens.push({
          token: refreshToken,
          createdAt: new Date(),
        });

        if (user.refreshTokens.length > 5) {
          user.refreshTokens = user.refreshTokens.slice(-5);
        }

        await user.save();

        res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          maxAge: 60 * 60 * 1000,
        });

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          path: "/",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({
          msg: "Email already verified. You are now logged in.",
          alreadyVerified: true,
          user: { id: user._id, name: user.name, email: user.email },
        });
      }

      // Mark user as verified if not already
      user.isVerified = true;
      await user.save();

      // Generate tokens for new verified user
      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);

      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date(),
      });

      await user.save();

      // Set cookies
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // **** KEEPING ONLY THIS WELCOME EMAIL CALL ****
      // Send welcome email only if this is a first-time verification
      try {
        await sendWelcomeEmail(user.name, user.email);
        // welcomeEmailSent = true; // Remove this line
      } catch (emailError) {
        console.error("Failed to send welcome email:", emailError);
      }

      return res.json({
        msg: "Email verification successful!",
        user: { id: user._id, name: user.name, email: user.email },
      });
    }

    // Second path: Check for tokens stored directly in the User model (legacy path)
    const user = await User.findOne({
      verificationToken: hashedToken,
    });

    if (!user) {
      return res.status(400).json({
        msg: "Invalid verification token. Please sign up again.",
      });
    }

    if (user.isVerified) {
      // Mark token as used even if user is already verified
      await new Token({
        token: originalToken,
        type: "verification",
        userId: user._id,
      }).save();

      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);

      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date(),
      });

      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }

      await user.save();

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return res.json({
        msg: "Email already verified. You are now logged in.",
        alreadyVerified: true,
        user: { id: user._id, name: user.name, email: user.email },
      });
    }

    // Save this token as used
    await new Token({
      token: originalToken,
      type: "verification",
      userId: user._id,
    }).save();

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;

    const accessToken = jwtHelpers.generateAccessToken(user._id);
    const refreshToken = jwtHelpers.generateRefreshToken(user._id);

    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({
      token: refreshToken,
      createdAt: new Date(),
    });

    await user.save();

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // **** COMPLETELY REMOVE THIS WELCOME EMAIL CALL ****
    // Do not add any welcome email sending code here

    return res.json({
      msg: "Email verification successful!",
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Email verification error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});

router.delete("/delete-account", authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
      return res.status(400).json({ msg: "Invalid user ID format" });
    }

    const user = await User.findByIdAndDelete(req.user.id);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken", { path: "/" });

    res.json({ msg: "Account successfully deleted" });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

router.put(
  "/update-name",
  authMiddleware,
  validateRequest(validationSchemas.updateName),
  async (req, res) => {
    try {
      const { name } = req.body;

      if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
        return res.status(400).json({ msg: "Invalid user ID format" });
      }

      const user = await User.findByIdAndUpdate(
        req.user.id,
        { $set: { name: name.trim() } },
        { new: true }
      ).select("-password -refreshTokens");

      if (!user) {
        return res.status(404).json({ msg: "User not found" });
      }

      res.json(user);
    } catch (err) {
      console.error("Update name error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.put(
  "/update-password",
  authMiddleware,
  validateRequest(validationSchemas.updatePassword),
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
        return res.status(400).json({ msg: "Invalid user ID format" });
      }

      const user = await User.findById(req.user.id);

      if (!user) {
        return res.status(404).json({ msg: "User not found" });
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: "Current password is incorrect" });
      }

      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(newPassword, salt);

      await user.save();

      res.json({ msg: "Password updated successfully" });
    } catch (err) {
      console.error("Update password error:", err);
      res.status(500).json({ msg: "Server error" });
    }
  }
);

router.post(
  "/validate-password",
  authMiddleware,
  validateRequest(validationSchemas.validatePassword),
  async (req, res) => {
    try {
      const { password } = req.body;

      if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
        return res.status(400).json({ msg: "Invalid user ID format" });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ msg: "User not found", valid: false });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        return res.json({ msg: "Password is valid", valid: true });
      } else {
        return res
          .status(400)
          .json({ msg: "Password is incorrect", valid: false });
      }
    } catch (err) {
      console.error("Password validation error:", err);
      res.status(500).json({ msg: "Server error", valid: false });
    }
  }
);

router.post("/refresh-token", async (req, res) => {
  try {
    console.log("⭐ Refresh token route called");
    console.log("⭐ Cookies received:", req.cookies);
    console.log("⭐ Cookie header:", req.headers.cookie);

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      console.log("❌ Refresh token not found in cookies");
      return res.status(401).json({ msg: "Refresh token not found" });
    }

    try {
      const decoded = jwtHelpers.verifyToken(refreshToken);
      console.log("✅ Refresh token decoded:", decoded);

      if (!decoded || decoded.type !== "refresh") {
        console.log("❌ Invalid refresh token type:", decoded?.type);
        return res.status(401).json({ msg: "Invalid refresh token" });
      }

      const user = await User.findOne({
        _id: decoded.id,
        "refreshTokens.token": refreshToken,
      });

      if (!user) {
        console.log("❌ User not found with token");
        return res
          .status(401)
          .json({ msg: "Token not found or user doesn't exist" });
      }

      console.log("✅ User found:", user._id);

      // Rest of your existing code for generating new tokens
      const newAccessToken = jwtHelpers.generateAccessToken(user._id);
      const newRefreshToken = jwtHelpers.generateRefreshToken(user._id);

      user.refreshTokens = user.refreshTokens.filter(
        (t) => t.token !== refreshToken
      );
      user.refreshTokens.push({
        token: newRefreshToken,
        createdAt: new Date(),
      });

      await user.save();

      res.cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      console.log("✅ New tokens generated and cookies set");
      res.json({ msg: "Token refreshed successfully" });
    } catch (tokenError) {
      console.error("❌ Token verification error:", tokenError);
      return res
        .status(401)
        .json({ msg: "Invalid refresh token: " + tokenError.message });
    }
  } catch (err) {
    console.error("❌ Refresh token route error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

router.post("/logout", authMiddleware, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      await User.updateOne(
        { _id: req.user.id },
        { $pull: { refreshTokens: { token: refreshToken } } }
      );
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken", { path: "/" });

    res.json({ msg: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

router.get("/check-auth-status", (req, res) => {
  try {
    const accessToken = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;

    let accessTokenStatus = "Invalid";
    let refreshTokenStatus = "Invalid";
    let accessTokenExpiry = null;
    let refreshTokenExpiry = null;

    if (accessToken) {
      try {
        const decoded = jwtHelpers.verifyToken(accessToken);
        accessTokenStatus = decoded ? "Valid" : "Invalid";
        if (decoded) {
          accessTokenExpiry = new Date(decoded.exp * 1000).toISOString();
        }
      } catch (err) {
        accessTokenStatus = "Invalid: " + err.message;
      }
    }

    if (refreshToken) {
      try {
        const decoded = jwtHelpers.verifyToken(refreshToken);
        refreshTokenStatus = decoded ? "Valid" : "Invalid";
        if (decoded) {
          refreshTokenExpiry = new Date(decoded.exp * 1000).toISOString();
        }
      } catch (err) {
        refreshTokenStatus = "Invalid: " + err.message;
      }
    }

    res.json({
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      accessTokenStatus,
      refreshTokenStatus,
      accessTokenExpiry,
      refreshTokenExpiry,
      cookieHeader: req.headers.cookie,
      rawCookies: req.cookies,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/test-cookies", (req, res) => {
  try {
    // Create test tokens
    const testAccessToken = jwtHelpers.generateAccessToken("test-user-id");
    const testRefreshToken = jwtHelpers.generateRefreshToken("test-user-id");

    // Set cookies
    res.cookie("accessToken", testAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    res.cookie("refreshToken", testRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      msg: "Test cookies set successfully",
      accessToken: testAccessToken,
      refreshToken: testRefreshToken,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
