const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../models/User");
const mongoose = require("mongoose");
const authMiddleware = require('../middleware/auth');
const { jwtHelpers } = require('../config/jwt');
const {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendVerificationEmail,
  sendOtpEmail,
} = require("../utils/emailService");

const rateLimit = require("express-rate-limit");
const Joi = require('joi');

const validationSchemas = require('../utils/validationSchemas');
const validateRequest = require('../middleware/validateRequest');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { msg: "Too many login attempts, please try again later" }
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { msg: "Too many password reset requests, please try again later" }
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { msg: "Too many OTP verification attempts, please try again later" }
});

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

      const verificationToken = crypto.randomBytes(32).toString("hex");
      const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");

      const user = new User({
        name,
        email,
        password: hash,
        isVerified: false,
        verificationToken: hashedToken,
        verificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        refreshTokens: []
      });
      await user.save();

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
        return res.status(500).json({ msg: "Failed to send verification code" });
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
        createdAt: new Date()
      });
      
      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }
      
      await user.save();

      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000
      });
      
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh-token',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.json({
        user: { id: user._id, name: user.name, email: user.email },
        msg: "Authentication successful"
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
        return res.status(500).json({ msg: "Failed to send verification code" });
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
    
    const user = await User.findById(req.user.id).select("-password -refreshTokens");
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
        return res.json({ msg: "If your email is registered, you will receive a password reset link shortly" });
      }

      const resetToken = crypto.randomBytes(32).toString("hex");

      user.resetPasswordToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      user.resetPasswordExpires = Date.now() + 60 * 60 * 1000;

      await user.save();

      try {
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
        return res
          .status(500)
          .json({ msg: "Failed to send reset email" });
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

      const resetPasswordToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({ msg: "Invalid or expired reset token" });
      }

      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(password, salt);

      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);
      
      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date()
      });
      
      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }
      
      await user.save();
      
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000
      });
      
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh-token',
        maxAge: 7 * 24 * 60 * 60 * 1000 
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
    
    if (!originalToken || typeof originalToken !== 'string' || originalToken.length < 16) {
      return res.status(400).json({
        msg: "Invalid verification token format",
      });
    }

    const verificationToken = crypto
      .createHash("sha256")
      .update(originalToken)
      .digest("hex");

    const db = mongoose.connection.db;
    const verifiedTokens = db.collection("verifiedTokens");

    const tokenRecord = await verifiedTokens.findOne({ originalToken });

    if (tokenRecord) {
      const user = await User.findById(tokenRecord.userId);

      if (user) {
        const accessToken = jwtHelpers.generateAccessToken(user._id);
        const refreshToken = jwtHelpers.generateRefreshToken(user._id);
        
        user.refreshTokens = user.refreshTokens || [];
        user.refreshTokens.push({
          token: refreshToken,
          createdAt: new Date()
        });
        
        if (user.refreshTokens.length > 5) {
          user.refreshTokens = user.refreshTokens.slice(-5);
        }
        
        await user.save();
        
        res.cookie('accessToken', accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000
        });
        
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/api/auth/refresh-token',
          maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({
          msg: "Email already verified. You can now log in.",
          alreadyVerified: true,
          user: { id: user._id, name: user.name, email: user.email },
        });
      }
    }

    const user = await User.findOne({
      verificationToken,
    });

    if (!user) {
      const recentlyVerifiedUsers = await User.find({
        isVerified: true,
        verificationToken: { $exists: false },
      })
        .sort({ _id: -1 })
        .limit(5);

      if (recentlyVerifiedUsers.length > 0) {
        return res.status(400).json({
          msg: "This verification link has already been used. Please try logging in.",
          alreadyVerified: true,
        });
      }

      return res.status(400).json({
        msg: "Invalid verification token. Please sign up again.",
      });
    }

    if (user.isVerified) {
      const accessToken = jwtHelpers.generateAccessToken(user._id);
      const refreshToken = jwtHelpers.generateRefreshToken(user._id);
      
      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date()
      });
      
      if (user.refreshTokens.length > 5) {
        user.refreshTokens = user.refreshTokens.slice(-5);
      }
      
      await user.save();
      
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000
      });
      
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh-token',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      return res.json({
        msg: "Email already verified. You can now log in.",
        alreadyVerified: true,
        user: { id: user._id, name: user.name, email: user.email },
      });
    }

    if (user.verificationExpires && user.verificationExpires < Date.now()) {
      return res.status(400).json({
        msg: "Verification link has expired. Please request a new one.",
        expired: true,
      });
    }

    try {
      await verifiedTokens.insertOne({
        originalToken,
        hashedToken: verificationToken,
        userId: user._id,
        verifiedAt: new Date(),
      });
    } catch (err) {
      console.error("Failed to record verified token:", err);
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    
    const accessToken = jwtHelpers.generateAccessToken(user._id);
    const refreshToken = jwtHelpers.generateRefreshToken(user._id);
    
    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({
      token: refreshToken,
      createdAt: new Date()
    });
    
    await user.save();
    
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000
    });
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth/refresh-token',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    try {
      await sendWelcomeEmail(user.name, user.email);
    } catch (emailError) {
      console.error("Failed to send welcome email:", emailError);
    }

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

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh-token' });

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
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ msg: "Refresh token not found" });
    }
    
    const decoded = jwtHelpers.verifyToken(refreshToken);
    if (!decoded || decoded.type !== 'refresh') {
      return res.status(401).json({ msg: "Invalid refresh token" });
    }
    
    const user = await User.findOne({
      _id: decoded.id,
      'refreshTokens.token': refreshToken
    });
    
    if (!user) {
      return res.status(401).json({ msg: "Token not found or user doesn't exist" });
    }
    
    const newAccessToken = jwtHelpers.generateAccessToken(user._id);
    const newRefreshToken = jwtHelpers.generateRefreshToken(user._id);

    user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
    user.refreshTokens.push({
      token: newRefreshToken,
      createdAt: new Date()
    });
    
    await user.save();
    
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000
    });
    
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth/refresh-token',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.json({ msg: "Token refreshed successfully" });
  } catch (err) {
    console.error("Refresh token error:", err);
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
    
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh-token' });
    
    res.json({ msg: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;