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
  sendOtpEmail
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
    // Generate a 6-digit OTP code
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Hash the OTP for storage
    const hashedOtp = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");
    
    // Set OTP and expiration (10 minutes)
    user.otpCode = hashedOtp;
    user.otpExpires = Date.now() + 600000; // 10 minutes
    await user.save();

    // Send OTP email
    const emailSent = await sendOtpEmail(user.email, otp);
    
    if (!emailSent) {
      user.otpCode = undefined;
      user.otpExpires = undefined;
      await user.save();
      return res.status(500).json({ msg: "Failed to send verification code" });
    }

    // Return user ID for OTP verification step
    res.json({
      msg: "Verification code sent to your email",
      requiresOtp: true,
      userId: user._id
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error");
  }
});

router.post("/verify-otp", async (req, res) => {
  try {
    const { userId, otp } = req.body;

    // Find user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ msg: "Invalid verification attempt" });
    }

    // Verify OTP exists and hasn't expired
    if (!user.otpCode || !user.otpExpires) {
      return res.status(400).json({ msg: "Verification code has not been requested" });
    }

    if (user.otpExpires < Date.now()) {
      // Clear expired OTP
      user.otpCode = undefined;
      user.otpExpires = undefined;
      await user.save();
      
      return res.status(400).json({ msg: "Verification code has expired" });
    }

    // Hash the provided OTP to compare with stored hash
    const hashedOtp = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    // Check if OTP matches
    if (hashedOtp !== user.otpCode) {
      return res.status(400).json({ msg: "Invalid verification code" });
    }

    // Clear the OTP after successful verification
    user.otpCode = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Generate JWT token for authentication
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Return the token and user info
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("OTP verification error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// Add a route to resend OTP
router.post("/resend-otp", async (req, res) => {
  try {
    const { userId } = req.body;

    // Find user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ msg: "Invalid user" });
    }

    // Generate a new 6-digit OTP code
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Hash the OTP for storage
    const hashedOtp = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");
    
    // Set OTP and expiration (10 minutes)
    user.otpCode = hashedOtp;
    user.otpExpires = Date.now() + 600000; // 10 minutes
    await user.save();

    // Send OTP email
    const emailSent = await sendOtpEmail(user.email, otp);
    
    if (!emailSent) {
      user.otpCode = undefined;
      user.otpExpires = undefined;
      await user.save();
      return res.status(500).json({ msg: "Failed to send verification code" });
    }

    res.json({ 
      msg: "Verification code resent successfully",
      email: user.email
    });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ msg: "Server error" });
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

    // Store the original token for tracking
    const originalToken = req.params.token;
    
    // Get hashed token
    const verificationToken = crypto
      .createHash("sha256")
      .update(originalToken)
      .digest("hex");

    console.log(`Hashed token: ${verificationToken}`);
    
    // First, check if this token has already been used by checking for a verified user
    // We'll use a special collection to track used tokens
    const db = mongoose.connection.db;
    const verifiedTokens = db.collection('verifiedTokens');
    
    const tokenRecord = await verifiedTokens.findOne({ originalToken });
    
    if (tokenRecord) {
      console.log("Token was previously used successfully");
      // Find the user that was verified with this token
      const user = await User.findById(tokenRecord.userId);
      
      if (user) {
        // Generate JWT token for automatic login
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });
        
        return res.json({
          msg: "Email already verified. You can now log in.",
          alreadyVerified: true,
          token,
          user: { id: user._id, name: user.name, email: user.email },
        });
      }
    }
    
    // Find user with matching token
    const user = await User.findOne({
      verificationToken,
    });

    if (!user) {
      console.log("No user found with matching token");
      
      // Instead of showing an error, let's check if any recently verified users exist
      // that might have used this token before
      const recentlyVerifiedUsers = await User.find({
        isVerified: true,
        verificationToken: { $exists: false }
      }).sort({ _id: -1 }).limit(5);
      
      if (recentlyVerifiedUsers.length > 0) {
        return res.status(400).json({
          msg: "This verification link has already been used. Please try logging in.",
          alreadyVerified: true
        });
      }
      
      return res.status(400).json({
        msg: "Invalid verification token. Please sign up again.",
      });
    }

    console.log(`Found user: ${user.email}, isVerified: ${user.isVerified}`);

    // Check if already verified
    if (user.isVerified) {
      console.log("User already verified");

      // Generate JWT token for automatic login
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      return res.json({
        msg: "Email already verified. You can now log in.",
        alreadyVerified: true,
        token,
        user: { id: user._id, name: user.name, email: user.email },
      });
    }
    
    // Check if token is expired
    if (user.verificationExpires && user.verificationExpires < Date.now()) {
      console.log("Token expired");
      return res.status(400).json({
        msg: "Verification link has expired. Please request a new one.",
        expired: true
      });
    }

    // Store the original token in our tracking collection for future reference
    try {
      await verifiedTokens.insertOne({
        originalToken,
        hashedToken: verificationToken,
        userId: user._id,
        verifiedAt: new Date()
      });
    } catch (err) {
      console.log("Warning: Could not track verified token:", err.message);
      // Continue even if this fails
    }

    // Update user verification status
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    console.log(`User ${user.email} verified successfully`);

    // Send welcome email after verification - only once per user
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

    console.log("Sending successful response with token");
    
    return res.json({
      msg: "Email verification successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Email verification error:", err);
    return res.status(500).json({ msg: "Server error", error: err.message });
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
