const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { jwtHelpers } = require("../config/jwt");
const apiAuth = require("../middleware/apiAuth");

// API Login route - returns JWT token
router.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ msg: "Please provide email and password" });
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return res.status(400).json({ 
        msg: "Please verify your email before logging in",
        pendingVerification: true,
        email: user.email
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwtHelpers.generateApiToken(user._id);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error("API login error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;