const jwt = require("jsonwebtoken");
const { jwtHelpers } = require("../config/jwt");

// API authentication middleware
const apiAuthMiddleware = (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.header("Authorization");
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ msg: "No token, authorization denied" });
    }
    
    // Extract token from Bearer format
    const token = authHeader.split(" ")[1];
    
    if (!token) {
      return res.status(401).json({ msg: "No token, authorization denied" });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { id: decoded.userId };
      next();
    } catch (err) {
      return res.status(401).json({ msg: "Token is not valid" });
    }
  } catch (err) {
    console.error("API auth error:", err);
    res.status(500).json({ msg: "Server error" });
  }
};

module.exports = apiAuthMiddleware;