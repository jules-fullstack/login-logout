const jwt = require("jsonwebtoken");
const { jwtHelpers } = require("../config/jwt");

// API authentication middleware
const apiAuthMiddleware = (req, res, next) => {
  try {
    // Get token from multiple possible sources
    const authHeader = req.header("Authorization");
    const xAuthToken = req.header("x-auth-token");
    
    let token = null;
    
    // Check Authorization header (Bearer token)
    if (authHeader && authHeader.startsWith("Bearer ")) {
      // Extract token from Bearer format
      token = authHeader.split(" ")[1];
    }
    
    // If no Bearer token, check x-auth-token
    if (!token && xAuthToken) {
      token = xAuthToken;
    }
    
    // If still no token, check cookies
    if (!token && req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    
    if (!token) {
      return res.status(401).json({ msg: "No token, authorization denied" });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Handle different token formats (id or userId)
      const userId = decoded.id || decoded.userId;
      
      req.user = { id: String(userId) };
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