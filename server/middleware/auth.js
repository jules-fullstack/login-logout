const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  try {
    // Check for both cookie-based token and header-based token
    const accessToken = req.cookies.accessToken;
    const headerToken = req.header("x-auth-token");
    
    // Enhanced debugging
    console.log("[Auth Middleware] Cookies:", req.cookies);
    console.log("[Auth Middleware] Auth Header:", req.header("x-auth-token"));
    console.log("[Auth Middleware] Bearer Header:", req.header("Authorization"));
    
    let token = accessToken;
    
    // If no cookie token, check header token
    if (!token) {
      token = headerToken;
    }
    
    // Also check Authorization header (Bearer token)
    if (!token && req.header("Authorization")) {
      const authHeader = req.header("Authorization");
      if (authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7);
      }
    }
    
    if (!token) {
      return res.status(401).json({ msg: "No authentication token found" });
    }

    try {
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log("[Auth Middleware] Token decoded:", decoded);
      
      // Convert user ID to string for consistent format
      const userId = decoded.id || decoded.userId;
      
      // Add user info to request
      req.user = { id: String(userId) };
      next();
    } catch (tokenError) {
      console.error("[Auth Middleware] Token verification error:", tokenError);
      return res.status(401).json({ msg: "Token verification failed" });
    }
  } catch (err) {
    console.error("[Auth Middleware] General error:", err);
    res.status(401).json({ msg: "Authentication failed" });
  }
};