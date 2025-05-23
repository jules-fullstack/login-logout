const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  try {
    // Enhanced debugging
    console.log("[Auth Middleware] Cookies:", req.cookies);
    
    const accessToken = req.cookies.accessToken;
    
    if (!accessToken) {
      return res.status(401).json({ msg: "No access token found in cookies" });
    }

    try {
      // Verify the token
      const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
      console.log("[Auth Middleware] Token decoded:", decoded);
      
      // Add user info to request
      req.user = { id: decoded.id };
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