const { jwtHelpers } = require('../config/jwt');

const authMiddleware = (req, res, next) => {
  const token = req.cookies.accessToken;
  
  const headerToken = req.header('x-auth-token');
  
  const accessToken = token || headerToken;
  
  if (!accessToken) {
    return res.status(401).json({ msg: "Authentication required" });
  }
  
  try {
    const decoded = jwtHelpers.verifyToken(accessToken);
    if (!decoded) {
      return res.status(401).json({ msg: "Token is not valid" });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ msg: "Token is not valid" });
  }
};

module.exports = authMiddleware;