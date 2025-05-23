const jwt = require('jsonwebtoken');

const JWT_DEFAULTS = {
  accessTokenExpiry: '1h',
  refreshTokenExpiry: '7d'
};

const jwtConfig = {
  secret: process.env.JWT_SECRET,
  accessTokenExpiry: process.env.JWT_ACCESS_TOKEN_EXPIRY || JWT_DEFAULTS.accessTokenExpiry,
  refreshTokenExpiry: process.env.JWT_REFRESH_TOKEN_EXPIRY || JWT_DEFAULTS.refreshTokenExpiry
};

const jwtHelpers = {
  generateAccessToken: (userId) => {
    return jwt.sign({ id: userId }, jwtConfig.secret, {
      expiresIn: jwtConfig.accessTokenExpiry
    });
  },
  
  generateRefreshToken: (userId) => {
    return jwt.sign(
      { id: userId, type: 'refresh' },
      jwtConfig.secret,
      { expiresIn: jwtConfig.refreshTokenExpiry }
    );
  },

  generateApiToken: (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
},
  
  verifyToken: (token) => {
    try {
      return jwt.verify(token, jwtConfig.secret);
    } catch (error) {
      return null;
    }
  }
};

module.exports = { jwtConfig, jwtHelpers };