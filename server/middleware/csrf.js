const Tokens = require('csrf');
const tokens = new Tokens();

// Generate a secret to be stored in the session/cookie
const generateSecret = () => {
  return tokens.secretSync();
};

// Generate a token from the secret
const generateToken = (secret) => {
  return tokens.create(secret);
};

// Verify a token against a secret
const verifyToken = (secret, token) => {
  return tokens.verify(secret, token);
};

// Middleware to initialize CSRF protection
const csrfProtection = (options = {}) => {
  const {
    cookieName = '_csrf',
    headerName = 'x-csrf-token',
    cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    ignoreMethods = ['GET', 'HEAD', 'OPTIONS']
  } = options;

  return (req, res, next) => {
    // Skip for certain methods that don't modify state
    if (ignoreMethods.includes(req.method) || req.skipCsrf) {
      return next();
    }

    // Get secret from cookie
    let secret = req.cookies[cookieName];
    
    // If no secret exists, this is likely their first request
    if (!secret) {
      // Don't enforce CSRF on the first request, but set up for future requests
      secret = generateSecret();
      res.cookie(cookieName, secret, cookieOptions);
      return next();
    }

    // Get token from header
    const token = req.headers[headerName.toLowerCase()] || 
                 (req.body && req.body._csrf);

    // Verify the token
    if (!token || !verifyToken(secret, token)) {
      return res.status(403).json({
        msg: 'Invalid CSRF token. Please refresh the page and try again.'
      });
    }

    // Store verified token status
    req.csrfVerified = true;
    next();
  };
};

// Middleware to create and send a CSRF token
const csrfToken = (options = {}) => {
  const {
    cookieName = '_csrf'
  } = options;

  return (req, res, next) => {
    // Get existing secret or create a new one
    let secret = req.cookies[cookieName];
    
    if (!secret) {
      secret = generateSecret();
      res.cookie(cookieName, secret, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
    }

    // Add a method to generate tokens from this secret
    req.csrfToken = () => {
      return generateToken(secret);
    };

    next();
  };
};

// Helper middleware to skip CSRF for specific routes
const skipCsrf = (req, res, next) => {
  req.skipCsrf = true;
  next();
};

module.exports = {
  csrfProtection,
  csrfToken,
  skipCsrf
};