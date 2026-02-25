/**
 * Authentication Middleware
 * 
 * Validates JWT tokens on all protected routes.
 * Handles token refresh, session management, and auth failure logging.
 */

const jwt = require('jsonwebtoken');
const logger = require('./logger');

// Configuration
const JWT_CONFIG = {
  algorithm: 'HS256',
  expiresIn: '15m',          // 15-minute access tokens
  refreshExpiresIn: '7d',    // 7-day refresh tokens
  issuer: process.env.JWT_ISSUER || 'openclaw-security',
  audience: 'openclaw-api',
};

// In-memory token blacklist (use Redis in production)
const tokenBlacklist = new Set();

/**
 * Generate JWT token
 */
function generateToken(userId, role, expiresIn = JWT_CONFIG.expiresIn) {
  const payload = {
    userId,
    role,
    iat: Math.floor(Date.now() / 1000),
  };

  return jwt.sign(payload, process.env.JWT_SECRET, {
    algorithm: JWT_CONFIG.algorithm,
    expiresIn,
    issuer: JWT_CONFIG.issuer,
    audience: JWT_CONFIG.audience,
  });
}

/**
 * Generate token pair (access + refresh)
 */
function generateTokenPair(userId, role) {
  const accessToken = generateToken(userId, role, JWT_CONFIG.expiresIn);
  const refreshToken = generateToken(userId, role, JWT_CONFIG.refreshExpiresIn);

  return {
    accessToken,
    refreshToken,
    expiresIn: '15m',
  };
}

/**
 * Verify and decode JWT
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
    });
  } catch (error) {
    return null;
  }
}

/**
 * Extract token from request
 */
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;

  return parts[1];
}

/**
 * Authentication middleware
 */
function authMiddleware(req, res, next) {
  // Skip auth for public endpoints
  const publicRoutes = ['/health', '/auth/login', '/auth/refresh', '/api/v1/auth/login'];
  if (publicRoutes.includes(req.path)) {
    return next();
  }

  const token = extractToken(req);

  // Missing token
  if (!token) {
    logger.warn('auth:missing_token', {
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'NO_TOKEN',
    });
  }

  // Token in blacklist (revoked)
  if (tokenBlacklist.has(token)) {
    logger.warn('auth:blacklisted_token', {
      ip: req.ip,
      path: req.path,
    });
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'TOKEN_REVOKED',
    });
  }

  // Verify token
  const decoded = verifyToken(token);
  if (!decoded) {
    logger.warn('auth:invalid_token', {
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'INVALID_TOKEN',
    });
  }

  // Attach user info to request
  req.user = {
    id: decoded.userId,
    role: decoded.role,
  };

  next();
}

/**
 * Role-based authorization middleware
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn('auth:insufficient_role', {
        ip: req.ip,
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path,
      });
      return res.status(403).json({
        error: 'Forbidden',
        code: 'INSUFFICIENT_ROLE',
        message: `This action requires one of: ${allowedRoles.join(', ')}`,
      });
    }

    next();
  };
}

/**
 * Revoke token (add to blacklist)
 */
function revokeToken(token) {
  tokenBlacklist.add(token);
  // Auto-cleanup after token expires (set TTL in Redis in production)
  const decoded = verifyToken(token);
  if (decoded && decoded.exp) {
    const ttl = (decoded.exp * 1000) - Date.now();
    setTimeout(() => {
      tokenBlacklist.delete(token);
    }, ttl);
  }
}

/**
 * Login endpoint (generates token pair)
 */
async function loginHandler(req, res) {
  const { userId, role } = req.body;

  // Validate input
  if (!userId || !role) {
    return res.status(400).json({
      error: 'Missing userId or role',
    });
  }

  // Validate role
  const validRoles = ['owner', 'admin', 'developer', 'api_consumer', 'viewer'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({
      error: `Invalid role. Must be one of: ${validRoles.join(', ')}`,
    });
  }

  try {
    const tokens = generateTokenPair(userId, role);

    logger.info('auth:login_success', {
      userId,
      role,
      ip: req.ip,
    });

    res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
      tokenType: 'Bearer',
    });
  } catch (error) {
    logger.error('auth:login_error', {
      error: error.message,
      userId,
      ip: req.ip,
    });
    res.status(500).json({ error: 'Failed to generate token' });
  }
}

/**
 * Refresh token endpoint
 */
function refreshHandler(req, res) {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Missing refreshToken' });
  }

  const decoded = verifyToken(refreshToken);
  if (!decoded) {
    logger.warn('auth:invalid_refresh_token', {
      ip: req.ip,
    });
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  // Check if refresh token is blacklisted
  if (tokenBlacklist.has(refreshToken)) {
    logger.warn('auth:refresh_token_revoked', {
      ip: req.ip,
      userId: decoded.userId,
    });
    return res.status(401).json({ error: 'Refresh token revoked' });
  }

  try {
    // Generate new access token
    const newAccessToken = generateToken(decoded.userId, decoded.role);

    // Rotate refresh token (one-time use)
    revokeToken(refreshToken);
    const newRefreshToken = generateToken(
      decoded.userId,
      decoded.role,
      JWT_CONFIG.refreshExpiresIn
    );

    logger.info('auth:token_refreshed', {
      userId: decoded.userId,
      ip: req.ip,
    });

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: '15m',
      tokenType: 'Bearer',
    });
  } catch (error) {
    logger.error('auth:refresh_error', {
      error: error.message,
      ip: req.ip,
    });
    res.status(500).json({ error: 'Failed to refresh token' });
  }
}

/**
 * Logout endpoint (revoke token)
 */
function logoutHandler(req, res) {
  const token = extractToken(req);
  if (token) {
    revokeToken(token);
  }

  logger.info('auth:logout', {
    userId: req.user?.id,
    ip: req.ip,
  });

  res.json({ message: 'Logged out successfully' });
}

module.exports = {
  authMiddleware,
  requireRole,
  generateToken,
  generateTokenPair,
  verifyToken,
  revokeToken,
  extractToken,
  // Route handlers
  loginHandler,
  refreshHandler,
  logoutHandler,
  // Config
  JWT_CONFIG,
};
