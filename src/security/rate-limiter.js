/**
 * Multi-Layer Rate Limiting
 * 
 * Layer 1: IP-based (all requests)
 * Layer 2: API Key-based (authenticated)
 * Layer 3: Model-specific (by tier)
 * 
 * Uses in-memory store (upgrade to Redis for production)
 */

const logger = require('./logger');

// In-memory rate limit stores
const ipLimits = new Map();
const keyLimits = new Map();
const modelLimits = new Map();

// Rate limit configurations
const LIMITS = {
  ip: {
    requestsPerMinute: 100,
    algorithm: 'sliding_window',
  },
  apiKey: {
    requestsPerMinute: 60,
    algorithm: 'token_bucket',
    burst: 5, // Allow 5 burst requests
  },
  models: {
    haiku: {
      requestsPerMinute: 60,
      tokensPerMinute: 100000,
    },
    sonnet: {
      requestsPerMinute: 30,
      tokensPerMinute: 50000,
    },
    opus: {
      requestsPerMinute: 10,
      tokensPerMinute: 20000,
    },
  },
};

/**
 * Sliding window rate limiter
 */
function checkSlidingWindow(key, limit, store) {
  const now = Date.now();
  const windowSize = 60 * 1000; // 1 minute

  if (!store.has(key)) {
    store.set(key, []);
  }

  const requests = store.get(key);
  
  // Remove requests outside the window
  const validRequests = requests.filter(
    timestamp => now - timestamp < windowSize
  );

  if (validRequests.length >= limit) {
    return { allowed: false, remaining: 0 };
  }

  validRequests.push(now);
  store.set(key, validRequests);

  return {
    allowed: true,
    remaining: limit - validRequests.length,
    resetAt: new Date(validRequests[0] + windowSize),
  };
}

/**
 * Token bucket rate limiter
 */
function checkTokenBucket(key, limit, burst, store) {
  const now = Date.now();

  if (!store.has(key)) {
    store.set(key, {
      tokens: limit,
      lastRefill: now,
    });
  }

  const bucket = store.get(key);
  const timePassed = now - bucket.lastRefill;
  const tokensToAdd = (timePassed / 60000) * limit;
  bucket.tokens = Math.min(limit + burst, bucket.tokens + tokensToAdd);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return {
      allowed: true,
      remaining: Math.floor(bucket.tokens),
    };
  }

  return { allowed: false, remaining: 0 };
}

/**
 * Check IP-based rate limit (Layer 1)
 */
function checkIPLimit(ip) {
  const limit = LIMITS.ip.requestsPerMinute;
  const result = checkSlidingWindow(ip, limit, ipLimits);

  if (!result.allowed) {
    logger.security.rateLimited({
      type: 'ip',
      ip,
      limit,
    });
  }

  return {
    type: 'ip',
    allowed: result.allowed,
    limit,
    remaining: result.remaining,
    resetAt: result.resetAt,
  };
}

/**
 * Check API Key-based rate limit (Layer 2)
 */
function checkKeyLimit(key) {
  const limit = LIMITS.apiKey.requestsPerMinute;
  const burst = LIMITS.apiKey.burst;
  const result = checkTokenBucket(key, limit, burst, keyLimits);

  if (!result.allowed) {
    logger.security.rateLimited({
      type: 'apiKey',
      keyLastChars: key.slice(-4),
      limit,
    });
  }

  return {
    type: 'apiKey',
    allowed: result.allowed,
    limit,
    remaining: result.remaining,
  };
}

/**
 * Check model-specific rate limit (Layer 3)
 */
function checkModelLimit(model, tokenCount = 0) {
  if (!LIMITS.models[model]) {
    return { allowed: true, type: 'model' };
  }

  const limit = LIMITS.models[model];
  const key = `model:${model}`;

  const result = checkSlidingWindow(key, limit.requestsPerMinute, modelLimits);

  if (!result.allowed) {
    logger.security.rateLimited({
      type: 'model',
      model,
      limit: limit.requestsPerMinute,
    });
  }

  return {
    type: 'model',
    model,
    allowed: result.allowed,
    limit: limit.requestsPerMinute,
    remaining: result.remaining,
  };
}

/**
 * Rate limiter middleware
 */
function rateLimitMiddleware(options = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const apiKey = req.headers['x-api-key'] || (req.user ? req.user.id : null);

    // Check IP limit (always)
    const ipCheck = checkIPLimit(ip);
    if (!ipCheck.allowed) {
      return res.status(429).json({
        error: 'Too Many Requests',
        code: 'RATE_LIMITED_IP',
        retryAfter: '60s',
      }).set('Retry-After', '60');
    }

    // Check API key limit (if authenticated)
    if (apiKey) {
      const keyCheck = checkKeyLimit(apiKey);
      if (!keyCheck.allowed) {
        return res.status(429).json({
          error: 'Too Many Requests',
          code: 'RATE_LIMITED_KEY',
          retryAfter: '60s',
        }).set('Retry-After', '60');
      }

      // Attach rate limit info to request
      req.rateLimit = {
        ipCheck,
        keyCheck,
      };
    }

    // Add rate limit headers to response
    res.set({
      'X-RateLimit-Limit': ipCheck.limit,
      'X-RateLimit-Remaining': ipCheck.remaining,
      'X-RateLimit-Reset': ipCheck.resetAt ? Math.ceil(ipCheck.resetAt.getTime() / 1000) : '',
    });

    next();
  };
}

/**
 * Model-specific rate limiter
 */
function modelRateLimitMiddleware(model) {
  return (req, res, next) => {
    const check = checkModelLimit(model);
    if (!check.allowed) {
      return res.status(429).json({
        error: 'Model rate limit exceeded',
        code: 'MODEL_RATE_LIMITED',
        model,
      }).set('Retry-After', '60');
    }

    req.modelRateLimit = check;
    next();
  };
}

/**
 * Reset limits (for testing)
 */
function resetLimits() {
  ipLimits.clear();
  keyLimits.clear();
  modelLimits.clear();
}

/**
 * Get current limit status
 */
function getLimitStatus(ip, key) {
  return {
    ip: ipLimits.get(ip) || [],
    key: keyLimits.get(key) || {},
  };
}

module.exports = {
  checkIPLimit,
  checkKeyLimit,
  checkModelLimit,
  rateLimitMiddleware,
  modelRateLimitMiddleware,
  resetLimits,
  getLimitStatus,
  LIMITS,
};
