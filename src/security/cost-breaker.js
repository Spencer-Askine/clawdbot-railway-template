/**
 * Cost Circuit Breaker
 * 
 * Prevents runaway costs by monitoring spending and enforcing thresholds.
 * Implements automatic downgrading and emergency shutoffs.
 */

const logger = require('./logger');

// Model pricing (update to match your rates)
const MODEL_PRICING = {
  haiku: {
    inputPerMTok: 0.25,
    outputPerMTok: 1.25,
  },
  sonnet: {
    inputPerMTok: 3,
    outputPerMTok: 15,
  },
  opus: {
    inputPerMTok: 15,
    outputPerMTok: 75,
  },
};

// Circuit breaker thresholds
const THRESHOLDS = {
  warning: parseFloat(process.env.CIRCUIT_WARNING || 100), // $100/day
  softLimit: parseFloat(process.env.CIRCUIT_SOFT || 250), // $250/day
  hardLimit: parseFloat(process.env.CIRCUIT_HARD || 500), // $500/day
  emergency: parseFloat(process.env.CIRCUIT_EMERGENCY || 1000), // $1000/day
};

// Cost tracking (in-memory; use Redis in production)
const costTracker = {
  today: {
    timestamp: Date.now(),
    total: 0,
    byModel: {
      haiku: 0,
      sonnet: 0,
      opus: 0,
    },
    byKey: {},
  },
};

/**
 * Calculate request cost
 */
function calculateCost(model, inputTokens = 0, outputTokens = 0) {
  if (!MODEL_PRICING[model]) {
    return 0;
  }

  const pricing = MODEL_PRICING[model];
  const inputCost = (inputTokens / 1000000) * pricing.inputPerMTok;
  const outputCost = (outputTokens / 1000000) * pricing.outputPerMTok;

  return inputCost + outputCost;
}

/**
 * Reset daily totals (call at midnight)
 */
function resetDailyTotals() {
  costTracker.today = {
    timestamp: Date.now(),
    total: 0,
    byModel: {
      haiku: 0,
      sonnet: 0,
      opus: 0,
    },
    byKey: {},
  };
}

/**
 * Track cost for a request
 */
function trackCost(model, inputTokens, outputTokens, apiKey) {
  const cost = calculateCost(model, inputTokens, outputTokens);

  // Update daily totals
  costTracker.today.total += cost;
  costTracker.today.byModel[model] = (costTracker.today.byModel[model] || 0) + cost;

  // Track by API key
  if (apiKey) {
    costTracker.today.byKey[apiKey] = (costTracker.today.byKey[apiKey] || 0) + cost;
  }

  // Log cost tracking
  logger.cost.tracking({
    model,
    inputTokens,
    outputTokens,
    cost,
    totalDaily: costTracker.today.total,
    apiKey: apiKey ? apiKey.slice(-4) : 'none',
  });

  return cost;
}

/**
 * Check circuit breaker state
 */
function getCircuitState() {
  const total = costTracker.today.total;

  if (total >= THRESHOLDS.emergency) {
    return 'EMERGENCY';
  } else if (total >= THRESHOLDS.hardLimit) {
    return 'HARD_LIMIT';
  } else if (total >= THRESHOLDS.softLimit) {
    return 'SOFT_LIMIT';
  } else if (total >= THRESHOLDS.warning) {
    return 'WARNING';
  } else {
    return 'OK';
  }
}

/**
 * Check if model request is allowed
 */
function canMakeRequest(model, apiKey = null) {
  const state = getCircuitState();

  const allowed = {
    haiku: true,
    sonnet: state !== 'HARD_LIMIT' && state !== 'EMERGENCY',
    opus: state === 'OK' || state === 'WARNING',
  };

  const canRequest = allowed[model] !== false;

  if (!canRequest) {
    logger.cost.circuitBreaker({
      model,
      state,
      total: costTracker.today.total,
      threshold: THRESHOLDS[state.toLowerCase()],
      apiKey: apiKey ? apiKey.slice(-4) : 'none',
      action: 'blocked',
    });
  }

  return canRequest;
}

/**
 * Get recommended model downgrade
 */
function getDowngradedModel(requestedModel) {
  const state = getCircuitState();

  if (state === 'EMERGENCY') {
    return 'haiku'; // Only allow Haiku
  } else if (state === 'HARD_LIMIT') {
    if (requestedModel === 'opus') {
      return 'sonnet';
    }
  } else if (state === 'SOFT_LIMIT') {
    if (requestedModel === 'opus') {
      return 'sonnet';
    }
  }

  return requestedModel; // No downgrade needed
}

/**
 * Circuit breaker middleware
 */
function circuitBreakerMiddleware(req, res, next) {
  const state = getCircuitState();
  const total = costTracker.today.total;

  // Attach state info to request
  req.costState = {
    state,
    total,
    thresholds: THRESHOLDS,
  };

  // Check for emergency shutoff
  if (state === 'EMERGENCY') {
    logger.cost.circuitBreaker({
      state: 'EMERGENCY',
      total,
      action: 'blocking_all',
    });

    return res.status(503).json({
      error: 'Service Unavailable',
      code: 'COST_EMERGENCY_SHUTOFF',
      message: 'Service temporarily suspended due to cost limits',
      message_detail: `Daily spend ($${total.toFixed(2)}) has reached emergency threshold ($${THRESHOLDS.emergency})`,
    });
  }

  // Check hard limit and block non-Haiku
  if (state === 'HARD_LIMIT' && req.body && req.body.model !== 'haiku') {
    logger.cost.circuitBreaker({
      state: 'HARD_LIMIT',
      total,
      requestedModel: req.body.model,
      action: 'downgraded_to_haiku',
    });

    // Automatically downgrade
    req.body.model = 'haiku';
    req.costDowngraded = true;
  }

  // Soft limit: downgrade Opus to Sonnet
  if (state === 'SOFT_LIMIT' && req.body && req.body.model === 'opus') {
    logger.cost.circuitBreaker({
      state: 'SOFT_LIMIT',
      total,
      requestedModel: 'opus',
      action: 'downgraded_to_sonnet',
    });

    req.body.model = 'sonnet';
    req.costDowngraded = true;
  }

  // Send warning header
  if (state === 'WARNING' || state === 'SOFT_LIMIT' || state === 'HARD_LIMIT') {
    res.set({
      'X-Cost-State': state,
      'X-Cost-Daily': `$${total.toFixed(2)}`,
      'X-Cost-Warning': `Daily spending at ${state}`,
    });
  }

  next();
}

/**
 * Get cost status (for /admin/costs)
 */
function getCostStatus() {
  return {
    state: getCircuitState(),
    daily: costTracker.today.total,
    byModel: costTracker.today.byModel,
    byKey: costTracker.today.byKey,
    thresholds: THRESHOLDS,
    nextReset: new Date(
      new Date().setHours(24, 0, 0, 0)
    ).toISOString(),
  };
}

/**
 * Manual reset (owner only)
 */
function manualReset() {
  logger.cost.circuitBreaker({
    action: 'manual_reset',
    previousTotal: costTracker.today.total,
  });

  resetDailyTotals();
}

module.exports = {
  trackCost,
  calculateCost,
  getCircuitState,
  canMakeRequest,
  getDowngradedModel,
  circuitBreakerMiddleware,
  getCostStatus,
  manualReset,
  THRESHOLDS,
  MODEL_PRICING,
};
