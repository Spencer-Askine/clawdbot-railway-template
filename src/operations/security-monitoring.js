/**
 * Security Monitoring & Dashboards
 * 
 * Real-time security metrics API.
 * Provides data for monitoring dashboards.
 */

const logger = require('../security/logger');

// Metrics collector
const metrics = {
  authentication: {
    totalLogins: 0,
    failedLogins: 0,
    successfulLogins: 0,
    tokenRefreshes: 0,
    logouts: 0,
  },
  authorization: {
    permissionDenied: 0,
    modelAccessDenied: 0,
  },
  security: {
    injectionAttempts: 0,
    rateLimitHits: 0,
    suspiciousActivity: 0,
    piiDetected: 0,
  },
  cost: {
    dailySpend: 0,
    circuitBreakerEvents: 0,
    warningThresholds: 0,
  },
  api: {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    avgResponseTimeMs: 0,
  },
};

// Time-series data for trending
const timeSeries = {
  hourly: [], // [{timestamp, metrics}]
  daily: [],  // [{timestamp, metrics}]
  weekly: [], // [{timestamp, metrics}]
};

const MAX_POINTS = {
  hourly: 168,   // 7 days of hourly data
  daily: 365,    // 1 year of daily data
  weekly: 104,   // 2 years of weekly data
};

/**
 * Record authentication event
 */
function recordAuthEvent(eventType, data = {}) {
  metrics.authentication.totalLogins++;

  switch (eventType) {
    case 'login_success':
      metrics.authentication.successfulLogins++;
      break;
    case 'login_failed':
      metrics.authentication.failedLogins++;
      break;
    case 'token_refresh':
      metrics.authentication.tokenRefreshes++;
      break;
    case 'logout':
      metrics.authentication.logouts++;
      break;
  }
}

/**
 * Record authorization event
 */
function recordAuthzEvent(eventType, data = {}) {
  switch (eventType) {
    case 'permission_denied':
      metrics.authorization.permissionDenied++;
      break;
    case 'model_access_denied':
      metrics.authorization.modelAccessDenied++;
      break;
  }
}

/**
 * Record security event
 */
function recordSecurityEvent(eventType, data = {}) {
  switch (eventType) {
    case 'injection_attempt':
      metrics.security.injectionAttempts++;
      break;
    case 'rate_limit_hit':
      metrics.security.rateLimitHits++;
      break;
    case 'suspicious_activity':
      metrics.security.suspiciousActivity++;
      break;
    case 'pii_detected':
      metrics.security.piiDetected++;
      break;
  }
}

/**
 * Record cost event
 */
function recordCostEvent(eventType, amount = 0, data = {}) {
  switch (eventType) {
    case 'spend_tracked':
      metrics.cost.dailySpend += amount;
      break;
    case 'warning_threshold':
      metrics.cost.warningThresholds++;
      break;
    case 'circuit_breaker':
      metrics.cost.circuitBreakerEvents++;
      break;
  }
}

/**
 * Record API request
 */
function recordApiRequest(endpoint, statusCode, responseTimeMs) {
  metrics.api.totalRequests++;
  
  if (statusCode >= 200 && statusCode < 300) {
    metrics.api.successfulRequests++;
  } else if (statusCode >= 400) {
    metrics.api.failedRequests++;
  }

  // Update rolling average response time
  const weight = 0.1; // Recent requests weighted 10%
  metrics.api.avgResponseTimeMs = 
    (metrics.api.avgResponseTimeMs * (1 - weight)) + 
    (responseTimeMs * weight);
}

/**
 * Capture current metrics snapshot
 */
function captureSnapshot() {
  return {
    timestamp: new Date().toISOString(),
    metrics: JSON.parse(JSON.stringify(metrics)),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  };
}

/**
 * Archive metrics to time series
 */
function archiveMetrics() {
  const snapshot = captureSnapshot();

  // Add to hourly
  timeSeries.hourly.push(snapshot);
  if (timeSeries.hourly.length > MAX_POINTS.hourly) {
    timeSeries.hourly.shift();
  }

  // Reset daily metrics
  metrics.cost.dailySpend = 0;
  metrics.api.totalRequests = 0;
  metrics.api.successfulRequests = 0;
  metrics.api.failedRequests = 0;
}

/**
 * Get security dashboard data
 */
function getSecurityDashboard() {
  const failureRate = metrics.authentication.totalLogins > 0
    ? ((metrics.authentication.failedLogins / metrics.authentication.totalLogins) * 100).toFixed(2)
    : 0;

  const successRate = metrics.api.totalRequests > 0
    ? ((metrics.api.successfulRequests / metrics.api.totalRequests) * 100).toFixed(2)
    : 0;

  return {
    status: {
      health: metrics.api.failedRequests < metrics.api.totalRequests * 0.05 ? 'healthy' : 'degraded',
      uptime: `${(process.uptime() / 3600).toFixed(2)} hours`,
    },
    authentication: {
      totalLogins: metrics.authentication.totalLogins,
      successRate: `${successRate}%`,
      failureRate: `${failureRate}%`,
      failedLogins: metrics.authentication.failedLogins,
      recentTokenRefreshes: metrics.authentication.tokenRefreshes,
    },
    security: {
      injectionAttemptsDetected: metrics.security.injectionAttempts,
      rateLimitHits: metrics.security.rateLimitHits,
      suspiciousActivityEvents: metrics.security.suspiciousActivity,
      piiDetectionEvents: metrics.security.piiDetected,
      riskScore: calculateRiskScore(),
    },
    cost: {
      dailySpend: `$${metrics.cost.dailySpend.toFixed(2)}`,
      circuitBreakerEvents: metrics.cost.circuitBreakerEvents,
      warningThresholdHits: metrics.cost.warningThresholds,
    },
    api: {
      totalRequests: metrics.api.totalRequests,
      successfulRequests: metrics.api.successfulRequests,
      failedRequests: metrics.api.failedRequests,
      avgResponseTime: `${metrics.api.avgResponseTimeMs.toFixed(0)}ms`,
    },
  };
}

/**
 * Calculate overall risk score (0-100)
 */
function calculateRiskScore() {
  let score = 0;

  // Authentication risk
  const authFailureRate = metrics.authentication.totalLogins > 0
    ? metrics.authentication.failedLogins / metrics.authentication.totalLogins
    : 0;
  score += authFailureRate * 20; // Max 20 points

  // Injection attacks
  score += Math.min(metrics.security.injectionAttempts * 2, 20); // Max 20 points

  // Rate limiting
  score += Math.min(metrics.security.rateLimitHits * 0.5, 20); // Max 20 points

  // Cost anomalies
  score += metrics.cost.circuitBreakerEvents * 10; // Max 10 points
  score += metrics.cost.warningThresholds * 5;     // Max 5 points

  // PII exposure
  score += metrics.security.piiDetected * 15; // Max 15 points

  return Math.min(score, 100);
}

/**
 * Get historical trends
 */
function getTrends(period = 'daily') {
  const data = timeSeries[period] || [];
  
  if (data.length < 2) {
    return { error: 'Insufficient data for trends' };
  }

  const latest = data[data.length - 1];
  const previous = data[data.length - 2];

  return {
    period,
    timestamp: latest.timestamp,
    metrics: {
      authFailureChange: latest.metrics.authentication.failedLogins - previous.metrics.authentication.failedLogins,
      injectionAttemptsChange: latest.metrics.security.injectionAttempts - previous.metrics.security.injectionAttempts,
      costChange: latest.metrics.cost.dailySpend - previous.metrics.cost.dailySpend,
      apiSuccessRateChange: 
        (latest.metrics.api.successfulRequests / latest.metrics.api.totalRequests) -
        (previous.metrics.api.successfulRequests / previous.metrics.api.totalRequests),
    },
  };
}

/**
 * Health check
 */
function getHealthStatus() {
  const memory = process.memoryUsage();
  const memoryUsagePercent = (memory.heapUsed / memory.heapTotal) * 100;

  return {
    status: memoryUsagePercent > 90 ? 'warning' : 'healthy',
    uptime: process.uptime(),
    memory: {
      heapUsedMb: (memory.heapUsed / 1024 / 1024).toFixed(2),
      heapTotalMb: (memory.heapTotal / 1024 / 1024).toFixed(2),
      usagePercent: memoryUsagePercent.toFixed(2),
    },
    metrics: {
      activeIncidents: 0, // Will be populated by incident response
      openAlerts: 0,      // Will be populated by alerting system
    },
  };
}

/**
 * Export metrics for monitoring systems
 */
function exportMetricsPrometheus() {
  const lines = [];

  lines.push('# HELP openclaw_auth_total Total authentication events');
  lines.push(`openclaw_auth_total ${metrics.authentication.totalLogins}`);
  
  lines.push('# HELP openclaw_auth_failed Failed authentication attempts');
  lines.push(`openclaw_auth_failed ${metrics.authentication.failedLogins}`);
  
  lines.push('# HELP openclaw_injection_attempts Detected injection attempts');
  lines.push(`openclaw_injection_attempts ${metrics.security.injectionAttempts}`);
  
  lines.push('# HELP openclaw_rate_limits Rate limit hits');
  lines.push(`openclaw_rate_limits ${metrics.security.rateLimitHits}`);
  
  lines.push('# HELP openclaw_daily_spend Daily API spend in dollars');
  lines.push(`openclaw_daily_spend ${metrics.cost.dailySpend}`);
  
  lines.push('# HELP openclaw_api_requests Total API requests');
  lines.push(`openclaw_api_requests ${metrics.api.totalRequests}`);
  
  lines.push('# HELP openclaw_api_success Successful API requests');
  lines.push(`openclaw_api_success ${metrics.api.successfulRequests}`);
  
  lines.push('# HELP openclaw_api_avg_response_time Average API response time in ms');
  lines.push(`openclaw_api_avg_response_time ${metrics.api.avgResponseTimeMs.toFixed(0)}`);
  
  lines.push('# HELP openclaw_risk_score Overall security risk score (0-100)');
  lines.push(`openclaw_risk_score ${calculateRiskScore()}`);

  return lines.join('\n');
}

module.exports = {
  recordAuthEvent,
  recordAuthzEvent,
  recordSecurityEvent,
  recordCostEvent,
  recordApiRequest,
  captureSnapshot,
  archiveMetrics,
  getSecurityDashboard,
  getTrends,
  getHealthStatus,
  calculateRiskScore,
  exportMetricsPrometheus,
};
