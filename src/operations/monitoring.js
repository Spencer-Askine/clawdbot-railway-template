/**
 * Security Monitoring & Metrics
 * 
 * Tracks and exposes security metrics for dashboards.
 * Provides real-time visibility into:
 * - Authentication failures and successes
 * - Rate limit hits
 * - Cost trends
 * - Incident status
 * - System health
 */

const logger = require('../security/logger');

// Metrics storage (use Redis in production)
const metrics = {
  auth: {
    successful: 0,
    failed: 0,
    tokenRefreshed: 0,
    loggedOut: 0,
  },
  rateLimit: {
    ipHits: 0,
    keyHits: 0,
    modelHits: 0,
  },
  cost: {
    dailyTotal: 0,
    lastUpdate: new Date(),
  },
  security: {
    injectionAttempts: 0,
    piiDetected: 0,
    blacklistedIps: 0,
    blacklistedKeys: 0,
  },
  performance: {
    avgResponseTime: 0,
    p95ResponseTime: 0,
    p99ResponseTime: 0,
    errorRate: 0,
  },
};

// Time-series data for charts (in-memory; use InfluxDB/Prometheus in production)
const timeSeries = {
  authFailures: [],     // [{ timestamp, count }]
  costTrend: [],        // [{ timestamp, daily, byModel }]
  rateLimitHits: [],    // [{ timestamp, type, count }]
  incidents: [],        // [{ timestamp, type, severity, count }]
};

const MAX_SERIES_POINTS = 1440; // Keep 24 hours of 1-minute data

/**
 * Record authentication event
 */
function recordAuthEvent(type, metadata = {}) {
  const validTypes = ['successful', 'failed', 'tokenRefreshed', 'loggedOut'];

  if (!validTypes.includes(type)) {
    logger.warn('Invalid auth event type', { type });
    return;
  }

  metrics.auth[type]++;

  if (type === 'failed') {
    recordTimeSeries('authFailures', { count: 1 });
  }

  logger.security.authEvent({
    type,
    ...metadata,
  });
}

/**
 * Record rate limit hit
 */
function recordRateLimitHit(layer, metadata = {}) {
  const validLayers = ['ipHits', 'keyHits', 'modelHits'];

  if (!validLayers.includes(layer)) {
    logger.warn('Invalid rate limit layer', { layer });
    return;
  }

  metrics.rateLimit[layer]++;
  recordTimeSeries('rateLimitHits', { type: layer, count: 1 });

  logger.security.rateLimitEvent({
    layer,
    ...metadata,
  });
}

/**
 * Record cost update
 */
function recordCostUpdate(dailyTotal, byModel = {}) {
  metrics.cost.dailyTotal = dailyTotal;
  metrics.cost.lastUpdate = new Date();

  recordTimeSeries('costTrend', {
    daily: dailyTotal,
    byModel,
  });
}

/**
 * Record security event (injection, PII, etc.)
 */
function recordSecurityEvent(type, metadata = {}) {
  const validTypes = ['injectionAttempts', 'piiDetected', 'blacklistedIps', 'blacklistedKeys'];

  if (!validTypes.includes(type)) {
    logger.warn('Invalid security event type', { type });
    return;
  }

  metrics.security[type]++;

  logger.security.securityEvent({
    type,
    ...metadata,
  });
}

/**
 * Record incident
 */
function recordIncident(type, severity, metadata = {}) {
  recordTimeSeries('incidents', { type, severity, count: 1 });

  logger.security.incidentEvent({
    type,
    severity,
    ...metadata,
  });
}

/**
 * Record response time for performance tracking
 */
function recordResponseTime(endpoint, duration, status) {
  // Update rolling average
  metrics.performance.avgResponseTime =
    (metrics.performance.avgResponseTime * 0.95) + (duration * 0.05);

  // This is simplified; real implementation uses percentile calculation
  metrics.performance.p95ResponseTime = metrics.performance.avgResponseTime * 1.5;
  metrics.performance.p99ResponseTime = metrics.performance.avgResponseTime * 2.0;

  if (status >= 400) {
    // Track error rate
    metrics.performance.errorRate =
      (metrics.performance.errorRate * 0.99) + (0.01);
  }
}

/**
 * Record to time series (maintains rolling window)
 */
function recordTimeSeries(seriesName, data) {
  if (!timeSeries[seriesName]) {
    timeSeries[seriesName] = [];
  }

  timeSeries[seriesName].push({
    timestamp: new Date().toISOString(),
    ...data,
  });

  // Keep only recent data
  if (timeSeries[seriesName].length > MAX_SERIES_POINTS) {
    timeSeries[seriesName].shift();
  }
}

/**
 * Get current metrics snapshot
 */
function getMetricsSnapshot() {
  return {
    timestamp: new Date().toISOString(),
    metrics: {
      auth: { ...metrics.auth },
      rateLimit: { ...metrics.rateLimit },
      cost: { ...metrics.cost },
      security: { ...metrics.security },
      performance: { ...metrics.performance },
    },
  };
}

/**
 * Get time series data (for charts)
 */
function getTimeSeriesData(series, hours = 24) {
  if (!timeSeries[series]) {
    return [];
  }

  const cutoff = new Date(Date.now() - (hours * 60 * 60 * 1000));

  return timeSeries[series].filter(
    point => new Date(point.timestamp) > cutoff
  );
}

/**
 * Calculate trending metrics
 */
function getTrending() {
  return {
    authFailureRate: (
      metrics.auth.failed /
      (metrics.auth.successful + metrics.auth.failed || 1)
    ).toFixed(4),
    
    rateLimitHitRate: (
      (metrics.rateLimit.ipHits + metrics.rateLimit.keyHits) / 1000 || 0
    ).toFixed(4),
    
    securityEventRate: (
      (metrics.security.injectionAttempts + metrics.security.piiDetected) / 1000 || 0
    ).toFixed(4),
    
    errorRate: metrics.performance.errorRate.toFixed(4),
    
    avgResponseTime: `${metrics.performance.avgResponseTime.toFixed(2)}ms`,
  };
}

/**
 * Get health status
 */
function getHealthStatus() {
  const authFailureRate = metrics.auth.failed /
    (metrics.auth.successful + metrics.auth.failed || 1);

  const securityEventRate = metrics.security.injectionAttempts +
    metrics.security.piiDetected;

  const isHealthy =
    authFailureRate < 0.1 &&
    securityEventRate < 100 &&
    metrics.performance.errorRate < 0.05;

  return {
    status: isHealthy ? 'healthy' : 'degraded',
    authFailureRate: (authFailureRate * 100).toFixed(2) + '%',
    securityEvents: securityEventRate,
    errorRate: (metrics.performance.errorRate * 100).toFixed(2) + '%',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Reset daily metrics
 */
function resetDailyMetrics() {
  metrics.auth = {
    successful: 0,
    failed: 0,
    tokenRefreshed: 0,
    loggedOut: 0,
  };

  metrics.rateLimit = {
    ipHits: 0,
    keyHits: 0,
    modelHits: 0,
  };

  metrics.security = {
    injectionAttempts: 0,
    piiDetected: 0,
    blacklistedIps: 0,
    blacklistedKeys: 0,
  };

  logger.info('Daily metrics reset');
}

/**
 * Export for Prometheus/StatsD (OpenMetrics format)
 */
function getPrometheusMetrics() {
  const lines = [
    '# HELP openclaw_auth_successful_total Successful authentications',
    '# TYPE openclaw_auth_successful_total counter',
    `openclaw_auth_successful_total ${metrics.auth.successful}`,
    '',
    '# HELP openclaw_auth_failed_total Failed authentications',
    '# TYPE openclaw_auth_failed_total counter',
    `openclaw_auth_failed_total ${metrics.auth.failed}`,
    '',
    '# HELP openclaw_ratelimit_hits_total Rate limit hits',
    '# TYPE openclaw_ratelimit_hits_total counter',
    `openclaw_ratelimit_hits_total{layer="ip"} ${metrics.rateLimit.ipHits}`,
    `openclaw_ratelimit_hits_total{layer="key"} ${metrics.rateLimit.keyHits}`,
    `openclaw_ratelimit_hits_total{layer="model"} ${metrics.rateLimit.modelHits}`,
    '',
    '# HELP openclaw_cost_daily Daily API cost',
    '# TYPE openclaw_cost_daily gauge',
    `openclaw_cost_daily ${metrics.cost.dailyTotal.toFixed(2)}`,
    '',
    '# HELP openclaw_security_injection_attempts_total Injection attempts',
    '# TYPE openclaw_security_injection_attempts_total counter',
    `openclaw_security_injection_attempts_total ${metrics.security.injectionAttempts}`,
    '',
    '# HELP openclaw_performance_response_time_ms Response time',
    '# TYPE openclaw_performance_response_time_ms gauge',
    `openclaw_performance_response_time_ms ${metrics.performance.avgResponseTime.toFixed(2)}`,
  ];

  return lines.join('\n');
}

module.exports = {
  recordAuthEvent,
  recordRateLimitHit,
  recordCostUpdate,
  recordSecurityEvent,
  recordIncident,
  recordResponseTime,
  getMetricsSnapshot,
  getTimeSeriesData,
  getTrending,
  getHealthStatus,
  resetDailyMetrics,
  getPrometheusMetrics,
};
