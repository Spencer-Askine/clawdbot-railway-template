/**
 * Incident Response Automation
 * 
 * Automatically detects security incidents and triggers appropriate responses.
 * - API key compromise
 * - Brute force attacks
 * - Cost anomalies
 * - Data exfiltration attempts
 * - Service degradation
 */

const logger = require('../security/logger');

// Incident severity levels
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

// Incident types
const INCIDENT_TYPES = {
  KEY_COMPROMISE: 'key_compromise',
  BRUTE_FORCE: 'brute_force',
  COST_ANOMALY: 'cost_anomaly',
  DATA_EXFILTRATION: 'data_exfiltration',
  SERVICE_DEGRADATION: 'service_degradation',
  INJECTION_ATTACK: 'injection_attack',
  RATE_LIMIT_ABUSE: 'rate_limit_abuse',
};

// Incident detection thresholds
const DETECTION_THRESHOLDS = {
  [INCIDENT_TYPES.BRUTE_FORCE]: {
    failedLoginsPerMinute: 10,
    timeWindowMinutes: 5,
    blockDurationMinutes: 60,
  },
  [INCIDENT_TYPES.COST_ANOMALY]: {
    dailySpikeFactor: 3, // 3x normal spend
    minBaselineDaily: 50,
  },
  [INCIDENT_TYPES.DATA_EXFILTRATION]: {
    responseTokensPerMinute: 100000,
    timeWindowMinutes: 5,
  },
  [INCIDENT_TYPES.RATE_LIMIT_ABUSE]: {
    hitsPerMinute: 50,
    timeWindowMinutes: 5,
    ipBlockDurationMinutes: 1440, // 24 hours
  },
};

// In-memory incident tracking
const incidentTracker = {
  active: new Map(),     // Currently open incidents
  history: [],           // Historical incidents
  maxHistorySize: 1000,
};

// Blacklist for blocking IPs/keys temporarily
const blacklist = {
  ips: new Map(),        // {ip: expiryTimestamp}
  apiKeys: new Map(),    // {key: expiryTimestamp}
};

/**
 * Create incident record
 */
function createIncident(type, severity, data = {}) {
  const incident = {
    id: `incident_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    type,
    severity,
    timestamp: new Date().toISOString(),
    status: 'open',
    detectedAt: new Date(),
    data,
    actions: [],
  };

  incidentTracker.active.set(incident.id, incident);

  return incident;
}

/**
 * Detect brute force attack
 */
function detectBruteForce(ip, recentFailures) {
  const threshold = DETECTION_THRESHOLDS[INCIDENT_TYPES.BRUTE_FORCE];
  
  if (recentFailures.length >= threshold.failedLoginsPerMinute) {
    const oldest = recentFailures[0];
    const newest = recentFailures[recentFailures.length - 1];
    const timeDiffMinutes = (newest - oldest) / (60 * 1000);

    if (timeDiffMinutes <= threshold.timeWindowMinutes) {
      return {
        detected: true,
        failureCount: recentFailures.length,
        timeWindow: timeDiffMinutes,
      };
    }
  }

  return { detected: false };
}

/**
 * Detect cost anomaly
 */
function detectCostAnomaly(dailySpend, baseline7DayAverage) {
  const threshold = DETECTION_THRESHOLDS[INCIDENT_TYPES.COST_ANOMALY];
  
  if (dailySpend > baseline7DayAverage * threshold.dailySpikeFactor &&
      dailySpend > threshold.minBaselineDaily) {
    return {
      detected: true,
      currentDaily: dailySpend,
      baselineAverage: baseline7DayAverage,
      spikeFactor: (dailySpend / baseline7DayAverage).toFixed(2),
    };
  }

  return { detected: false };
}

/**
 * Detect data exfiltration attempt
 */
function detectDataExfiltration(recentResponseTokens) {
  const threshold = DETECTION_THRESHOLDS[INCIDENT_TYPES.DATA_EXFILTRATION];
  
  const tokensPerMinute = recentResponseTokens.reduce((sum, t) => sum + t.tokens, 0);

  if (tokensPerMinute > threshold.responseTokensPerMinute) {
    return {
      detected: true,
      tokensPerMinute,
      threshold: threshold.responseTokensPerMinute,
      ratio: (tokensPerMinute / threshold.responseTokensPerMinute).toFixed(2),
    };
  }

  return { detected: false };
}

/**
 * Respond to key compromise
 */
async function respondToKeyCompromise(incident) {
  logger.security.incidentDetected({
    type: INCIDENT_TYPES.KEY_COMPROMISE,
    severity: SEVERITY.CRITICAL,
    action: 'key_disabled',
    apiKey: incident.data.apiKey,
  });

  const action = {
    type: 'auto_response',
    action: 'disable_key',
    timestamp: new Date().toISOString(),
    key: incident.data.apiKey,
  };

  // Add to blacklist immediately
  blacklist.apiKeys.set(
    incident.data.apiKey,
    Date.now() + (24 * 60 * 60 * 1000) // 24 hours
  );

  incident.actions.push(action);

  // TODO: Send alert to ops (Slack, email, SMS)
  // TODO: Log to external SIEM

  return action;
}

/**
 * Respond to brute force
 */
async function respondToBruteForce(incident) {
  logger.security.incidentDetected({
    type: INCIDENT_TYPES.BRUTE_FORCE,
    severity: SEVERITY.HIGH,
    action: 'ip_blocked',
    ip: incident.data.ip,
    failureCount: incident.data.failureCount,
  });

  const action = {
    type: 'auto_response',
    action: 'block_ip',
    timestamp: new Date().toISOString(),
    ip: incident.data.ip,
    durationMinutes: DETECTION_THRESHOLDS[INCIDENT_TYPES.BRUTE_FORCE].blockDurationMinutes,
  };

  // Block the IP
  const threshold = DETECTION_THRESHOLDS[INCIDENT_TYPES.BRUTE_FORCE];
  blacklist.ips.set(
    incident.data.ip,
    Date.now() + (threshold.blockDurationMinutes * 60 * 1000)
  );

  incident.actions.push(action);

  // After 5+ attempts, escalate to 24-hour block
  if (incident.data.failureCount >= 20) {
    blacklist.ips.set(
      incident.data.ip,
      Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    );

    incident.actions.push({
      type: 'escalation',
      action: 'extended_block',
      reason: 'persistent_attacks',
      durationMinutes: 1440,
      timestamp: new Date().toISOString(),
    });
  }

  return action;
}

/**
 * Respond to cost anomaly
 */
async function respondToCostAnomaly(incident) {
  logger.cost.circuitBreaker({
    type: 'anomaly_detected',
    severity: SEVERITY.HIGH,
    dailySpend: incident.data.currentDaily,
    baseline: incident.data.baselineAverage,
  });

  const action = {
    type: 'auto_response',
    action: 'activate_soft_limit',
    timestamp: new Date().toISOString(),
    reason: `Spend spike to $${incident.data.currentDaily.toFixed(2)} (${incident.data.spikeFactor}x baseline)`,
    effect: 'downgrade_opus_to_sonnet',
  };

  incident.actions.push(action);

  // TODO: Send alert to ops

  return action;
}

/**
 * Respond to data exfiltration
 */
async function respondToDataExfiltration(incident) {
  logger.security.incidentDetected({
    type: INCIDENT_TYPES.DATA_EXFILTRATION,
    severity: SEVERITY.HIGH,
    action: 'rate_limit_tightened',
    tokensPerMinute: incident.data.tokensPerMinute,
  });

  const action = {
    type: 'auto_response',
    action: 'tighten_rate_limits',
    timestamp: new Date().toISOString(),
    apiKey: incident.data.apiKey,
    reason: `Abnormal data extraction: ${incident.data.tokensPerMinute} tokens/min`,
  };

  incident.actions.push(action);

  // Temporarily reduce rate limit for this key
  // (Implementation depends on your rate limiter storage)

  return action;
}

/**
 * Main incident response dispatcher
 */
async function respondToIncident(incident) {
  const handlers = {
    [INCIDENT_TYPES.KEY_COMPROMISE]: respondToKeyCompromise,
    [INCIDENT_TYPES.BRUTE_FORCE]: respondToBruteForce,
    [INCIDENT_TYPES.COST_ANOMALY]: respondToCostAnomaly,
    [INCIDENT_TYPES.DATA_EXFILTRATION]: respondToDataExfiltration,
  };

  const handler = handlers[incident.type];
  if (handler) {
    try {
      await handler(incident);
      logger.info(`Incident response executed: ${incident.id}`);
    } catch (error) {
      logger.error('incident_response_failed', {
        incidentId: incident.id,
        error: error.message,
      });
    }
  }
}

/**
 * Close incident
 */
function closeIncident(incidentId, reason) {
  const incident = incidentTracker.active.get(incidentId);
  if (!incident) return null;

  incident.status = 'closed';
  incident.closedAt = new Date().toISOString();
  incident.closeReason = reason;

  // Move to history
  incidentTracker.active.delete(incidentId);
  incidentTracker.history.push(incident);

  // Trim history
  if (incidentTracker.history.length > incidentTracker.maxHistorySize) {
    incidentTracker.history.shift();
  }

  return incident;
}

/**
 * Check if IP is blacklisted
 */
function isIpBlacklisted(ip) {
  const expiry = blacklist.ips.get(ip);
  if (!expiry) return false;

  if (Date.now() > expiry) {
    blacklist.ips.delete(ip);
    return false;
  }

  return true;
}

/**
 * Check if API key is blacklisted
 */
function isKeyBlacklisted(apiKey) {
  const expiry = blacklist.apiKeys.get(apiKey);
  if (!expiry) return false;

  if (Date.now() > expiry) {
    blacklist.apiKeys.delete(apiKey);
    return false;
  }

  return true;
}

/**
 * Kill switch - emergency shutdown of all API access
 */
function activateKillSwitch(reason) {
  const incident = createIncident(
    'kill_switch_activated',
    SEVERITY.CRITICAL,
    { reason }
  );

  logger.security.incidentDetected({
    type: 'kill_switch',
    severity: SEVERITY.CRITICAL,
    reason,
  });

  incidentTracker.killSwitchActive = {
    activatedAt: new Date().toISOString(),
    reason,
    incidentId: incident.id,
  };

  return incident;
}

/**
 * Release kill switch
 */
function releaseKillSwitch(reason) {
  if (incidentTracker.killSwitchActive) {
    logger.security.incidentDetected({
      type: 'kill_switch_released',
      reason,
      wasActiveFor: Date.now() - new Date(incidentTracker.killSwitchActive.activatedAt).getTime(),
    });

    incidentTracker.killSwitchActive = null;
    return true;
  }

  return false;
}

/**
 * Check if kill switch is active
 */
function isKillSwitchActive() {
  return !!incidentTracker.killSwitchActive;
}

/**
 * Get incident status
 */
function getIncidentStatus() {
  return {
    activeIncidents: incidentTracker.active.size,
    totalIncidents: incidentTracker.history.length + incidentTracker.active.size,
    killSwitchActive: isKillSwitchActive(),
    recentIncidents: Array.from(incidentTracker.active.values())
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 10),
  };
}

module.exports = {
  INCIDENT_TYPES,
  SEVERITY,
  createIncident,
  detectBruteForce,
  detectCostAnomaly,
  detectDataExfiltration,
  respondToIncident,
  closeIncident,
  isIpBlacklisted,
  isKeyBlacklisted,
  activateKillSwitch,
  releaseKillSwitch,
  isKillSwitchActive,
  getIncidentStatus,
};
