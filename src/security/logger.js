/**
 * Structured Security Logger
 * 
 * Outputs JSON logs for security events, API calls, errors, and audit trail.
 * Integrates with monitoring/SIEM systems.
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || '/data/logs';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// Create logs directory if it doesn't exist
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const LOG_LEVELS = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  critical: 5,
};

const CURRENT_LOG_LEVEL = LOG_LEVELS[LOG_LEVEL] || LOG_LEVELS.info;

/**
 * Sanitize sensitive data from logs
 */
function sanitize(obj) {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const sensitiveFields = [
    'password',
    'token',
    'key',
    'secret',
    'apiKey',
    'authorization',
    'credit_card',
    'ssn',
  ];

  const sanitized = JSON.parse(JSON.stringify(obj));

  function walk(current) {
    for (const key in current) {
      if (current.hasOwnProperty(key)) {
        const lowerKey = key.toLowerCase();
        const isSensitive = sensitiveFields.some(
          field => lowerKey.includes(field)
        );

        if (isSensitive) {
          if (typeof current[key] === 'string') {
            // Show only last 4 chars
            const value = current[key];
            current[key] = value.length > 4 
              ? `***${value.slice(-4)}` 
              : '***';
          } else {
            current[key] = '[REDACTED]';
          }
        } else if (typeof current[key] === 'object' && current[key] !== null) {
          walk(current[key]);
        }
      }
    }
  }

  walk(sanitized);
  return sanitized;
}

/**
 * Format log entry
 */
function formatLogEntry(level, category, event, data = {}) {
  return {
    timestamp: new Date().toISOString(),
    level,
    category,
    event,
    data: sanitize(data),
    pid: process.pid,
    hostname: process.env.HOSTNAME || 'unknown',
  };
}

/**
 * Write log to file (JSON)
 */
function writeLog(entry) {
  try {
    const logFile = path.join(LOG_DIR, 'security.log');
    fs.appendFileSync(
      logFile,
      JSON.stringify(entry) + '\n'
    );
  } catch (error) {
    console.error('Failed to write log:', error.message);
  }
}

/**
 * Log to console (formatted)
 */
function consoleLog(entry) {
  const level = entry.level.toUpperCase();
  const emoji = {
    'TRACE': '📝',
    'DEBUG': '🐛',
    'INFO': 'ℹ️',
    'WARN': '⚠️',
    'ERROR': '❌',
    'CRITICAL': '🛑',
  }[level] || '•';

  console.log(
    `${emoji} [${entry.timestamp}] ${level} [${entry.category}:${entry.event}]`,
    JSON.stringify(entry.data, null, 2)
  );
}

/**
 * Log function
 */
function log(levelName, category, event, data = {}) {
  const level = LOG_LEVELS[levelName] || LOG_LEVELS.info;

  if (level < CURRENT_LOG_LEVEL) {
    return; // Skip if below log level
  }

  const entry = formatLogEntry(levelName, category, event, data);

  // Write to file (all logs)
  writeLog(entry);

  // Write to console (warn and above)
  if (level >= LOG_LEVELS.warn) {
    consoleLog(entry);
  }
}

/**
 * Public API
 */
const logger = {
  trace: (event, data) => log('trace', 'system', event, data),
  debug: (event, data) => log('debug', 'system', event, data),
  info: (event, data) => log('info', 'system', event, data),
  warn: (event, data) => log('warn', 'system', event, data),
  error: (event, data) => log('error', 'system', event, data),
  critical: (event, data) => log('critical', 'system', event, data),

  // Specialized logging methods
  auth: {
    login: (data) => log('info', 'auth', 'login_success', data),
    loginFailed: (data) => log('warn', 'auth', 'login_failed', data),
    logout: (data) => log('info', 'auth', 'logout', data),
    tokenRefresh: (data) => log('info', 'auth', 'token_refresh', data),
    permissionDenied: (data) => log('warn', 'auth', 'permission_denied', data),
  },

  api: {
    request: (data) => log('debug', 'api', 'request', data),
    response: (data) => log('debug', 'api', 'response', data),
    error: (data) => log('error', 'api', 'error', data),
  },

  security: {
    injectionDetected: (data) => log('warn', 'security', 'injection_detected', data),
    rateLimited: (data) => log('warn', 'security', 'rate_limited', data),
    unauthorized: (data) => log('warn', 'security', 'unauthorized', data),
    suspiciousActivity: (data) => log('warn', 'security', 'suspicious_activity', data),
    incidentDetected: (data) => log('critical', 'security', 'incident_detected', data),
  },

  cost: {
    tracking: (data) => log('info', 'cost', 'tracking', data),
    warning: (data) => log('warn', 'cost', 'warning', data),
    circuitBreaker: (data) => log('critical', 'cost', 'circuit_breaker', data),
  },

  audit: {
    configChange: (data) => log('info', 'audit', 'config_change', data),
    keyRotation: (data) => log('info', 'audit', 'key_rotation', data),
    userChange: (data) => log('info', 'audit', 'user_change', data),
  },
};

module.exports = logger;
