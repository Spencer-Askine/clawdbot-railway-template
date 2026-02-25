/**
 * Comprehensive Audit Logging
 * 
 * Records all administrative actions, config changes, and sensitive access.
 * Maintains immutable audit trail for compliance (GDPR, SOC2, etc.)
 */

const fs = require('fs');
const path = require('path');
const logger = require('../security/logger');

// In-memory audit log (backup to persistent storage)
const auditLog = [];
const maxInMemorySize = 10000;

// Audit event types
const AUDIT_EVENTS = {
  ADMIN_LOGIN: 'admin.login',
  ADMIN_LOGOUT: 'admin.logout',
  USER_CREATED: 'user.created',
  USER_DELETED: 'user.deleted',
  USER_ROLE_CHANGED: 'user.role_changed',
  ROLE_PERMISSION_CHANGED: 'role.permission_changed',
  CONFIG_CHANGED: 'config.changed',
  KEY_ROTATED: 'key.rotated',
  KEY_REVOKED: 'key.revoked',
  COST_LIMIT_CHANGED: 'cost.limit_changed',
  INCIDENT_CREATED: 'incident.created',
  INCIDENT_RESOLVED: 'incident.resolved',
  DATA_EXPORTED: 'data.exported',
  DATA_DELETED: 'data.deleted',
  SYSTEM_ALERT: 'system.alert',
  UNAUTHORIZED_ACCESS_ATTEMPT: 'unauthorized.access',
  API_CALL_HIGH_VALUE: 'api.call_high_value',
};

/**
 * Create audit log entry
 */
function createAuditEntry(event, data = {}) {
  const entry = {
    id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    event,
    actor: {
      userId: data.userId || 'system',
      ip: data.ip || 'unknown',
      userAgent: data.userAgent || null,
    },
    action: data.action || event,
    resource: {
      type: data.resourceType || null,
      id: data.resourceId || null,
      name: data.resourceName || null,
    },
    changes: data.changes || {},
    result: data.result || 'success',
    notes: data.notes || '',
    metadata: data.metadata || {},
  };

  // Validate event type
  if (!Object.values(AUDIT_EVENTS).includes(event)) {
    logger.warn('Unknown audit event type', { event });
  }

  auditLog.push(entry);

  // Trim in-memory log if too large
  if (auditLog.length > maxInMemorySize) {
    auditLog.shift();
  }

  // Log to file for persistence
  persistAuditEntry(entry);

  return entry;
}

/**
 * Persist audit entry to disk
 */
function persistAuditEntry(entry) {
  try {
    const logDir = process.env.AUDIT_LOG_DIR || '/data/logs/audit';
    const date = new Date();
    const dateStr = date.toISOString().split('T')[0];
    const logFile = path.join(logDir, `audit-${dateStr}.jsonl`);

    // Create directory if needed
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true, mode: 0o750 });
    }

    // Append to JSONL file (one JSON per line for easy parsing)
    fs.appendFileSync(
      logFile,
      JSON.stringify(entry) + '\n'
    );
  } catch (error) {
    logger.error('audit_log_persist_failed', {
      error: error.message,
      entry: entry.id,
    });
  }
}

/**
 * Log user access
 */
function logUserAccess(userId, resource, action, metadata = {}) {
  return createAuditEntry(AUDIT_EVENTS.API_CALL_HIGH_VALUE, {
    userId,
    action,
    resourceType: resource.type,
    resourceId: resource.id,
    resourceName: resource.name,
    metadata,
    result: 'success',
  });
}

/**
 * Log configuration change
 */
function logConfigChange(userId, configKey, oldValue, newValue, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.CONFIG_CHANGED, {
    userId,
    action: `Changed ${configKey}`,
    resourceType: 'config',
    resourceId: configKey,
    changes: {
      oldValue: maskSensitiveValue(oldValue),
      newValue: maskSensitiveValue(newValue),
    },
    notes: reason,
    result: 'success',
  });
}

/**
 * Log unauthorized access attempt
 */
function logUnauthorizedAccess(userId, ip, resource, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
    userId: userId || 'anonymous',
    ip,
    action: `Attempted unauthorized access to ${resource}`,
    resourceType: 'system',
    result: 'failed',
    notes: reason,
  });
}

/**
 * Log user creation
 */
function logUserCreated(createdBy, newUserId, role, metadata = {}) {
  return createAuditEntry(AUDIT_EVENTS.USER_CREATED, {
    userId: createdBy,
    action: `Created user ${newUserId} with role ${role}`,
    resourceType: 'user',
    resourceId: newUserId,
    changes: { role, ...metadata },
    result: 'success',
  });
}

/**
 * Log user deletion
 */
function logUserDeleted(deletedBy, userId, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.USER_DELETED, {
    userId: deletedBy,
    action: `Deleted user ${userId}`,
    resourceType: 'user',
    resourceId: userId,
    notes: reason,
    result: 'success',
  });
}

/**
 * Log role change
 */
function logRoleChanged(changedBy, userId, oldRole, newRole, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.USER_ROLE_CHANGED, {
    userId: changedBy,
    action: `Changed user ${userId} role from ${oldRole} to ${newRole}`,
    resourceType: 'user',
    resourceId: userId,
    changes: {
      oldRole,
      newRole,
    },
    notes: reason,
    result: 'success',
  });
}

/**
 * Log key rotation
 */
function logKeyRotation(rotatedBy, keyType, oldKeyId, newKeyId, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.KEY_ROTATED, {
    userId: rotatedBy,
    action: `Rotated ${keyType} key`,
    resourceType: 'key',
    resourceId: keyType,
    changes: {
      oldKeyLastChars: oldKeyId.slice(-4),
      newKeyLastChars: newKeyId.slice(-4),
    },
    notes: reason,
    result: 'success',
  });
}

/**
 * Log data export
 */
function logDataExport(exportedBy, dataType, rowCount, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.DATA_EXPORTED, {
    userId: exportedBy,
    action: `Exported ${rowCount} rows of ${dataType}`,
    resourceType: 'data',
    resourceId: dataType,
    metadata: { rowCount },
    notes: reason,
    result: 'success',
  });
}

/**
 * Log data deletion
 */
function logDataDeletion(deletedBy, dataType, query, rowsAffected, reason = '') {
  return createAuditEntry(AUDIT_EVENTS.DATA_DELETED, {
    userId: deletedBy,
    action: `Deleted ${rowsAffected} rows of ${dataType}`,
    resourceType: 'data',
    resourceId: dataType,
    metadata: { rowsAffected, query: maskSensitiveValue(query) },
    notes: reason,
    result: 'success',
  });
}

/**
 * Log incident creation
 */
function logIncidentCreated(incidentId, type, severity, metadata = {}) {
  return createAuditEntry(AUDIT_EVENTS.INCIDENT_CREATED, {
    action: `Incident ${type} detected`,
    resourceType: 'incident',
    resourceId: incidentId,
    metadata: { incidentType: type, severity, ...metadata },
    result: 'success',
  });
}

/**
 * Log incident resolution
 */
function logIncidentResolved(incidentId, resolution, metadata = {}) {
  return createAuditEntry(AUDIT_EVENTS.INCIDENT_RESOLVED, {
    action: `Incident ${incidentId} resolved`,
    resourceType: 'incident',
    resourceId: incidentId,
    notes: resolution,
    metadata,
    result: 'success',
  });
}

/**
 * Query audit log with filters
 */
function queryAuditLog(filters = {}) {
  let results = [...auditLog];

  // Filter by event type
  if (filters.event) {
    results = results.filter(e => e.event === filters.event);
  }

  // Filter by user
  if (filters.userId) {
    results = results.filter(e => e.actor.userId === filters.userId);
  }

  // Filter by resource type
  if (filters.resourceType) {
    results = results.filter(e => e.resource.type === filters.resourceType);
  }

  // Filter by date range
  if (filters.startDate) {
    const start = new Date(filters.startDate).getTime();
    results = results.filter(e => new Date(e.timestamp).getTime() >= start);
  }

  if (filters.endDate) {
    const end = new Date(filters.endDate).getTime();
    results = results.filter(e => new Date(e.timestamp).getTime() <= end);
  }

  // Filter by result
  if (filters.result) {
    results = results.filter(e => e.result === filters.result);
  }

  // Sort by timestamp (newest first)
  results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Limit results
  if (filters.limit) {
    results = results.slice(0, filters.limit);
  }

  return results;
}

/**
 * Get audit summary
 */
function getAuditSummary(hoursBack = 24) {
  const cutoff = new Date(Date.now() - (hoursBack * 60 * 60 * 1000));
  const recent = auditLog.filter(e => new Date(e.timestamp) > cutoff);

  const eventCounts = {};
  const userActions = {};

  for (const entry of recent) {
    eventCounts[entry.event] = (eventCounts[entry.event] || 0) + 1;
    userActions[entry.actor.userId] = (userActions[entry.actor.userId] || 0) + 1;
  }

  return {
    timeRange: {
      hours: hoursBack,
      from: cutoff.toISOString(),
      to: new Date().toISOString(),
    },
    totalEvents: recent.length,
    eventTypes: eventCounts,
    topUsers: Object.entries(userActions)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .reduce((acc, [user, count]) => ({ ...acc, [user]: count }), {}),
  };
}

/**
 * Export audit log for compliance
 */
function exportAuditLog(format = 'json', filters = {}) {
  const results = queryAuditLog(filters);

  if (format === 'csv') {
    return convertToCsv(results);
  } else if (format === 'json') {
    return JSON.stringify(results, null, 2);
  } else {
    throw new Error(`Unsupported format: ${format}`);
  }
}

/**
 * Convert to CSV format
 */
function convertToCsv(data) {
  const headers = ['Timestamp', 'Event', 'User', 'IP', 'Resource', 'Action', 'Result'];
  const rows = data.map(e => [
    e.timestamp,
    e.event,
    e.actor.userId,
    e.actor.ip,
    `${e.resource.type}/${e.resource.id}`,
    e.action,
    e.result,
  ]);

  const csv = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
  ].join('\n');

  return csv;
}

/**
 * Mask sensitive values in logs
 */
function maskSensitiveValue(value) {
  if (!value) return value;

  const str = String(value);

  // Mask API keys
  if (str.includes('sk-') || str.includes('token')) {
    return '***REDACTED***';
  }

  // Mask passwords
  if (str.toLowerCase().includes('password')) {
    return '***REDACTED***';
  }

  return value;
}

/**
 * Get audit log statistics
 */
function getAuditStats() {
  const events = {};
  const users = new Set();

  for (const entry of auditLog) {
    events[entry.event] = (events[entry.event] || 0) + 1;
    users.add(entry.actor.userId);
  }

  return {
    totalEntries: auditLog.length,
    uniqueEventTypes: Object.keys(events).length,
    uniqueUsers: users.size,
    eventBreakdown: events,
    oldestEntry: auditLog[0]?.timestamp,
    newestEntry: auditLog[auditLog.length - 1]?.timestamp,
  };
}

module.exports = {
  AUDIT_EVENTS,
  createAuditEntry,
  logUserAccess,
  logConfigChange,
  logUnauthorizedAccess,
  logUserCreated,
  logUserDeleted,
  logRoleChanged,
  logKeyRotation,
  logDataExport,
  logDataDeletion,
  logIncidentCreated,
  logIncidentResolved,
  queryAuditLog,
  getAuditSummary,
  exportAuditLog,
  getAuditStats,
};
