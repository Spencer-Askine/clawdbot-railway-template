/**
 * Automated Key Rotation
 * 
 * Manages API key lifecycle:
 * - Tracks key age
 * - Issues reminders (80 days: warning, 90 days: urgent)
 * - Schedules rotation dates
 * - Logs rotation history
 * - Validates new keys before activation
 */

const logger = require('../security/logger');

// Key management state
const keyStore = {
  keys: new Map(),      // {keyId: {name, type, createdAt, lastRotated, expiresAt, status}}
  rotationSchedule: [], // [{keyId, scheduledFor, status}]
  rotationHistory: [],  // [{keyId, rotatedAt, newKeyId, reason}]
};

// Key configuration
const KEY_CONFIG = {
  anthropic: {
    maxAgeMonths: 12,    // Rotate every 12 months
    warningDays: 80,     // Warn 80 days before expiry
    urgentDays: 10,      // Urgent 10 days before expiry
  },
  discord: {
    maxAgeMonths: 6,     // Rotate every 6 months
    warningDays: 50,
    urgentDays: 7,
  },
  gateway: {
    maxAgeMonths: 12,
    warningDays: 80,
    urgentDays: 10,
  },
};

/**
 * Register a key for tracking
 */
function registerKey(keyId, metadata) {
  const {
    name,
    type,           // 'anthropic' | 'discord' | 'gateway'
    createdAt = new Date(),
    status = 'active',
  } = metadata;

  const config = KEY_CONFIG[type];
  if (!config) {
    throw new Error(`Unknown key type: ${type}`);
  }

  const expiresAt = new Date(createdAt);
  expiresAt.setMonth(expiresAt.getMonth() + config.maxAgeMonths);

  keyStore.keys.set(keyId, {
    keyId,
    name,
    type,
    createdAt,
    lastRotated: createdAt,
    expiresAt,
    status,
    rotationCount: 0,
  });

  logger.security.keyManagement({
    action: 'key_registered',
    keyId: keyId.slice(-4),
    type,
    expiresAt,
  });

  return keyStore.keys.get(keyId);
}

/**
 * Get days until key expiry
 */
function getDaysUntilExpiry(keyId) {
  const key = keyStore.keys.get(keyId);
  if (!key) return null;

  const now = new Date();
  const expiryTime = new Date(key.expiresAt).getTime();
  const nowTime = now.getTime();
  const daysDiff = Math.floor((expiryTime - nowTime) / (1000 * 60 * 60 * 24));

  return daysDiff;
}

/**
 * Get rotation status for a key
 */
function getRotationStatus(keyId) {
  const key = keyStore.keys.get(keyId);
  if (!key) return null;

  const daysUntilExpiry = getDaysUntilExpiry(keyId);
  const config = KEY_CONFIG[key.type];

  let status = 'ok';
  let action = null;

  if (daysUntilExpiry <= 0) {
    status = 'expired';
    action = 'revoke_immediately';
  } else if (daysUntilExpiry <= config.urgentDays) {
    status = 'urgent';
    action = 'rotate_now';
  } else if (daysUntilExpiry <= config.warningDays) {
    status = 'warning';
    action = 'schedule_rotation';
  }

  return {
    keyId,
    name: key.name,
    type: key.type,
    status,
    daysUntilExpiry,
    expiresAt: key.expiresAt,
    createdAt: key.createdAt,
    rotationCount: key.rotationCount,
    action,
  };
}

/**
 * Check all keys and return those needing attention
 */
function getKeysNeedingRotation() {
  const needsAttention = [];

  for (const [keyId, key] of keyStore.keys) {
    if (key.status !== 'active') continue;

    const rotationStatus = getRotationStatus(keyId);
    if (['expired', 'urgent', 'warning'].includes(rotationStatus.status)) {
      needsAttention.push(rotationStatus);
    }
  }

  return needsAttention.sort((a, b) => a.daysUntilExpiry - b.daysUntilExpiry);
}

/**
 * Schedule a key rotation
 */
function scheduleRotation(keyId, newKeyId, scheduledFor = 'immediately') {
  const key = keyStore.keys.get(keyId);
  if (!key) {
    throw new Error(`Key not found: ${keyId}`);
  }

  const scheduledDate = scheduledFor === 'immediately'
    ? new Date()
    : new Date(scheduledFor);

  const rotation = {
    keyId,
    newKeyId,
    scheduledFor: scheduledDate,
    status: 'scheduled',
    createdAt: new Date(),
  };

  keyStore.rotationSchedule.push(rotation);

  logger.security.keyManagement({
    action: 'rotation_scheduled',
    oldKeyId: keyId.slice(-4),
    newKeyId: newKeyId.slice(-4),
    scheduledFor: scheduledDate,
  });

  return rotation;
}

/**
 * Execute key rotation
 */
function executeRotation(keyId, newKeyId, metadata = {}) {
  const oldKey = keyStore.keys.get(keyId);
  if (!oldKey) {
    throw new Error(`Old key not found: ${keyId}`);
  }

  // Validate new key (basic check)
  if (!newKeyId || newKeyId.length < 10) {
    throw new Error('Invalid new key ID');
  }

  // Mark old key as rotated
  oldKey.status = 'rotated';
  oldKey.rotatedAt = new Date();

  // Register new key
  registerKey(newKeyId, {
    name: oldKey.name,
    type: oldKey.type,
    status: 'active',
  });

  // Update rotation count
  const newKey = keyStore.keys.get(newKeyId);
  newKey.rotationCount = (oldKey.rotationCount || 0) + 1;

  // Record in history
  const historyEntry = {
    rotatedAt: new Date(),
    oldKeyId: keyId,
    newKeyId,
    reason: metadata.reason || 'scheduled',
    initiatedBy: metadata.initiatedBy || 'system',
  };
  keyStore.rotationHistory.push(historyEntry);

  // Remove from scheduled
  keyStore.rotationSchedule = keyStore.rotationSchedule.filter(
    r => r.keyId !== keyId || r.status !== 'scheduled'
  );

  logger.security.keyManagement({
    action: 'key_rotated',
    oldKeyId: keyId.slice(-4),
    newKeyId: newKeyId.slice(-4),
    reason: metadata.reason,
    rotationNumber: newKey.rotationCount,
  });

  return {
    oldKey,
    newKey,
    history: historyEntry,
  };
}

/**
 * Revoke a key (mark as inactive)
 */
function revokeKey(keyId, reason = 'unknown') {
  const key = keyStore.keys.get(keyId);
  if (!key) {
    throw new Error(`Key not found: ${keyId}`);
  }

  key.status = 'revoked';
  key.revokedAt = new Date();
  key.revokeReason = reason;

  logger.security.keyManagement({
    action: 'key_revoked',
    keyId: keyId.slice(-4),
    reason,
  });

  return key;
}

/**
 * Get rotation schedule (upcoming rotations)
 */
function getRotationSchedule() {
  return keyStore.rotationSchedule
    .filter(r => r.status === 'scheduled')
    .sort((a, b) => new Date(a.scheduledFor) - new Date(b.scheduledFor));
}

/**
 * Get rotation history
 */
function getRotationHistory(type = null, limit = 50) {
  let history = [...keyStore.rotationHistory];

  if (type) {
    const typeKey = keyStore.keys.get(history[0]?.oldKeyId);
    if (typeKey) {
      history = history.filter(h => {
        const k = keyStore.keys.get(h.oldKeyId);
        return k && k.type === type;
      });
    }
  }

  return history.slice(-limit).reverse();
}

/**
 * Generate rotation report (for alerts/dashboards)
 */
function getRotationReport() {
  const allKeys = Array.from(keyStore.keys.values());
  const needsAttention = getKeysNeedingRotation();
  const scheduled = getRotationSchedule();

  return {
    timestamp: new Date().toISOString(),
    summary: {
      totalKeys: allKeys.length,
      activeKeys: allKeys.filter(k => k.status === 'active').length,
      keysNeedingRotation: needsAttention.length,
      scheduledRotations: scheduled.length,
    },
    needsAttention,
    scheduled,
    recent: getRotationHistory(null, 5),
  };
}

/**
 * Validate key before activation
 */
async function validateKey(keyType, keyValue) {
  // This is where you'd add actual validation logic
  // e.g., test API call to verify key works

  if (!keyValue || keyValue.length < 10) {
    return { valid: false, reason: 'Key too short' };
  }

  // Placeholder validation
  return { valid: true };
}

/**
 * Run daily rotation check (call from cron)
 */
function runDailyRotationCheck() {
  const needsAttention = getKeysNeedingRotation();

  logger.info('Daily key rotation check', {
    checkedKeys: keyStore.keys.size,
    needsAttention: needsAttention.length,
  });

  const alerts = [];

  for (const key of needsAttention) {
    if (key.status === 'expired') {
      alerts.push({
        severity: 'critical',
        key: key.name,
        message: `Key has EXPIRED (${key.type})`,
        action: 'Revoke immediately',
      });
    } else if (key.status === 'urgent') {
      alerts.push({
        severity: 'high',
        key: key.name,
        message: `Key expires in ${key.daysUntilExpiry} days (${key.type})`,
        action: 'Schedule rotation today',
      });
    } else if (key.status === 'warning') {
      alerts.push({
        severity: 'medium',
        key: key.name,
        message: `Key expires in ${key.daysUntilExpiry} days (${key.type})`,
        action: 'Plan rotation soon',
      });
    }
  }

  // Log all alerts
  for (const alert of alerts) {
    logger.security.keyRotationAlert(alert);
  }

  return {
    timestamp: new Date().toISOString(),
    alerts,
  };
}

/**
 * Export key audit for compliance
 */
function getKeyAudit() {
  return {
    exportDate: new Date().toISOString(),
    keys: Array.from(keyStore.keys.values()).map(key => ({
      name: key.name,
      type: key.type,
      status: key.status,
      createdAt: key.createdAt,
      lastRotated: key.lastRotated,
      expiresAt: key.expiresAt,
      rotationCount: key.rotationCount,
    })),
    rotations: keyStore.rotationHistory.length,
    latestRotation: keyStore.rotationHistory[keyStore.rotationHistory.length - 1],
  };
}

module.exports = {
  registerKey,
  getDaysUntilExpiry,
  getRotationStatus,
  getKeysNeedingRotation,
  scheduleRotation,
  executeRotation,
  revokeKey,
  getRotationSchedule,
  getRotationHistory,
  getRotationReport,
  validateKey,
  runDailyRotationCheck,
  getKeyAudit,
  KEY_CONFIG,
};
