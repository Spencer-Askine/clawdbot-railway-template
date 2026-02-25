/**
 * Role-Based Access Control (RBAC)
 * 
 * Manages user roles, permissions, and model tier access.
 * Enforces least-privilege access throughout the system.
 */

const logger = require('./logger');

// Role definitions with permissions and model access
const ROLES = {
  owner: {
    displayName: 'Owner',
    description: 'Full system access',
    permissions: [
      'admin:all',
      'models:opus',
      'models:sonnet',
      'models:haiku',
      'keys:create',
      'keys:rotate',
      'keys:delete',
      'config:read',
      'config:write',
      'users:manage',
      'logs:read',
      'costs:view',
    ],
    modelAccess: ['opus', 'sonnet', 'haiku'],
    rateLimit: {
      requestsPerMinute: 100,
      costCapDaily: null, // No cap
      costCapMonthly: null,
    },
  },

  admin: {
    displayName: 'Administrator',
    description: 'All models + config access',
    permissions: [
      'models:opus',
      'models:sonnet',
      'models:haiku',
      'keys:rotate',
      'config:read',
      'config:write',
      'logs:read',
      'costs:view',
    ],
    modelAccess: ['opus', 'sonnet', 'haiku'],
    rateLimit: {
      requestsPerMinute: 60,
      costCapDaily: 500,
      costCapMonthly: 10000,
    },
  },

  developer: {
    displayName: 'Developer',
    description: 'Sonnet + Haiku, read-only admin',
    permissions: [
      'models:sonnet',
      'models:haiku',
      'keys:view',
      'config:read',
      'logs:read',
      'costs:view',
    ],
    modelAccess: ['sonnet', 'haiku'],
    rateLimit: {
      requestsPerMinute: 30,
      costCapDaily: 100,
      costCapMonthly: 2000,
    },
  },

  api_consumer: {
    displayName: 'API Consumer',
    description: 'Models per API key assignment',
    permissions: [
      'models:use',
      'keys:view-own',
    ],
    modelAccess: [], // Determined per API key
    rateLimit: {
      requestsPerMinute: 20,
      costCapDaily: 50,
      costCapMonthly: 1000,
    },
  },

  viewer: {
    displayName: 'Viewer',
    description: 'Dashboard read-only access',
    permissions: [
      'dashboard:view',
      'logs:read-limited',
    ],
    modelAccess: [],
    rateLimit: {
      requestsPerMinute: 10,
      costCapDaily: 0, // Can't make API calls
      costCapMonthly: 0,
    },
  },
};

/**
 * Check if a role has a specific permission
 */
function hasPermission(role, permission) {
  if (!ROLES[role]) {
    return false;
  }

  const rolePerms = ROLES[role].permissions;
  
  // Exact match
  if (rolePerms.includes(permission)) {
    return true;
  }

  // Wildcard match (e.g., "admin:*" matches "admin:all")
  for (const perm of rolePerms) {
    if (perm.endsWith('*')) {
      const prefix = perm.replace('*', '');
      if (permission.startsWith(prefix)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if a role can access a specific model
 */
function canAccessModel(role, model) {
  if (!ROLES[role]) {
    return false;
  }

  const allowedModels = ROLES[role].modelAccess;
  return allowedModels.includes(model);
}

/**
 * Get rate limit for a role
 */
function getRateLimit(role) {
  if (!ROLES[role]) {
    return null;
  }
  return ROLES[role].rateLimit;
}

/**
 * RBAC authorization middleware
 */
function rbacMiddleware(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Attach role information to request
  const roleInfo = ROLES[req.user.role];
  if (!roleInfo) {
    logger.error('rbac:invalid_role', {
      userId: req.user.id,
      role: req.user.role,
    });
    return res.status(401).json({ error: 'Invalid user role' });
  }

  req.userRole = {
    name: req.user.role,
    ...roleInfo,
  };

  next();
}

/**
 * Model access control middleware
 * Call after rbacMiddleware
 */
function requireModelAccess(requiredModel) {
  return (req, res, next) => {
    if (!req.user || !req.userRole) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Check if user's role has access to this model
    if (!canAccessModel(req.user.role, requiredModel)) {
      logger.warn('rbac:model_access_denied', {
        userId: req.user.id,
        role: req.user.role,
        requestedModel: requiredModel,
        allowedModels: req.userRole.modelAccess,
        path: req.path,
        ip: req.ip,
      });

      return res.status(403).json({
        error: 'Forbidden',
        code: 'MODEL_ACCESS_DENIED',
        message: `Your role (${req.user.role}) does not have access to ${requiredModel}. Allowed models: ${req.userRole.modelAccess.join(', ')}`,
      });
    }

    req.requestedModel = requiredModel;
    next();
  };
}

/**
 * Permission check middleware
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!hasPermission(req.user.role, permission)) {
      logger.warn('rbac:permission_denied', {
        userId: req.user.id,
        role: req.user.role,
        requiredPermission: permission,
        path: req.path,
        ip: req.ip,
      });

      return res.status(403).json({
        error: 'Forbidden',
        code: 'PERMISSION_DENIED',
        message: `Your role (${req.user.role}) does not have the "${permission}" permission`,
      });
    }

    next();
  };
}

/**
 * Get all available roles
 */
function getAllRoles() {
  return Object.entries(ROLES).map(([key, value]) => ({
    id: key,
    ...value,
  }));
}

/**
 * Get role details
 */
function getRoleDetails(role) {
  return ROLES[role] || null;
}

module.exports = {
  ROLES,
  hasPermission,
  canAccessModel,
  getRateLimit,
  rbacMiddleware,
  requireModelAccess,
  requirePermission,
  getAllRoles,
  getRoleDetails,
};
