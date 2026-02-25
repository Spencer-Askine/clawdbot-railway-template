/**
 * Secrets Validator
 * 
 * Runs on application startup.
 * Checks that all required environment variables are present and valid.
 * Refuses to start if any checks fail.
 */

const crypto = require('crypto');
const logger = require('./logger');

// Define required secrets and their validation rules
const REQUIRED_SECRETS = {
  ANTHROPIC_API_KEY: {
    pattern: /^sk-ant-api03-[a-zA-Z0-9_-]{80,}$/,
    description: 'Anthropic API key (sk-ant-api03-...)',
    isExample: false,
  },
  DISCORD_BOT_TOKEN: {
    pattern: /^[A-Za-z0-9_-]{24,}\.G[a-zA-Z0-9_-]{6,}\.[-_a-zA-Z0-9]{27,}$/,
    description: 'Discord bot token',
    isExample: false,
  },
  OPENCLAW_GATEWAY_TOKEN: {
    pattern: /^[a-f0-9]{64}$/,
    description: 'OpenClaw gateway auth token (64 hex chars)',
    isExample: false,
  },
  JWT_SECRET: {
    pattern: /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{64,}$/,
    description: 'JWT signing secret (min 64 chars)',
    minLength: 64,
    isExample: false,
  },
};

// Placeholder/example values that should NEVER be in production
const DANGEROUS_VALUES = [
  'YOUR-KEY-HERE',
  'YOUR-TOKEN-HERE',
  'PLACEHOLDER',
  'EXAMPLE',
  'sk-ant-YOUR-KEY',
  'your-key',
  'change-me',
  'changeme',
  'xxx',
  'test',
  'demo',
];

/**
 * Validate a single secret
 */
function validateSecret(name, value, rules) {
  // Check if present
  if (!value || value.trim() === '') {
    return {
      valid: false,
      error: `MISSING: ${name} (${rules.description})`,
      critical: true,
    };
  }

  // Check if placeholder/example value
  const lowerValue = value.toLowerCase();
  for (const dangerous of DANGEROUS_VALUES) {
    if (lowerValue.includes(dangerous.toLowerCase())) {
      return {
        valid: false,
        error: `PLACEHOLDER DETECTED: ${name} contains example value "${dangerous}". Replace with real credentials.`,
        critical: true,
      };
    }
  }

  // Validate pattern
  if (rules.pattern && !rules.pattern.test(value)) {
    return {
      valid: false,
      error: `INVALID FORMAT: ${name} does not match expected pattern. Expected: ${rules.description}`,
      critical: true,
    };
  }

  // Check minimum length
  if (rules.minLength && value.length < rules.minLength) {
    return {
      valid: false,
      error: `TOO SHORT: ${name} must be at least ${rules.minLength} characters`,
      critical: true,
    };
  }

  return {
    valid: true,
    name,
    length: value.length,
  };
}

/**
 * Main validation function
 */
function validateSecrets() {
  logger.info('🔐 Starting secrets validation...');

  const results = {
    passed: [],
    failed: [],
    warnings: [],
  };

  // Validate each required secret
  for (const [name, rules] of Object.entries(REQUIRED_SECRETS)) {
    const value = process.env[name];
    const validation = validateSecret(name, value, rules);

    if (validation.valid) {
      results.passed.push({
        name: validation.name,
        status: '✅',
        message: `Valid (${validation.length} chars)`,
      });
    } else {
      results.failed.push({
        name,
        status: '❌',
        message: validation.error,
        critical: validation.critical,
      });
    }
  }

  // Log results
  logger.info(`\n🔐 SECRETS VALIDATION REPORT`);
  logger.info(`═══════════════════════════════\n`);

  // Passed secrets
  if (results.passed.length > 0) {
    logger.info(`✅ PASSED (${results.passed.length}):`);
    for (const result of results.passed) {
      logger.info(`   ${result.status} ${result.name}: ${result.message}`);
    }
    logger.info('');
  }

  // Failed secrets
  if (results.failed.length > 0) {
    logger.error(`\n❌ FAILED (${results.failed.length}):`);
    for (const result of results.failed) {
      logger.error(`   ${result.status} ${result.name}`);
      logger.error(`      └─ ${result.message}`);
    }
  }

  // Exit if any critical failures
  if (results.failed.length > 0) {
    logger.error('\n🛑 STARTUP BLOCKED: Fix all validation errors above before continuing.');
    logger.error('   Environment variables required:');
    for (const [name, rules] of Object.entries(REQUIRED_SECRETS)) {
      logger.error(`   - ${name} (${rules.description})`);
    }
    process.exit(1);
  }

  logger.info(`\n✅ All secrets validated successfully. Safe to start.\n`);
}

module.exports = {
  validateSecrets,
  REQUIRED_SECRETS,
};
