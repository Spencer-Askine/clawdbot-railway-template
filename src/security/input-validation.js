/**
 * Input Validation & Prompt Injection Defense
 * 
 * Validates all user inputs before they reach the model.
 * Detects and blocks common prompt injection patterns.
 */

const logger = require('./logger');

// Prompt injection patterns to block
const INJECTION_PATTERNS = [
  // Instruction override attempts
  /ignore\s+(all\s+)?your\s+(instructions|prompt|system)/i,
  /forget\s+(all\s+)?your\s+(instructions|prompt|rules)/i,
  /you\s+are\s+now\s+(a\s+)?jailbreak/i,
  /act\s+as\s+(an?\s+)?(unrestricted|uncensored)/i,
  /disregard\s+(all\s+)?(your\s+)?rules/i,
  /ignore\s+everything\s+above/i,
  /reveal\s+your\s+(system\s+)?prompt/i,
  /show\s+me\s+your\s+instructions/i,
  /what\s+is\s+your\s+system\s+prompt/i,
  
  // DAN (Do Anything Now) attempts
  /dan\s+mode/i,
  /developer\s+mode/i,
  /admin\s+mode/i,
  
  // SQL injection patterns
  /('\s*or\s*'1'\s*=\s*'1|"\s*or\s*"1"\s*=\s*"1|;\s*drop\s+table)/i,
  
  // Path traversal
  /\.\.\s*\/\s*\.\.\s*\//,
  /\.\.\\\.\.\\)/,
];

// PII patterns to detect
const PII_PATTERNS = {
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  phone: /\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
};

/**
 * Validate input length
 */
function validateLength(input, maxLength = 4000) {
  if (!input || typeof input !== 'string') {
    return {
      valid: false,
      error: 'Input must be a non-empty string',
    };
  }

  if (input.length > maxLength) {
    return {
      valid: false,
      error: `Input exceeds maximum length of ${maxLength} characters`,
    };
  }

  return { valid: true };
}

/**
 * Check for prompt injection patterns
 */
function detectInjection(input) {
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      return {
        detected: true,
        pattern: pattern.toString(),
      };
    }
  }
  return { detected: false };
}

/**
 * Check for PII in input
 */
function detectPII(input) {
  const detected = {};
  
  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    const matches = input.match(pattern);
    if (matches) {
      detected[type] = matches.length;
    }
  }

  return Object.keys(detected).length > 0 ? detected : null;
}

/**
 * Sanitize input (remove dangerous characters)
 */
function sanitizeInput(input) {
  // Remove null bytes
  let sanitized = input.replace(/\x00/g, '');
  
  // Remove excessive whitespace
  sanitized = sanitized.replace(/\s{4,}/g, '   ');
  
  return sanitized;
}

/**
 * Comprehensive input validation
 */
function validateInput(input, options = {}) {
  const {
    maxLength = 4000,
    checkInjection = true,
    checkPII = false,
    sanitize = false,
  } = options;

  // Length check
  const lengthCheck = validateLength(input, maxLength);
  if (!lengthCheck.valid) {
    return {
      valid: false,
      error: lengthCheck.error,
      action: 'reject',
    };
  }

  // Injection check
  if (checkInjection) {
    const injectionCheck = detectInjection(input);
    if (injectionCheck.detected) {
      logger.security.injectionDetected({
        pattern: injectionCheck.pattern,
        inputLength: input.length,
        inputPreview: input.substring(0, 100),
      });

      return {
        valid: false,
        error: 'Suspicious input pattern detected. This input cannot be processed.',
        action: 'reject',
        detail: 'prompt_injection_blocked',
      };
    }
  }

  // PII check
  if (checkPII) {
    const piiCheck = detectPII(input);
    if (piiCheck) {
      logger.security.suspiciousActivity({
        type: 'pii_detected',
        detected: piiCheck,
        inputLength: input.length,
      });

      // Warning only, but could be rejected based on policy
      return {
        valid: true,
        warning: `Personal information detected: ${Object.keys(piiCheck).join(', ')}`,
        action: 'warn',
      };
    }
  }

  // Sanitize if requested
  if (sanitize) {
    return {
      valid: true,
      input: sanitizeInput(input),
    };
  }

  return { valid: true, input };
}

/**
 * Validate conversation (array of messages)
 */
function validateConversation(messages, options = {}) {
  if (!Array.isArray(messages)) {
    return {
      valid: false,
      error: 'Messages must be an array',
    };
  }

  const maxTurns = options.maxTurns || 50;
  if (messages.length > maxTurns) {
    return {
      valid: false,
      error: `Conversation exceeds maximum of ${maxTurns} turns`,
    };
  }

  // Validate each message
  const validated = [];
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];

    if (!msg.content || typeof msg.content !== 'string') {
      return {
        valid: false,
        error: `Message ${i + 1}: missing or invalid content`,
      };
    }

    const validation = validateInput(msg.content, options);
    if (!validation.valid) {
      return {
        valid: false,
        error: `Message ${i + 1}: ${validation.error}`,
      };
    }

    validated.push(msg);
  }

  return { valid: true, messages: validated };
}

/**
 * Middleware for request validation
 */
function validationMiddleware(options = {}) {
  return (req, res, next) => {
    // Validate body if present
    if (req.body && req.body.prompt) {
      const validation = validateInput(req.body.prompt, options);

      if (!validation.valid) {
        logger.security.injectionDetected({
          userId: req.user?.id,
          ip: req.ip,
          detail: validation.detail,
        });

        return res.status(400).json({
          error: validation.error,
          code: 'INVALID_INPUT',
        });
      }

      // Attach validated input
      req.validatedInput = validation.input || req.body.prompt;
    }

    // Validate conversation if present
    if (req.body && req.body.messages) {
      const validation = validateConversation(req.body.messages, options);

      if (!validation.valid) {
        logger.security.injectionDetected({
          userId: req.user?.id,
          ip: req.ip,
          detail: 'conversation_validation_failed',
        });

        return res.status(400).json({
          error: validation.error,
          code: 'INVALID_CONVERSATION',
        });
      }

      req.validatedMessages = validation.messages;
    }

    next();
  };
}

module.exports = {
  validateInput,
  validateConversation,
  validateLength,
  detectInjection,
  detectPII,
  sanitizeInput,
  validationMiddleware,
  INJECTION_PATTERNS,
  PII_PATTERNS,
};
