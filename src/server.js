#!/usr/bin/env node

/**
 * OpenClaw Security-Hardened Server
 * Main entry point for hardened deployment
 */

const express = require('express');
const http = require('http');
const { createProxyMiddleware } = require('http-proxy-middleware');
const logger = require('./security/logger');
const { validateSecrets } = require('./security/secrets-validator');
const setupSecurityModules = require('./server-integration');

const PORT = process.env.PORT || 3000;
const GATEWAY_HOST = process.env.GATEWAY_HOST || 'localhost';
const GATEWAY_PORT = process.env.GATEWAY_PORT || 18789;

let server;

/**
 * Initialize and start the server
 */
async function start() {
  try {
    // Step 1: Validate all secrets on startup
    logger.info('🔐 Validating secrets...');
    validateSecrets();
    logger.info('✅ All secrets validated successfully');

    // Step 2: Create Express app
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Step 3: Setup security modules
    logger.info('🛡️  Setting up security modules...');
    setupSecurityModules(app);
    logger.info('✅ Security modules initialized');

    // Step 4: Health check endpoint (public)
    app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'ok',
        security: 'enabled',
        timestamp: new Date().toISOString(),
      });
    });

    // Step 5: Proxy all other traffic to OpenClaw gateway
    app.use(
      createProxyMiddleware({
        target: `http://${GATEWAY_HOST}:${GATEWAY_PORT}`,
        changeOrigin: true,
        logLevel: process.env.LOG_LEVEL || 'info',
        onError: (err, req, res) => {
          logger.error('Gateway proxy error', {
            error: err.message,
            path: req.path,
            method: req.method,
          });
          res.status(503).json({
            error: 'Gateway unavailable',
            message: 'OpenClaw gateway is not responding',
          });
        },
        onProxyRes: (proxyRes, req, res) => {
          // Log successful proxies
          logger.info('Gateway proxy request', {
            path: req.path,
            method: req.method,
            statusCode: proxyRes.statusCode,
          });
        },
      })
    );

    // Step 6: Error handlers
    app.use((err, req, res, next) => {
      logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        path: req.path,
      });
      res.status(500).json({
        error: 'Internal server error',
        requestId: req.id,
      });
    });

    // Step 7: Start server
    server = http.createServer(app);
    server.listen(PORT, () => {
      logger.info(`🚀 Security-hardened server listening on port ${PORT}`);
      logger.info(`📡 Proxying to OpenClaw gateway at ${GATEWAY_HOST}:${GATEWAY_PORT}`);
      logger.info('✅ Server ready for requests');
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully...');
      server.close(() => {
        logger.info('Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully...');
      server.close(() => {
        logger.info('Server closed');
        process.exit(0);
      });
    });
  } catch (error) {
    logger.critical('Server startup failed', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
}

// Start the server
start();
