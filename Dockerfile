# OpenClaw Security-Hardened Dockerfile
# Based on Node.js Alpine for minimal attack surface

FROM node:20.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (production only)
RUN npm ci --only=production && \
    npm cache clean --force

# Final stage - minimal image
FROM node:20.11-alpine

# Install security tools (optional, for hardening validation)
RUN apk add --no-cache ca-certificates curl

# Create non-root user
RUN addgroup -g 1001 openclaw && \
    adduser -u 1001 -G openclaw -s /bin/sh -D openclaw

WORKDIR /app

# Copy production dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY --chown=openclaw:openclaw . .

# Set environment
ENV NODE_ENV=production
ENV LOG_DIR=/data/logs

# Create necessary directories with correct permissions
RUN mkdir -p /data/logs && \
    chown -R openclaw:openclaw /data/logs && \
    chmod 750 /data/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
    CMD wget --spider -q http://localhost:3000/health || exit 1

# Drop unnecessary capabilities
RUN setcap -r /bin/busybox 2>/dev/null || true

# Switch to non-root user
USER openclaw

# Security: Read-only filesystem where possible
# (Note: This requires specific volume mounts)

EXPOSE 3000

CMD ["node", "src/server.js"]

# Build metadata
LABEL maintainer="security@openclaw"
LABEL version="1.0"
LABEL description="OpenClaw Security-Hardened Container"
