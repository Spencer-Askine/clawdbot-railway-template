#!/bin/bash

# Setup Cron Jobs for OpenClaw Security Maintenance
# Run this once to install all automated security tasks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/data/logs"
BACKUP_DIR="/data/backups"

# Create required directories
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# Ensure scripts are executable
chmod +x "$SCRIPT_DIR/backup.sh"

# Environment setup (create if doesn't exist)
CRON_ENV="/etc/environment.d/openclaw-cron.sh"
if [[ ! -f "$CRON_ENV" ]]; then
    cat > "$CRON_ENV" <<EOF
#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LOG_DIR="$LOG_DIR"
export BACKUP_DIR="$BACKUP_DIR"
export ENCRYPT_KEY="\$ENCRYPT_KEY"  # Must be set in environment
export DB_PASSWORD="\$DB_PASSWORD"  # Must be set in environment
EOF
    chmod 600 "$CRON_ENV"
    echo "Created cron environment: $CRON_ENV"
fi

# Create crontab entries
CRON_FILE="/tmp/openclaw-cron.txt"
cat > "$CRON_FILE" <<'EOF'
# OpenClaw Security Cron Jobs

# Full backup daily at 2 AM
0 2 * * * source /etc/environment.d/openclaw-cron.sh && /data/workspace/scripts/backup.sh full >> /data/logs/backup-daily.log 2>&1

# Incremental backup every 6 hours
0 */6 * * * source /etc/environment.d/openclaw-cron.sh && /data/workspace/scripts/backup.sh incremental >> /data/logs/backup-incremental.log 2>&1

# Verify backups daily at 4 AM
0 4 * * * source /etc/environment.d/openclaw-cron.sh && /data/workspace/scripts/backup.sh verify >> /data/logs/backup-verify.log 2>&1

# Cleanup logs older than 30 days (daily at 3 AM)
0 3 * * * find /data/logs -type f -name "*.log" -mtime +30 -delete

# Security audit checks (daily at 1 AM)
0 1 * * * source /etc/environment.d/openclaw-cron.sh && /data/workspace/scripts/security-audit.sh >> /data/logs/security-audit.log 2>&1
EOF

# Install crontab (for root or current user)
if [[ "$EUID" -eq 0 ]]; then
    crontab "$CRON_FILE"
    echo "Installed system crontab (root)"
else
    crontab "$CRON_FILE"
    echo "Installed user crontab for $(whoami)"
fi

# Verify installation
echo ""
echo "=== Installed Cron Jobs ==="
crontab -l

# Cleanup
rm "$CRON_FILE"

echo ""
echo "✅ Cron setup completed"
echo ""
echo "⚠️  IMPORTANT: Ensure these environment variables are set:"
echo "   - ENCRYPT_KEY (for backup encryption)"
echo "   - DB_PASSWORD (for database backups)"
echo ""
echo "Add to your systemd service or docker-compose.yml as needed."
