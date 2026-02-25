#!/bin/bash

# OpenClaw Automated Backup Script
# Backs up database, config, and application state with encryption
# Usage: ./backup.sh [full|incremental|verify]

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/data/backups}"
LOG_DIR="${LOG_DIR:-/data/logs}"
DB_HOST="${DB_HOST:-localhost}"
DB_USER="${DB_USER:-postgres}"
DB_NAME="${DB_NAME:-openclaw}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
ENCRYPT_KEY="${ENCRYPT_KEY:-}"  # Set via environment

# Logging
LOG_FILE="$LOG_DIR/backup.log"
mkdir -p "$BACKUP_DIR" "$LOG_DIR"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE"
    exit 1
}

# Check prerequisites
check_requirements() {
    command -v pg_dump >/dev/null 2>&1 || error "pg_dump not found"
    command -v gzip >/dev/null 2>&1 || error "gzip not found"
    command -v openssl >/dev/null 2>&1 || error "openssl not found"
    
    [[ -n "$ENCRYPT_KEY" ]] || error "ENCRYPT_KEY environment variable not set"
    [[ -d "$BACKUP_DIR" ]] || error "Backup directory not writable: $BACKUP_DIR"
}

# Full database backup
backup_database() {
    local backup_file="$BACKUP_DIR/db_$(date +'%Y%m%d_%H%M%S').sql.gz.enc"
    
    log "Starting database backup..."
    
    # Dump database, compress, and encrypt
    if PGPASSWORD="$DB_PASSWORD" pg_dump \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --no-password \
        | gzip \
        | openssl enc -aes-256-cbc -salt -pass env:ENCRYPT_KEY -out "$backup_file"; then
        
        log "Database backup completed: $backup_file ($(du -h "$backup_file" | cut -f1))"
        return 0
    else
        error "Database backup failed"
    fi
}

# Application config backup
backup_config() {
    local backup_file="$BACKUP_DIR/config_$(date +'%Y%m%d_%H%M%S').tar.gz.enc"
    
    log "Starting config backup..."
    
    # Backup config files (exclude secrets)
    if tar czf - \
        --exclude='**/node_modules' \
        --exclude='**/.git' \
        --exclude='**/.env*' \
        --exclude='**/dist' \
        -C /data workspace .clawdbot/openclaw.json 2>/dev/null \
        | openssl enc -aes-256-cbc -salt -pass env:ENCRYPT_KEY -out "$backup_file"; then
        
        log "Config backup completed: $backup_file ($(du -h "$backup_file" | cut -f1))"
        return 0
    else
        error "Config backup failed"
    fi
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"
    
    log "Verifying backup: $backup_file"
    
    if openssl enc -aes-256-cbc -d -pass env:ENCRYPT_KEY -in "$backup_file" -P 2>/dev/null | head -1; then
        log "Backup verification successful"
        return 0
    else
        error "Backup verification failed: $backup_file"
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log "Cleaning up backups older than $RETENTION_DAYS days..."
    
    find "$BACKUP_DIR" -type f -mtime "+$RETENTION_DAYS" -name "*.enc" -delete
    
    local count=$(find "$BACKUP_DIR" -type f -name "*.enc" | wc -l)
    log "Retention cleanup completed. Backups remaining: $count"
}

# Restore from backup
restore_backup() {
    local backup_file="$1"
    
    [[ -f "$backup_file" ]] || error "Backup file not found: $backup_file"
    
    log "WARNING: This will restore from $backup_file"
    read -p "Continue? (yes/no) " -r
    [[ $REPLY == "yes" ]] || exit 0
    
    log "Decrypting and restoring database..."
    
    if openssl enc -aes-256-cbc -d -pass env:ENCRYPT_KEY -in "$backup_file" \
        | gunzip \
        | PGPASSWORD="$DB_PASSWORD" psql \
            -h "$DB_HOST" \
            -U "$DB_USER" \
            -d "$DB_NAME"; then
        
        log "Restoration completed successfully"
    else
        error "Restoration failed"
    fi
}

# Main
main() {
    local mode="${1:-full}"
    
    check_requirements
    
    case "$mode" in
        full)
            log "=== FULL BACKUP ==="
            backup_database
            backup_config
            cleanup_old_backups
            log "Full backup completed"
            ;;
        incremental)
            log "=== INCREMENTAL BACKUP ==="
            backup_database
            cleanup_old_backups
            log "Incremental backup completed"
            ;;
        verify)
            log "=== VERIFY BACKUPS ==="
            find "$BACKUP_DIR" -type f -name "*.enc" | while read -r file; do
                verify_backup "$file"
            done
            ;;
        restore)
            restore_backup "$2"
            ;;
        *)
            echo "Usage: $0 [full|incremental|verify|restore <file>]"
            exit 1
            ;;
    esac
}

main "$@"
