# Operational Runbooks
**OpenClaw Day-to-Day Operations**

---

## 📋 **TABLE OF CONTENTS**

1. [Startup Procedure](#startup)
2. [Shutdown Procedure](#shutdown)
3. [Key Rotation](#key-rotation)
4. [Backup & Restore](#backup-restore)
5. [Database Operations](#database)
6. [Scaling & Performance](#scaling)
7. [Log Management](#logs)
8. [Admin Onboarding](#onboarding)
9. [On-Call Handoff](#handoff)
10. [Disaster Recovery](#disaster-recovery)

---

## **STARTUP PROCEDURE** {#startup}

**Time:** ~10 minutes  
**Runbook:** For bringing service online after planned/unplanned downtime

### **Pre-Startup Checks** (2 min)

```bash
# 1. Check system resources
free -h                          # Memory available
df -h /data                      # Disk space (need 20GB+ free)
ps aux | grep openclaw           # Verify not already running

# 2. Check network
ping -c 3 8.8.8.8               # Internet connectivity
dig anthropic.com               # DNS working

# 3. Check database
pg_isready -h localhost -U postgres
```

### **Start the Service** (3 min)

```bash
# Option A: Docker container (Railway)
docker-compose -f docker-compose.hardened.yml up -d openclaw

# Option B: Direct process
node src/server.js &

# Verify starting
docker logs openclaw-secure --follow
```

### **Post-Startup Validation** (5 min)

```bash
# Wait 10-15 seconds for startup
sleep 15

# 1. Health check
curl http://localhost:3000/health
# Expected: { "status": "ok", "security": "enabled" }

# 2. Authentication
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"userId": "admin", "role": "owner"}'
# Expected: JWT tokens returned

# 3. Metrics
curl http://localhost:3000/metrics | head -10
# Expected: Prometheus metrics available

# 4. Log verification
tail -20 /data/logs/security.log | jq '.event' | sort | uniq
# Expected: No error events

# 5. Alert if any failures
if [ $? -ne 0 ]; then
  echo "⚠️  STARTUP VALIDATION FAILED - Check logs"
  tail -50 /data/logs/error.log
fi
```

### **Startup Checklist**

- [ ] System resources adequate
- [ ] Database connection working
- [ ] Health check passes
- [ ] Auth endpoint responding
- [ ] Metrics available
- [ ] No startup errors in logs
- [ ] Alert team of go-live

---

## **SHUTDOWN PROCEDURE** {#shutdown}

**Time:** ~5 minutes  
**Safety:** Always graceful shutdown (30s timeout)

### **Pre-Shutdown Tasks** (2 min)

```bash
# 1. Notify stakeholders
echo "OpenClaw shutting down at $(date)" | tee /data/logs/shutdown-notice.txt

# 2. Drain connections (wait for in-flight requests to complete)
# Send SIGTERM (graceful shutdown) to service
kill -TERM $(pgrep -f "node.*server.js")

# Wait for graceful shutdown (30 seconds)
sleep 30

# Verify service stopped
ps aux | grep "node.*server.js" | grep -v grep
```

### **Shutdown Execution** (2 min)

```bash
# Option A: Docker
docker-compose -f docker-compose.hardened.yml down --timeout 30

# Option B: Force kill if needed (last resort)
kill -9 $(pgrep -f "node.*server.js")
pkill -9 -f docker

# Verify
docker ps | grep openclaw
# Expected: No running containers
```

### **Post-Shutdown Verification** (1 min)

```bash
# 1. Port released
lsof -i :3000
# Expected: (nothing)

# 2. Logs finalized
tail -5 /data/logs/security.log
# Expected: Graceful shutdown logged

# 3. Data integrity
ls -la /data/.clawdbot/openclaw.json*
# Expected: Latest config file intact
```

---

## **KEY ROTATION** {#key-rotation}

**Time:** ~30 minutes  
**Frequency:** Every 90 days (or on compromise)  
**Risk:** High - requires coordinated updates

### **Pre-Rotation Planning** (5 min)

```bash
# 1. Check current key age
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/admin/key-rotation/status

# 2. Schedule rotation window (off-peak)
# Best time: Weekday midnight UTC, no active users

# 3. Notify stakeholders
# Email: "Key rotation scheduled for X date, service unaffected"
```

### **Key Rotation Steps** (15 min)

```bash
# Step 1: Generate new key
# For Anthropic API:
# 1. Go to https://console.anthropic.com
# 2. Create new API key
# 3. Copy key value

NEW_KEY="sk-ant-..."

# Step 2: Test new key (before switching)
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $NEW_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-haiku-20241022",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "test"}]
  }'
# Expected: 200 OK with response

# Step 3: Update in Railway environment
# 1. Go to Railway project settings
# 2. Set ANTHROPIC_API_KEY=$NEW_KEY
# 3. Trigger redeploy

# Step 4: Verify new key working
sleep 30
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/models/haiku/run \
  -d '{"prompt": "test"}'
# Expected: Model response

# Step 5: Monitor for 5 minutes
watch -n 5 'tail -3 /data/logs/api.log | jq ".model\|.status"'
```

### **Rollback (if issues)** (5 min)

```bash
# If new key fails:
# 1. Revert ANTHROPIC_API_KEY to old value in Railway
# 2. Trigger redeploy
# 3. Verify recovery
# 4. Investigate issue before retrying

# Revert
# 1. Railways environment variables → ANTHROPIC_API_KEY
# 2. Paste old key
# 3. Redeploy
```

### **Post-Rotation** (5 min)

```bash
# 1. Revoke old key
# Go to https://console.anthropic.com
# Delete old API key

# 2. Log rotation in audit
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/admin/audit/key-rotated \
  -d '{"keyType": "anthropic", "reason": "scheduled"}'

# 3. Update password manager
# Update stored credentials

# 4. Notify team
echo "✅ Key rotation completed for Anthropic API"

# 5. Schedule next rotation (90 days from now)
date -d "+90 days"
```

### **Key Rotation Checklist**

- [ ] Schedule window identified
- [ ] New key generated
- [ ] New key tested
- [ ] Environment updated
- [ ] Service redeployed
- [ ] New key verified working
- [ ] Old key revoked
- [ ] Audit logged
- [ ] Team notified
- [ ] Next rotation scheduled

---

## **BACKUP & RESTORE** {#backup-restore}

**Time:** Variable (5 min backup, 30 min restore)  
**Frequency:** Daily full + 6h incremental  
**Location:** `/data/backups/`

### **Manual Backup (if needed)**

```bash
# Full backup (encrypted)
/data/workspace/scripts/backup.sh full

# Verify backup created
ls -lh /data/backups/ | tail -5

# Backup size
du -sh /data/backups/db_*.enc
```

### **Verify Backup Integrity**

```bash
# Test decrypt (without actually restoring)
/data/workspace/scripts/backup.sh verify

# Check recent backups
ls -lh /data/backups/db_*.enc | tail -3
```

### **Restore Procedure** (in emergency)

```bash
# WARNING: This overwrites current database
# 1. Identify backup to restore
ls -lh /data/backups/db_*.enc | grep "2026-02-23"
# Choose backup file: db_20260223_020000.sql.gz.enc

# 2. Stop service
docker-compose -f docker-compose.hardened.yml down

# 3. Restore from backup
ENCRYPT_KEY="..." /data/workspace/scripts/backup.sh restore /data/backups/db_20260223_020000.sql.gz.enc

# 4. Verify restoration
# - Check /data/.clawdbot/ for restored config
# - Check database tables

psql -U postgres -d openclaw -c "SELECT COUNT(*) FROM users;"

# 5. Restart service
docker-compose -f docker-compose.hardened.yml up -d

# 6. Verify service working
curl http://localhost:3000/health
```

### **Restore Checklist**

- [ ] Backup file identified and verified
- [ ] Service stopped gracefully
- [ ] Database restored successfully
- [ ] Data integrity verified
- [ ] Service restarted
- [ ] Health checks passing
- [ ] Team notified of recovery

---

## **DATABASE OPERATIONS** {#database}

**Time:** Variable  
**Critical:** Requires careful procedure

### **Check Database Health**

```bash
# Connection status
psql -U postgres -d openclaw -c "\l"

# Table sizes
psql -U postgres -d openclaw -c "
  SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
  FROM pg_tables
  WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"

# Connection pool
psql -U postgres -d openclaw -c "SELECT COUNT(*) FROM pg_stat_activity;"

# Slow queries
psql -U postgres -d openclaw -c "
  SELECT query, calls, total_time, mean_time
  FROM pg_stat_statements
  ORDER BY total_time DESC LIMIT 10;
"
```

### **Run VACUUM (cleanup)** [Monthly]

```bash
# Stop service (if possible)
docker pause openclaw-secure

# Run VACUUM
psql -U postgres -d openclaw -c "VACUUM ANALYZE;"

# Resume service
docker unpause openclaw-secure
```

### **Database Indexes**

```bash
# Check missing indexes (slow queries)
psql -U postgres -d openclaw -c "
  CREATE INDEX idx_audit_user ON audit_logs(user_id);
  CREATE INDEX idx_api_key ON api_keys(key_hash);
"

# Verify index creation
psql -U postgres -d openclaw -c "\di"
```

---

## **SCALING & PERFORMANCE** {#scaling}

**Time:** Variable  
**Impact:** Requires planning

### **Check Current Usage**

```bash
# CPU/Memory
docker stats openclaw-secure --no-stream

# Memory details
ps aux | grep openclaw | grep -v grep

# Disk
df -h /data

# Network
iftop
```

### **Scale Resources** (Docker)

```bash
# Update docker-compose.hardened.yml
# Edit: deploy.resources.limits.cpus & memory

# Example: 1 CPU → 2 CPUs, 512MB → 1GB
cpu: '2.0'
memory: 1GB

# Redeploy
docker-compose -f docker-compose.hardened.yml up -d --force-recreate
```

### **Performance Optimization**

```bash
# Enable caching headers
# (Update nginx.conf.hardened)
proxy_cache_valid 200 10m;
add_header X-Cache-Status $upstream_cache_status;

# Reduce log verbosity if needed
LOG_LEVEL=warn

# Enable compression
gzip on;
gzip_types application/json text/plain;
```

---

## **LOG MANAGEMENT** {#logs}

**Time:** 5-10 min  
**Frequency:** Weekly review

### **Check Logs** (Real-time)

```bash
# Follow security log
tail -f /data/logs/security.log | jq '.event' | sort | uniq -c

# API log
tail -f /data/logs/api.log | jq '.status' | sort | uniq -c

# Errors
tail -f /data/logs/error.log
```

### **Log Rotation** (Automatic, but verify)

```bash
# Check log file sizes
du -sh /data/logs/*

# Compress old logs (older than 30 days)
find /data/logs -name "*.log" -mtime +30 -exec gzip {} \;

# Remove very old logs (older than 1 year)
find /data/logs -name "*.log.gz" -mtime +365 -delete
```

### **Log Queries**

```bash
# Count auth failures by IP (last 24h)
tail -f /data/logs/security.log | \
  grep "login_failed" | \
  jq '.data.ip' | sort | uniq -c | sort -rn

# Rate limit hits
tail -f /data/logs/security.log | \
  grep "rate_limited" | jq '.data.type' | sort | uniq -c

# Cost anomalies
tail -f /data/logs/security.log | \
  grep "cost_anomaly" | jq '.data.daily'
```

---

## **ADMIN ONBOARDING** {#onboarding}

**Time:** ~2 hours  
**Frequency:** Per new admin

### **Welcome Packet**

- [ ] System access (SSH keys, passwords)
- [ ] Cloud account (Railway, GitHub, etc.)
- [ ] Monitoring tools (Prometheus, logs)
- [ ] On-call procedures
- [ ] Emergency contacts

### **Training Session** (1 hour)

1. **Tour the system** (15 min)
   - Show dashboard
   - Review current alerts
   - Check health status

2. **Key procedures** (30 min)
   - Startup/shutdown
   - Key rotation
   - Backup restoration
   - Incident response

3. **Hands-on practice** (15 min)
   - Query logs
   - Check metrics
   - Generate reports
   - Practice incident response

### **First Shift** (supervised)

- [ ] Monitor with experienced admin
- [ ] Respond to alerts
- [ ] Run planned maintenance
- [ ] Practice incident response

### **Checklist**

- [ ] Read all runbooks (this document)
- [ ] Read incident response runbooks (`RUNBOOKS.md`)
- [ ] Understand alert escalation
- [ ] Can access logs and metrics
- [ ] Can start/stop service
- [ ] Can rotate keys
- [ ] Know who to call on-call lead
- [ ] Completed first supervised shift

---

## **ON-CALL HANDOFF** {#handoff}

**Time:** 10-15 min  
**Frequency:** Weekly rotation

### **Handoff Meeting**

**Attendees:** Outgoing on-call + Incoming on-call + Lead

**Agenda:**

1. **Current status** (3 min)
   - Any open incidents?
   - Any warnings/alerts?
   - Any pending maintenance?

2. **Recent history** (3 min)
   - What incidents happened this week?
   - Any near-misses?
   - Performance issues?

3. **Upcoming** (2 min)
   - Planned maintenance?
   - Key rotation due?
   - Backups on schedule?

4. **Tools walkthrough** (3 min)
   - Show dashboards
   - Show alert configuration
   - Show escalation paths

5. **Q&A** (3 min)
   - Any questions?
   - Concerns?

### **Handoff Checklist**

- [ ] Current incident status reviewed
- [ ] Recent history discussed
- [ ] Upcoming tasks noted
- [ ] Tools demonstrated
- [ ] Escalation paths confirmed
- [ ] On-call contact list updated
- [ ] Incoming on-call has all access
- [ ] Meeting documented in Slack

---

## **DISASTER RECOVERY** {#disaster-recovery}

**Time:** 30-60 min  
**Frequency:** Test quarterly  
**Objective:** Recover from data loss, corruption, or total service loss

### **Scenario 1: Database Corruption**

```bash
# 1. Detect corruption
# → Error messages about invalid data
# → Query failures increasing

# 2. Restore from last clean backup
/data/workspace/scripts/backup.sh restore /data/backups/db_[LATEST_GOOD].sql.gz.enc

# 3. Verify data integrity
psql -U postgres -d openclaw -c "SELECT COUNT(*) FROM audit_logs;" # Should have data
psql -U postgres -d openclaw -c "PRAGMA integrity_check;" # Check integrity

# 4. Resume service
docker-compose -f docker-compose.hardened.yml up -d

# 5. Monitor for issues
tail -f /data/logs/error.log
```

### **Scenario 2: Disk Failure**

```bash
# 1. Data is on Railway persistent volume
# → Automatically replicated
# → Can restore from backup

# 2. Redeploy container
docker-compose -f docker-compose.hardened.yml up -d --force-recreate

# 3. Restore data if needed
/data/workspace/scripts/backup.sh restore /data/backups/db_[LATEST].sql.gz.enc
```

### **Scenario 3: Security Breach**

```bash
# 1. Activate kill switch (if needed)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/admin/emergency/kill-switch \
  -d '{"reason": "Security breach detected"}'

# 2. Preserve evidence
cp -r /data/logs /data/logs-backup-[DATE]

# 3. Rotate all keys
/data/workspace/scripts/rotate-all-keys.sh

# 4. Restore from clean backup
/data/workspace/scripts/backup.sh restore /data/backups/db_[CLEAN_DATE].sql.gz.enc

# 5. Redeploy service
docker-compose -f docker-compose.hardened.yml up -d --force-recreate

# 6. Release kill switch
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/admin/emergency/kill-switch/release \
  -d '{"reason": "Recovery complete"}'

# 7. Investigate
# Start forensics on backed-up logs
```

### **DR Testing Checklist**

- [ ] Monthly: Test backup verification
- [ ] Quarterly: Full restore test to staging
- [ ] Quarterly: Kill switch activation test
- [ ] Annually: Complete DR simulation

---

## **APPENDIX: Commands Reference**

```bash
# Health checks
curl http://localhost:3000/health

# Admin endpoints
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:3000/api/v1/admin/costs

# Logs
tail -f /data/logs/security.log | jq
tail -f /data/logs/api.log | jq

# Database
psql -U postgres -d openclaw -c "SELECT version();"

# Docker
docker-compose -f docker-compose.hardened.yml ps
docker logs openclaw-secure --tail 50
docker stats openclaw-secure

# System
ps aux | grep openclaw
lsof -i :3000
df -h /data
free -h
```

---

**Last Updated:** 2026-02-23  
**Review Schedule:** Quarterly  
**Version:** 1.0
