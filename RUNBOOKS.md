# Incident Response Runbooks
**OpenClaw Security Incident Procedures**

---

## 🚨 **INCIDENT SEVERITY LEVELS**

| Level | Response Time | Action | Owner |
|-------|---------------|--------|-------|
| **CRITICAL** | <15 min | Immediate intervention, kill switch, escalate | Security Lead |
| **HIGH** | <1 hour | Investigation, containment, stakeholder notification | Ops Manager |
| **MEDIUM** | <4 hours | Root cause analysis, temporary mitigation | Security Officer |
| **LOW** | <24 hours | Documentation, patch planning, monitoring | Ops Team |

---

## 📋 **RUNBOOK INDEX**

1. [Brute Force Attack](#1-brute-force-attack)
2. [Compromised API Key](#2-compromised-api-key)
3. [Cost Anomaly / Runaway Spending](#3-cost-anomaly)
4. [Data Exfiltration Attempt](#4-data-exfiltration)
5. [Service Degradation](#5-service-degradation)
6. [Unauthorized Access Attempt](#6-unauthorized-access)
7. [Malicious Prompt Injection](#7-prompt-injection)
8. [Rate Limit Abuse](#8-rate-limit-abuse)
9. [Kill Switch Activation](#9-kill-switch)
10. [Post-Incident Review](#10-post-incident-review)

---

## **1. BRUTE FORCE ATTACK**

**Severity:** HIGH  
**Detection:** >10 failed logins from same IP in 5 minutes

### **Automatic Response**
✅ System automatically:
- Blocks IP for 1 hour
- Logs failed attempts
- Escalates to 24-hour block after 20 attempts
- Sends security alert

### **Manual Response (if needed)**

**Step 1: Verify the Attack** (2 min)
```bash
# Check security logs
tail -f /data/logs/security.log | grep "brute_force\|login_failed"

# Identify attacker IP
grep "failed.*auth" /data/logs/security.log | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c
```

**Step 2: Check Current Status** (1 min)
```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/incidents
```

**Step 3: Enhance Protection** (5 min)
```bash
# If attack continuing after auto-block:
# 1. Manually extend IP block duration
# 2. Enable MFA for all accounts
# 3. Notify affected users
```

**Step 4: Communicate** (5 min)
- ✅ Auto-alert sent to Slack (if configured)
- Send email to affected admins
- Update incident ticket

**Step 5: Monitor** (ongoing)
```bash
# Watch for additional attacks
watch -n 10 'grep "brute_force" /data/logs/security.log | tail -5'
```

**Step 6: Cleanup** (24h+ later)
```bash
# Auto-unblock happens after block duration
# Manually verify IP is removed from blacklist
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/security/blacklist
```

### **Escalation Path**
- After 3 attacks in 7 days → Escalate to Security Lead
- If targeting admin accounts → Immediate escalation
- If from known attacker range → Firewall block at network level

---

## **2. COMPROMISED API KEY**

**Severity:** CRITICAL  
**Detection:** Suspicious activity pattern from key, unauthorized resource access

### **Automatic Response**
✅ System automatically:
- Disables the compromised key (24-hour blacklist)
- Logs the compromise event
- Sends CRITICAL alert
- Denies all requests from key

### **Manual Response**

**Step 1: Confirm Compromise** (<5 min)
```bash
# Check key's recent activity
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/audit?apiKey=<compromised_key>

# Look for:
# - Requests from unexpected IPs
# - Calls to sensitive endpoints
# - Unusual geographic locations
```

**Step 2: Immediate Containment** (2 min)
```bash
# Key is auto-disabled, but verify:
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/security/keys/<key_id>/status

# Expected: status = "blacklisted"
```

**Step 3: Generate New Key** (5 min)
```bash
# Create replacement key for the user/service
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/keys/create \
  -d '{"name": "service-name-replacement", "type": "api"}'

# Save new key securely
```

**Step 4: Rotate in Applications** (15 min)
- Update all services using the old key
- Deploy new configuration
- Verify services working with new key

**Step 5: Audit Access** (30 min)
```bash
# Check what the compromised key accessed
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/audit?filter=apiKey \
  --start-date "7 days ago"

# Look for unauthorized:
# - Data exports
# - Config changes
# - User modifications
# - Sensitive model calls
```

**Step 6: Revoke Permanently** (5 min)
```bash
# After new key deployed and working:
curl -X DELETE -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/keys/<old_key_id>

# Confirm revocation
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/security/keys
```

**Step 7: Communicate & Document**
- Notify key owner
- Create incident ticket with full timeline
- Document all actions taken
- Update post-incident review

### **Escalation Path**
- **Always escalate to Security Lead**
- If customer key: Notify customer immediately
- If multiple keys compromised: Incident declaration

---

## **3. COST ANOMALY**

**Severity:** HIGH  
**Detection:** Daily spend 3x+ baseline, or > $250

### **Automatic Response**
✅ System automatically:
- Sends HIGH alert
- Downgrades Opus → Sonnet requests
- Sets cost headers in response
- Logs anomaly event

### **Manual Response**

**Step 1: Confirm the Anomaly** (5 min)
```bash
# Check cost dashboard
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/costs

# Look for:
# - state: "SOFT_LIMIT" or "HARD_LIMIT"
# - daily: $XXX (vs baseline)
# - byModel breakdown
```

**Step 2: Root Cause Analysis** (15 min)
```bash
# Check which service caused spike
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/costs/by-service?hours=6

# Check which endpoints called most
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/costs/by-endpoint?hours=6

# Typical causes:
# - Runaway loop calling expensive model
# - User abuse / fuzzing
# - Bug in retry logic
# - Legitimate spike (batch job?)
```

**Step 3: Take Immediate Action** (10 min)

**If legitimate (expected spike):**
```bash
# Temporarily increase thresholds
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/costs/threshold-override \
  -d '{"duration": "24h", "reason": "batch_job_scheduled"}'
```

**If unauthorized/abuse:**
```bash
# Disable the problematic API key immediately
curl -X DELETE -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/keys/<key_id>

# Or block the user
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/users/<user_id>/disable
```

**Step 4: Investigate Code Changes** (20 min)
```bash
# If engineering-caused:
git log --oneline --since="6 hours ago" | grep -i "model\|api\|call"

# Check for new features / loops / retries
git diff HEAD~5 -- src/models/ src/api/
```

**Step 5: Monitor & Recover** (ongoing)
```bash
# Watch costs return to baseline
watch -n 30 'curl -s -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/costs | jq ".data.daily"'

# Expected: Costs drop within 1-2 hours if loop is fixed
```

**Step 6: Implement Safeguards** (30 min)
- Add per-user rate limits
- Implement maximum tokens/min
- Add monitoring alerts for cost spike
- Document the incident

### **Escalation Path**
- > $500 daily → Escalate to CEO
- > $1000 daily → EMERGENCY kill switch consideration
- Recurring anomalies → Implement hard circuit breaker

---

## **4. DATA EXFILTRATION ATTEMPT**

**Severity:** HIGH  
**Detection:** Unusually high output tokens/min from single key

### **Automatic Response**
✅ System automatically:
- Logs exfiltration attempt
- Tightens rate limits for the key
- Sends HIGH alert
- Records in incident system

### **Manual Response**

**Step 1: Confirm the Pattern** (5 min)
```bash
# Check for suspicious extraction patterns
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/audit?eventType=token_anomaly

# Look for:
# - Single key generating 100K+ tokens/min
# - Repeated calls with large context
# - Dumping entire databases
```

**Step 2: Identify the Data Being Extracted** (15 min)
```bash
# Check request logs for patterns
grep "<api_key>" /data/logs/api.log | tail -100 | jq '.body.prompt' | head -10

# Common exfiltration patterns:
# - "dump all users"
# - "export database"
# - "list all configs"
# - Repeated context window maximization
```

**Step 3: Immediate Containment** (5 min)
```bash
# Disable the key
curl -X DELETE -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/keys/<key_id>

# Kill all active sessions from that key
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/sessions/kill-by-key?key_id=<key_id>
```

**Step 4: Assess Data Loss** (30 min)
```bash
# What data might have been exposed?
# Check prompts in logs for sensitive data patterns
grep -E "password|credit|ssn|secret|token" /data/logs/api.log | wc -l

# Timeline of extraction
grep "<api_key>" /data/logs/api.log | jq '.timestamp' | head -1 # start
grep "<api_key>" /data/logs/api.log | jq '.timestamp' | tail -1 # end

# Estimated tokens extracted
grep "<api_key>" /data/logs/api.log | jq '.usage.output_tokens' | awk '{sum+=$1} END {print sum}'
```

**Step 5: Notify Affected Parties** (10 min)
- If customer data exposed: Notify customer
- If internal data: Escalate to CTO
- Create incident report
- Consider GDPR/privacy notification requirements

**Step 6: Implement Safeguards** (1 hour)
```bash
# Set strict limits on suspicious keys going forward
# Implement output token limits
# Add prompt content inspection
# Monitor for similar patterns
```

### **Escalation Path**
- Any customer data involved: **CRITICAL escalation**
- Internal secrets exposed: Immediate key rotation required
- GDPR/regulated data: Legal notification needed

---

## **5. SERVICE DEGRADATION**

**Severity:** HIGH  
**Detection:** Error rate > 5%, response time > 10s, or cascading failures

### **Manual Response**

**Step 1: Confirm Degradation** (2 min)
```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/health

# Check metrics:
# - error_rate > 5%
# - avg_response_time > 10s
# - failed_requests increasing
```

**Step 2: Identify Root Cause** (10 min)
```bash
# Check error logs
tail -100 /data/logs/error.log | jq '.message' | sort | uniq -c | sort -rn

# Common causes:
# - Database connection pool exhausted
# - External API timeout (Anthropic)
# - Memory leak or high CPU
# - Rate limit on upstream service
```

**Step 3: Quick Fixes** (varies)

**Database issue:**
```bash
# Check connections
psql -c "SELECT count(*) FROM pg_stat_activity;"
# If high: Kill idle connections, restart service
```

**External API timeout:**
```bash
# Check Anthropic API status
curl https://status.anthropic.com

# Temporary mitigation: Increase timeouts, retry with exponential backoff
```

**Memory/CPU:**
```bash
# Check resource usage
docker stats openclaw

# If needed: Restart container (auto-recovery should handle)
docker restart openclaw-secure
```

**Rate limit:**
```bash
# If hitting Anthropic rate limits:
# - Implement request queuing
# - Implement exponential backoff
# - Upgrade API tier if needed
```

**Step 4: Monitor Recovery** (ongoing)
```bash
# Watch error rate return to <1%
watch -n 5 'curl -s -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/health | jq ".performance.error_rate"'
```

**Step 5: Root Cause Fix** (post-incident)
- Implement permanent fix in code
- Deploy fix
- Verify issue resolved
- Add monitoring for this condition

### **Escalation Path**
- Degradation > 30 min: Escalate to ops
- Complete outage: Declare incident, activate war room
- Customer impact: Notify customer, provide ETA

---

## **6. UNAUTHORIZED ACCESS ATTEMPT**

**Severity:** MEDIUM  
**Detection:** Invalid token, permission denial, IP blacklist hit

### **Manual Response**

**Step 1: Log Analysis** (5 min)
```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/audit?event=unauthorized_access&hours=1
```

**Step 2: Assess Intent** (5 min)
- Accidental (user password guessing) → Send password reset
- Scanning (probing for endpoints) → Monitor for escalation
- Targeted (repeated attempts) → Activate brute force response

**Step 3: Take Action** (varies)
- If legitimate user → Assist with authentication
- If scanning → Monitor and log
- If targeted → Block IP, increase monitoring

### **Escalation Path**
- > 10 attempts/min from same IP: Escalate
- Known attacker ranges: Coordinate with SOC
- Targeted application attacks: Security team investigation

---

## **7. PROMPT INJECTION**

**Severity:** MEDIUM  
**Detection:** Suspicious input pattern detected

### **Manual Response**

**Step 1: Verify Attack** (2 min)
```bash
# Check injection attempt logs
tail -20 /data/logs/security.log | grep "injection\|suspicious"
```

**Step 2: Block & Monitor** (5 min)
- System auto-rejects injection attempts
- Monitor user's future requests
- Consider temporary rate limit increase for this user

**Step 3: User Notification** (optional)
- If repeated: Contact user to clarify legitimate intent
- If confirmed attack: Escalate to brute force procedures

### **Escalation Path**
- Repeated attempts: Escalate to brute force
- Sophisticated payloads: Security team analysis
- Actual data accessed: Data breach protocol

---

## **8. RATE LIMIT ABUSE**

**Severity:** LOW  
**Detection:** IP/key repeatedly hitting rate limits

### **Manual Response**

**Step 1: Identify Pattern** (5 min)
```bash
# Check rate limit hits
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/metrics?type=ratelimit
```

**Step 2: Determine Intent** (10 min)
- Legitimate user hitting limit due to normal usage → No action
- Fuzzing / scanning → Monitor
- DoS attempt → Escalate to brute force protocols

**Step 3: Guidance** (if legitimate)
- Contact user with recommendations
- Suggest using longer request intervals
- Offer API tier upgrade if needed

### **Escalation Path**
- If DoS attempt: Activate DDoS mitigation
- If sustained: Escalate to network ops

---

## **9. KILL SWITCH ACTIVATION**

**Severity:** CRITICAL  
**Usage:** Only in emergency - disables ALL API access

### **When to Use**
- Major security breach in progress
- Widespread data exfiltration
- Ransomware/malware attack on systems
- Catastrophic bug causing massive damage

### **Activation Procedure**

**Step 1: Decision** (1 min)
- Gather incident commander + security lead
- Confirm need for kill switch
- Decision maker authorizes

**Step 2: Activate** (1 min)
```bash
# Activate kill switch (requires admin token)
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/emergency/kill-switch \
  -d '{"reason": "CRITICAL: <description>"}'

# Expected: All API requests immediately return 503 Service Unavailable
```

**Step 3: Communicate** (5 min)
- Notify all users / customers
- Post status update
- Provide ETA for recovery

**Step 4: Investigation** (ongoing)
- Begin forensic analysis
- Determine scope of compromise
- Plan remediation

**Step 5: Recovery** (post-analysis)
```bash
# Release kill switch (requires admin token)
curl -X POST -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/v1/admin/emergency/kill-switch/release \
  -d '{"reason": "Remediation complete, resuming service"}'

# Expected: API returns to normal operation
```

### **Post-Kill Switch**
- Monitor all traffic carefully
- Implement additional safeguards
- Hold full security review
- Update incident response procedures

---

## **10. POST-INCIDENT REVIEW**

**Timing:** Within 24 hours of incident closure

### **Review Checklist**

- [ ] **Timeline**: Map exact sequence of events
- [ ] **Detection**: Was detection automatic? How long to detection?
- [ ] **Response**: Did auto-response work? Manual actions needed?
- [ ] **Duration**: Total incident time from start to resolution
- [ ] **Impact**: Data affected, services impacted, user notifications sent
- [ ] **Root Cause**: Why did this happen? Technical or process failure?
- [ ] **Prevention**: How do we prevent recurrence?
- [ ] **Improvements**: What should we improve in runbook/automation?

### **Post-Incident Meeting**

Participants:
- Incident Commander
- On-call responder
- Security Lead
- Engineering Lead (if code-related)

Agenda (60 min):
1. Timeline walkthrough (15 min)
2. Root cause analysis (20 min)
3. Preventive measures (15 min)
4. Runbook/training updates (10 min)

Output:
- Incident report (shared with team)
- 1-3 action items assigned
- Runbook updates if needed
- Training session if needed

### **Metrics to Track**

- MTTD (Mean Time To Detect): < 5 min target
- MTTR (Mean Time To Respond): < 15 min target
- MTRC (Mean Time To Resolve): < 1 hour target
- Auto-response success rate: > 90%

---

## 📞 **EMERGENCY CONTACTS**

```
Security Lead: [contact]
CTO: [contact]
Ops Manager: [contact]
On-Call: [rotation schedule]
Slack: #security-incidents
```

---

## 📚 **Related Documentation**

- Security Hardening Checklist: `SECURITY_HARDENING_CHECKLIST.md`
- Phase 3 Progress: `PHASE3_PROGRESS.md`
- Server Integration: `SERVER_USAGE_EXAMPLE.md`
- Incident Response Module: `src/operations/incident-response.js`

---

**Last Updated:** 2026-02-23  
**Review Schedule:** Quarterly  
**Training:** Annual for all ops staff
