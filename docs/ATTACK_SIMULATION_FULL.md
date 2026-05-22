# Attack Simulation & Security Testing Guide

## Overview

This guide demonstrates a **complete authorized attack simulation** that:
1. Launches the Bloom application
2. Executes realistic attacks (brute force, SQL injection, XSS, rate limiting)
3. Triggers real-time security detection and mitigation
4. Records the entire attack flow in a video
5. Displays security alerts in real-time dashboard

## Quick Start

### 1. Ensure Database Migration Applied

```bash
python -m alembic upgrade head
```

This creates:
- `attack_events` table - logs detected attacks
- `security_alerts` table - real-time notifications
- `blocked_ips` table - IP blocking registry
- `failed_login_attempts` table - brute force tracking

### 2. Start the API Server

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

### 3. Run the Attack Simulation

```bash
python scripts/enhanced_attack_simulator.py --target http://127.0.0.1:8000 --output ./attack_results
```

**What happens during simulation:**
- Browser opens and navigates to the application
- Performs 5+ failed login attempts (brute force)
- Injects SQL payloads
- Attempts XSS attacks
- Sends rapid requests (rate limit abuse)
- Queries security alerts API to check if attacks were detected
- **ENTIRE ATTACK FLOW IS RECORDED IN VIDEO**

### 4. View Results

Video and results are saved to:
```
attack_results/
├── last_run.json          # Attack metadata and event log
├── attack_demo.mp4        # Annotated demo (if generated)
└── videos/
    └── [uuid].webm        # Raw browser recording
```

### 5. View Dashboard with Real-Time Alerts

```bash
streamlit run dashboard/main.py
```

Navigate to **"Attack Simulation Results"** in the sidebar to see:
- ✅ Active security alerts
- 🎯 Detected attack events
- 🚫 Blocked IP addresses
- 📹 Attack simulation video
- 📊 Event timeline

## Attack Types Simulated

### 1. Brute Force Attack
- Multiple failed login attempts (5+ tries)
- Different passwords per attempt
- **Detection**: Triggers after 5 attempts in 10 minutes
- **Mitigation**: IP blocked for 1 hour

### 2. SQL Injection
- Payloads: `' OR '1'='1`, `admin' --`, `UNION SELECT`
- **Detection**: Pattern matching on request payload
- **Mitigation**: Request blocked, IP added to blocklist

### 3. Cross-Site Scripting (XSS)
- Payloads: `<script>alert('XSS')</script>`, `onerror` handlers
- **Detection**: Regex pattern matching
- **Mitigation**: Request rejected, IP blocked

### 4. Rate Limit Abuse
- 10 rapid requests in quick succession
- **Detection**: Configurable threshold
- **Mitigation**: Temporary rate limit enforcement

## Security Alerts Generated

During simulation, the system generates:

```json
{
  "alert_type": "attack_detected",
  "title": "Attack Detected: BRUTE_FORCE",
  "message": "Detected brute_force attack from 127.0.0.1",
  "severity": "high",
  "created_at": "2026-05-18T00:56:07Z"
}
```

And for mitigation:

```json
{
  "alert_type": "attack_blocked",
  "title": "🛡️ Attack Blocked",
  "message": "IP 127.0.0.1 has been blocked for 1 hour due to brute_force attack",
  "severity": "high",
  "created_at": "2026-05-18T00:56:07Z"
}
```

## API Endpoints for Security

### Get Active Alerts
```bash
curl http://127.0.0.1:8000/alerts/active
```

### Get Recent Attacks
```bash
curl http://127.0.0.1:8000/alerts/attacks
```

### Get Blocked IPs
```bash
curl http://127.0.0.1:8000/alerts/blocked-ips
```

### Block an Attacker
```bash
curl -X POST http://127.0.0.1:8000/alerts/attacks/1/block-ip?duration_seconds=3600
```

## Video Recording Details

The simulator records:
- Full browser window showing the application
- All attacks being attempted
- Application response to attacks
- Error messages and security rejections

**Output format**: WebM (VP9 codec, H.264 fallback)

**File location**: `attack_results/videos/[uuid].webm`

**Size**: Typically 10-20MB for 1-2 minute simulation

## Database Schema

### attack_events
```
id: Integer (PK)
attack_type: String (sql_injection, brute_force, xss, rate_limit)
source_ip: String
target_endpoint: String
payload: Text
severity: String (low, medium, high, critical)
status: String (detected, blocked, mitigated)
detected_at: TIMESTAMP
```

### security_alerts
```
id: Integer (PK)
alert_type: String (attack_detected, attack_blocked, threshold_exceeded)
title: String
message: Text
severity: String
source_ip: String (nullable)
attack_event_id: Integer (FK)
is_resolved: Boolean
created_at: TIMESTAMP
```

### blocked_ips
```
ip_address: String (unique)
reason: String
block_duration_seconds: Integer (NULL = permanent)
blocked_at: TIMESTAMP
expires_at: TIMESTAMP (nullable)
is_active: Boolean
```

## Testing Checklist

- [ ] Database migrations applied
- [ ] API server running on port 8000
- [ ] Simulator executes without errors
- [ ] Video file generated in `attack_results/videos/`
- [ ] Alerts visible in API and dashboard
- [ ] Blocked IPs appear in `/alerts/blocked-ips`
- [ ] Streamlit dashboard shows real-time alerts

## Troubleshooting

### No video recorded
- Ensure Playwright is installed: `python -m playwright install`
- Check disk space in `attack_results/videos/`
- Try with `--no-video` flag to skip recording

### API endpoints not responding
- Check if security middleware is interfering
- Verify API server is running: `curl http://127.0.0.1:8000/docs`
- Check firewall/network settings

### Database errors
- Run migrations: `python -m alembic upgrade head`
- Check database file permissions
- Verify SQLAlchemy connection string in settings

## Presentation Notes

This simulation is perfect for demonstrating:
1. **Real-time threat detection** - alerts appear during attack
2. **Automated mitigation** - attacker gets blocked immediately
3. **Audit trail** - all events logged to database
4. **Video evidence** - complete recording of attack flow
5. **Dashboard visibility** - security team sees everything in real-time

---

**Last Updated**: 2026-05-18
**Status**: ✅ Production Ready
