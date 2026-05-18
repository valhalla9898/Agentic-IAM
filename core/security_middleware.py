"""Security middleware for detecting and blocking attacks in real-time."""
from fastapi import Request
from datetime import datetime, timedelta
from typing import Callable
from core.attack_detection import AttackDetector, AttackLogger
from sqlalchemy.orm import Session


class AttackDetectionMiddleware:
    """Middleware to detect and block attacks in real-time."""

    def __init__(self, app, get_db: Callable):
        self.app = app
        self.get_db = get_db

    async def __call__(self, request: Request, call_next: Callable):
        """Process request and detect attacks."""
        # Extract client IP
        client_ip = request.client.host if request.client else "unknown"

        # Get database session
        try:
            db = next(self.get_db())
        except Exception:
            db = None

        # Check if IP is blocked
        if db and AttackDetector.is_ip_blocked(db, client_ip):
            print(f"[!] Blocked IP detected: {client_ip}")
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "IP address is blocked due to suspicious activity",
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

        # Check for attack patterns in URL and parameters
        url_path = request.url.path
        suspicious = False
        attack_type = None
        description = None

        # SQL Injection detection
        if AttackDetector.detect_sql_injection(url_path):
            suspicious = True
            attack_type = "sql_injection"
            description = f"SQL injection pattern detected in URL: {url_path}"

        # XSS detection
        if AttackDetector.detect_xss(url_path):
            suspicious = True
            attack_type = "xss"
            description = f"XSS pattern detected in URL: {url_path}"

        # Check request body for attacks
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                body_str = body.decode('utf-8', errors='ignore')

                if AttackDetector.detect_sql_injection(body_str):
                    suspicious = True
                    attack_type = "sql_injection"
                    description = f"SQL injection pattern detected in request body"

                if AttackDetector.detect_xss(body_str):
                    suspicious = True
                    attack_type = "xss"
                    description = f"XSS pattern detected in request body"
            except Exception:
                pass

        # Log suspicious activity
        if suspicious and db and attack_type:
            print(f"[!] ATTACK DETECTED: {attack_type} from {client_ip}")

            # Log attack event
            attack = AttackLogger.log_attack(
                db,
                attack_type=attack_type,
                source_ip=client_ip,
                payload=url_path[:200],
                target_endpoint=url_path,
                severity="high",
                description=description,
                metadata={"method": request.method}
            )

            # Create alert
            AttackLogger.log_alert(
                db,
                alert_type="attack_detected",
                title=f"Attack Detected: {attack_type.upper()}",
                message=f"Detected {attack_type} attack from {client_ip}. Endpoint: {url_path}",
                severity="high",
                source_ip=client_ip,
                attack_event_id=attack.id
            )

            # Block IP for 1 hour (3600 seconds)
            AttackLogger.block_ip(
                db,
                ip=client_ip,
                reason=f"Automatic block: {attack_type} detected",
                duration_seconds=3600,
                attack_event_id=attack.id
            )

            # Create mitigation alert
            AttackLogger.log_alert(
                db,
                alert_type="attack_blocked",
                title="🛡️ Attack Blocked",
                message=f"IP {client_ip} has been blocked for 1 hour due to {attack_type} attack attempt.",
                severity="high",
                source_ip=client_ip,
                attack_event_id=attack.id
            )

            # Reject the request
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked due to security policy",
                    "attack_type": attack_type,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

        # Continue to next middleware/route
        response = await call_next(request)
        return response


class LoginAttemptMiddleware:
    """Middleware to detect brute force login attempts."""

    def __init__(self, app, get_db: Callable):
        self.app = app
        self.get_db = get_db
        self.login_endpoint = "/auth/login"

    async def __call__(self, request: Request, call_next: Callable):
        """Detect brute force on login endpoint."""
        if not request.url.path.startswith(self.login_endpoint):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        # Get database session
        try:
            db = next(self.get_db())
        except Exception:
            return await call_next(request)

        # Extract username from request (if POST)
        username = "unknown"
        if request.method == "POST":
            try:
                body = await request.body()
                body_str = body.decode('utf-8', errors='ignore')
                import json
                data = json.loads(body_str)
                username = data.get("username", "unknown")
            except Exception:
                pass

        # Process the request
        response = await call_next(request)

        # If failed login (check response status or marker)
        # Log failed attempt
        if response.status_code in [401, 403]:
            from core.attack_detection import AttackLogger
            AttackLogger.log_failed_login(
                db,
                username=username,
                source_ip=client_ip,
                reason="invalid_credentials"
            )

            # Check for brute force
            if AttackDetector.detect_brute_force(db, username, client_ip, threshold=5, window_minutes=10):
                print(f"[!] BRUTE FORCE DETECTED: {username} from {client_ip}")

                # Log attack
                attack = AttackLogger.log_attack(
                    db,
                    attack_type="brute_force",
                    source_ip=client_ip,
                    target_endpoint="/auth/login",
                    severity="high",
                    description=f"Brute force attack on user {username}",
                    metadata={"username": username}
                )

                # Create alert
                AttackLogger.log_alert(
                    db,
                    alert_type="attack_detected",
                    title="⚠️ Brute Force Attack Detected",
                    message=f"Multiple failed login attempts for user '{username}' from {client_ip}",
                    severity="high",
                    source_ip=client_ip,
                    attack_event_id=attack.id
                )

                # Block IP
                AttackLogger.block_ip(
                    db,
                    ip=client_ip,
                    reason="Brute force attack detected",
                    duration_seconds=3600,
                    attack_event_id=attack.id
                )

                # Mitigation alert
                AttackLogger.log_alert(
                    db,
                    alert_type="attack_blocked",
                    title="🛡️ Brute Force Blocked",
                    message=f"IP {client_ip} has been blocked for 1 hour due to brute force attempts.",
                    severity="high",
                    source_ip=client_ip,
                    attack_event_id=attack.id
                )

        return response
