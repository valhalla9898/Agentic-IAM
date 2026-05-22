"""
     Q&A System
Advanced Security & Protection System
"""

import hashlib
import hmac
import secrets
import sqlite3
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple


class QASecurityManager:
    """Q&A System"""

    def __init__(self, db_path: str = "qa_security.db"):
        if db_path == ":memory:":
            self.db_path = tempfile.NamedTemporaryFile(suffix="_qa_security.db", delete=False).name
        else:
            self.db_path = db_path
        self._rate_limit_state = {}
        self._init_security_db()

    def _init_security_db(self):
        """Initialize security database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Rate limiting table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                request_count INTEGER DEFAULT 1,
                first_request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Suspicious activity log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity INTEGER DEFAULT 1
            )
        """)

        # User sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        """)

        # Blacklist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def check_rate_limit(
        self, user_id: str, endpoint: str, max_requests: int = 100, time_window: int = 3600
    ) -> Tuple[bool, Dict]:
        """Check if user exceeds rate limit"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        state_key = (user_id, endpoint)
        now = datetime.now()

        try:
            state = self._rate_limit_state.get(state_key)
            if state:
                elapsed = (now - state["first_request_time"]).total_seconds()
                if elapsed < time_window:
                    if state["request_count"] >= max_requests:
                        conn.close()
                        return False, {
                            "message": f"Rate limit exceeded. Max {max_requests} requests per {time_window}s",
                            "retry_after": time_window - int(elapsed),
                        }

                    state["request_count"] += 1
                else:
                    state = {
                        "request_count": 1,
                        "first_request_time": now,
                    }
                    self._rate_limit_state[state_key] = state
            else:
                state = {
                    "request_count": 1,
                    "first_request_time": now,
                }
                self._rate_limit_state[state_key] = state

            cursor.execute(
                """
                INSERT OR IGNORE INTO rate_limit (user_id, endpoint, request_count, first_request_time)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
            """,
                (user_id, endpoint),
            )

            cursor.execute(
                """
                UPDATE rate_limit
                SET request_count = ?, first_request_time = ?
                WHERE user_id = ? AND endpoint = ?
            """,
                (
                    state["request_count"],
                    state["first_request_time"].isoformat(sep=" ", timespec="seconds"),
                    user_id,
                    endpoint,
                ),
            )

            conn.commit()
            conn.close()

            return True, {"message": "Request allowed"}

        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Error checking rate limit: %s", e)
            return False, {"message": "Error checking rate limit"}

    def log_suspicious_activity(
        self,
        user_id: str,
        activity_type: str,
        description: str = "",
        ip_address: str = None,
        severity: int = 1,
    ) -> bool:
        """Log suspicious activity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO suspicious_activity
                (user_id, activity_type, description, ip_address, severity)
                VALUES (?, ?, ?, ?, ?)
            """,
                (user_id, activity_type, description, ip_address, severity),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to log suspicious activity: %s", e)
            return False

    def create_session(
        self, user_id: str, ip_address: str = None, user_agent: str = None, expires_in: int = 86400
    ) -> Optional[str]:
        """Create a secure session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(seconds=expires_in)

            cursor.execute(
                """
                INSERT INTO user_sessions
                (user_id, session_token, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                (user_id, session_token, ip_address, user_agent, expires_at.isoformat()),
            )

            conn.commit()
            conn.close()

            return session_token
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to create session: %s", e)
            return None

    def validate_session(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Validate a session token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT user_id, expires_at, is_active FROM user_sessions
                WHERE session_token = ?
            """,
                (session_token,),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                user_id, expires_at, is_active = result

                if not is_active:
                    return False, None

                expires_at_dt = datetime.fromisoformat(expires_at)
                if datetime.now() > expires_at_dt:
                    return False, None

                return True, user_id

            return False, None
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to validate session: %s", e)
            return False, None

    def is_user_blacklisted(self, user_id: str) -> bool:
        """Check if user is blacklisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT expires_at FROM blacklist
                WHERE user_id = ?
                ORDER BY expires_at DESC LIMIT 1
            """,
                (user_id,),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                expires_at = result[0]
                if expires_at:
                    expires_at_dt = datetime.fromisoformat(expires_at)
                    if datetime.now() > expires_at_dt:
                        return False
                return True

            return False
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug(
                "Failed to check blacklist for user %s: %s", user_id, e
            )
            return False

    def blacklist_user(self, user_id: str, reason: str = "", duration: int = None):
        """Blacklist a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            expires_at = None
            if duration:
                expires_at = (datetime.now() + timedelta(seconds=duration)).isoformat()

            cursor.execute(
                """
                INSERT INTO blacklist (user_id, reason, expires_at)
                VALUES (?, ?, ?)
            """,
                (user_id, reason, expires_at),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to blacklist user %s: %s", user_id, e)
            return False

    @staticmethod
    def hash_answer(answer: str, salt: str = None) -> Tuple[str, str]:
        """Hash answer for verification"""
        if salt is None:
            salt = secrets.token_hex(16)

        hash_obj = hashlib.pbkdf2_hmac(
            "sha256", answer.encode("utf-8"), salt.encode("utf-8"), 100000
        )

        hashed = hash_obj.hex()

        return hashed, salt

    @staticmethod
    def verify_answer(answer: str, hashed: str, salt: str) -> bool:
        """Verify hashed answer"""
        computed_hash, _ = QASecurityManager.hash_answer(answer, salt)
        return hmac.compare_digest(computed_hash, hashed)

    def get_security_report(self, user_id: str = None) -> Dict:
        """Get security report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            if user_id:
                # Single user report
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM suspicious_activity
                    WHERE user_id = ?
                """,
                    (user_id,),
                )

                suspicious_count = cursor.fetchone()[0]

                cursor.execute(
                    """
                    SELECT COUNT(*) FROM user_sessions
                    WHERE user_id = ? AND is_active = 1
                """,
                    (user_id,),
                )

                active_sessions = cursor.fetchone()[0]

                is_blacklisted = self.is_user_blacklisted(user_id)

                conn.close()

                return {
                    "user_id": user_id,
                    "suspicious_activities": suspicious_count,
                    "active_sessions": active_sessions,
                    "is_blacklisted": is_blacklisted,
                    "report_generated_at": datetime.now().isoformat(),
                }
            else:
                # System-wide report
                cursor.execute("SELECT COUNT(*) FROM suspicious_activity")
                total_suspicious = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM user_sessions WHERE is_active = 1")
                total_active_sessions = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM blacklist")
                total_blacklisted = cursor.fetchone()[0]

                conn.close()

                return {
                    "total_suspicious_activities": total_suspicious,
                    "total_active_sessions": total_active_sessions,
                    "total_blacklisted_users": total_blacklisted,
                    "report_generated_at": datetime.now().isoformat(),
                }

        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to generate security report: %s", e)
            return {"error": "failed to generate security report"}


# Singleton instance
_security_manager = None


def get_security_manager() -> QASecurityManager:
    """Get singleton instance of security manager"""
    global _security_manager
    if _security_manager is None:
        _security_manager = QASecurityManager()
    return _security_manager
