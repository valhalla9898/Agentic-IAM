"""
     Q&A System
Advanced Analytics & Statistics System
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
import json
import statistics as stats
import tempfile


class QAAnalytics:
    """  """

    def __init__(self, db_path: str = "qa_analytics.db"):
        if db_path == ":memory:":
            self.db_path = tempfile.NamedTemporaryFile(suffix="_qa_analytics.db", delete=False).name
        else:
            self.db_path = db_path
        self._init_analytics_db()

    def _init_analytics_db(self):
        """Initialize analytics database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # User progress tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                question_id INTEGER NOT NULL,
                is_correct BOOLEAN,
                time_spent INTEGER,
                attempts INTEGER DEFAULT 1,
                first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, question_id)
            )
        """)

        # Quiz sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL UNIQUE,
                category TEXT,
                difficulty_level TEXT,
                questions_count INTEGER,
                correct_answers INTEGER,
                score_percentage REAL,
                time_spent INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        """)

        # Performance metrics
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Learning paths
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learning_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                category TEXT NOT NULL,
                current_level TEXT,
                total_questions_seen INTEGER DEFAULT 0,
                total_correct INTEGER DEFAULT 0,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def track_question_attempt(
        self,
        user_id: str,
        question_id: int,
        is_correct: bool,
        time_spent: int
    ) -> bool:
        """Track user's question attempt"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO user_progress
                (user_id, question_id, is_correct, time_spent, attempts, last_attempt)
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    COALESCE((SELECT attempts FROM user_progress WHERE user_id = ? AND question_id = ?), 0) + 1,
                    CURRENT_TIMESTAMP
                )
            """, (user_id, question_id, is_correct, time_spent, user_id, question_id))

            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def record_quiz_session(
        self,
        user_id: str,
        session_id: str,
        category: str,
        difficulty_level: str,
        questions_count: int,
        correct_answers: int,
        time_spent: int
    ) -> bool:
        """Record a quiz session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            score_percentage = (
                correct_answers /
                questions_count *
                100) if questions_count > 0 else 0

            cursor.execute("""
                INSERT INTO quiz_sessions
                (user_id, session_id, category, difficulty_level, questions_count,
                 correct_answers, score_percentage, time_spent, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (user_id, session_id, category, difficulty_level, questions_count,
                  correct_answers, score_percentage, time_spent))

            # Update learning path
            self._update_learning_path(
                user_id,
                category,
                difficulty_level,
                questions_count,
                correct_answers)

            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def _update_learning_path(
        self,
        user_id: str,
        category: str,
        current_level: str,
        questions_seen: int,
        correct_answers: int
    ):
        """Update user's learning path"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO learning_paths
                (user_id, category, current_level, total_questions_seen, total_correct, last_activity)
                VALUES (
                    ?,
                    ?,
                    ?,
                    COALESCE((SELECT total_questions_seen FROM learning_paths WHERE user_id = ? AND category = ?), 0) + ?,
                    COALESCE((SELECT total_correct FROM learning_paths WHERE user_id = ? AND category = ?), 0) + ?,
                    CURRENT_TIMESTAMP
                )
            """, (user_id, category, current_level, user_id, category, questions_seen, user_id, category, correct_answers))

            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    def get_user_statistics(self, user_id: str) -> Dict:
        """Get comprehensive user statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Total questions attempted
            cursor.execute("""
                SELECT COUNT(*), SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END)
                FROM user_progress WHERE user_id = ?
            """, (user_id,))

            result = cursor.fetchone()
            total_attempted = result[0] or 0
            total_correct = result[1] or 0
            accuracy = (total_correct / total_attempted * 100) if total_attempted > 0 else 0

            # Quiz sessions
            cursor.execute("""
                SELECT COUNT(*), AVG(score_percentage), MAX(score_percentage), MIN(score_percentage)
                FROM quiz_sessions WHERE user_id = ?
            """, (user_id,))

            result = cursor.fetchone()
            quiz_count = result[0] or 0
            avg_score = result[1] or 0
            best_score = result[2] or 0
            worst_score = result[3] or 0

            # Time spent
            cursor.execute("""
                SELECT SUM(time_spent), AVG(time_spent)
                FROM user_progress WHERE user_id = ?
            """, (user_id,))

            result = cursor.fetchone()
            total_time = result[0] or 0
            avg_time_per_question = result[1] or 0

            # Learning paths
            cursor.execute("""
                SELECT category, current_level, total_questions_seen, total_correct
                FROM learning_paths WHERE user_id = ?
            """, (user_id,))

            learning_paths = []
            for row in cursor.fetchall():
                category, level, seen, correct = row
                learning_paths.append({
                    "category": category,
                    "level": level,
                    "questions_seen": seen,
                    "correct_answers": correct,
                    "category_accuracy": (correct / seen * 100) if seen > 0 else 0
                })

            conn.close()

            return {
                "user_id": user_id,
                "total_questions_attempted": total_attempted,
                "total_correct_answers": total_correct,
                "overall_accuracy_percentage": round(accuracy, 2),
                "quiz_sessions_count": quiz_count,
                "average_quiz_score": round(avg_score, 2),
                "best_quiz_score": round(best_score, 2),
                "worst_quiz_score": round(worst_score, 2),
                "total_time_spent_seconds": total_time,
                "average_time_per_question_seconds": round(avg_time_per_question, 2),
                "learning_paths": learning_paths,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            conn.close()
            return {"error": str(e)}

    def get_category_statistics(self, user_id: str = None) -> Dict:
        """Get statistics by category"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            if user_id:
                # Per-user category stats
                cursor.execute("""
                    SELECT category, current_level, total_questions_seen, total_correct
                    FROM learning_paths WHERE user_id = ?
                """, (user_id,))
            else:
                # System-wide category stats
                cursor.execute("""
                    SELECT category, COUNT(*), AVG(score_percentage)
                    FROM quiz_sessions GROUP BY category
                """)

            results = cursor.fetchall()
            conn.close()

            stats_data = {}
            for row in results:
                if user_id:
                    category, level, seen, correct = row
                    stats_data[category] = {
                        "current_level": level,
                        "questions_seen": seen,
                        "correct_answers": correct,
                        "accuracy": (correct / seen * 100) if seen > 0 else 0
                    }
                else:
                    category, count, avg_score = row
                    stats_data[category] = {
                        "quiz_attempts": count,
                        "average_score": round(avg_score, 2) if avg_score else 0
                    }

            return stats_data

        except Exception as e:
            conn.close()
            return {"error": str(e)}

    def get_leaderboard(self, limit: int = 100) -> List[Dict]:
        """Get top performers"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT user_id, AVG(score_percentage) as avg_score, COUNT(*) as quiz_count
                FROM quiz_sessions
                GROUP BY user_id
                ORDER BY avg_score DESC, quiz_count DESC
                LIMIT ?
            """, (limit,))

            results = cursor.fetchall()
            conn.close()

            leaderboard = []
            for rank, (user_id, avg_score, quiz_count) in enumerate(results, 1):
                leaderboard.append({
                    "rank": rank,
                    "user_id": user_id,
                    "average_score": round(avg_score, 2),
                    "quiz_sessions": quiz_count
                })

            return leaderboard

        except Exception as e:
            conn.close()
            return []

    def get_trending_questions(self, limit: int = 20) -> List[Dict]:
        """Get trending questions (most frequently attempted)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT question_id, COUNT(*) as attempt_count,
                       SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
                       ROUND(SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as success_rate
                FROM user_progress
                GROUP BY question_id
                ORDER BY attempt_count DESC
                LIMIT ?
            """, (limit,))

            results = cursor.fetchall()
            conn.close()

            trending = []
            for question_id, attempts, correct, success_rate in results:
                trending.append({
                    "question_id": question_id,
                    "attempt_count": attempts,
                    "correct_count": correct,
                    "success_rate_percentage": success_rate
                })

            return trending

        except Exception as e:
            conn.close()
            return []

    def get_performance_insights(self, user_id: str) -> Dict:
        """Get personalized performance insights"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Difficulty progression
            cursor.execute("""
                SELECT difficulty_level, AVG(score_percentage), COUNT(*)
                FROM quiz_sessions WHERE user_id = ?
                GROUP BY difficulty_level
            """, (user_id,))

            difficulty_stats = {}
            for level, avg_score, count in cursor.fetchall():
                difficulty_stats[level] = {
                    "average_score": round(avg_score, 2),
                    "attempts": count
                }

            # Weak areas (categories with lowest accuracy)
            cursor.execute("""
                SELECT category, total_correct, total_questions_seen
                FROM learning_paths WHERE user_id = ?
                ORDER BY (total_correct * 100.0 / total_questions_seen) ASC
                LIMIT 5
            """, (user_id,))

            weak_areas = []
            for category, correct, seen in cursor.fetchall():
                if seen > 0:
                    weak_areas.append({
                        "category": category,
                        "accuracy": round(correct * 100.0 / seen, 2),
                        "questions_seen": seen
                    })

            # Strong areas
            cursor.execute("""
                SELECT category, total_correct, total_questions_seen
                FROM learning_paths WHERE user_id = ?
                ORDER BY (total_correct * 100.0 / total_questions_seen) DESC
                LIMIT 5
            """, (user_id,))

            strong_areas = []
            for category, correct, seen in cursor.fetchall():
                if seen > 0:
                    strong_areas.append({
                        "category": category,
                        "accuracy": round(correct * 100.0 / seen, 2),
                        "questions_seen": seen
                    })

            conn.close()

            return {
                "user_id": user_id,
                "difficulty_progression": difficulty_stats,
                "weak_areas": weak_areas,
                "strong_areas": strong_areas,
                "insights_generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            conn.close()
            return {"error": str(e)}

    def get_system_health(self) -> Dict:
        """Get overall system health metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Total users
            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM quiz_sessions")
            total_users = cursor.fetchone()[0] or 0

            # Total quiz sessions
            cursor.execute("SELECT COUNT(*) FROM quiz_sessions")
            total_sessions = cursor.fetchone()[0] or 0

            # Average system-wide score
            cursor.execute("SELECT AVG(score_percentage) FROM quiz_sessions")
            avg_system_score = cursor.fetchone()[0] or 0

            # Most popular category
            cursor.execute("""
                SELECT category, COUNT(*) FROM quiz_sessions
                GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1
            """)

            result = cursor.fetchone()
            most_popular_category = result[0] if result else None

            # Active users (last 24 hours)
            cursor.execute("""
                SELECT COUNT(DISTINCT user_id) FROM quiz_sessions
                WHERE completed_at > datetime('now', '-1 day')
            """)

            active_users_24h = cursor.fetchone()[0] or 0

            conn.close()

            return {
                "total_registered_users": total_users,
                "total_quiz_sessions": total_sessions,
                "average_system_score": round(avg_system_score, 2),
                "most_popular_category": most_popular_category,
                "active_users_last_24h": active_users_24h,
                "health_check_timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            conn.close()
            return {"error": str(e)}


# Singleton instance
_analytics = None


def get_analytics() -> QAAnalytics:
    """Get singleton instance of analytics"""
    global _analytics
    if _analytics is None:
        _analytics = QAAnalytics()
    return _analytics
