"""

Intelligent Recommendation & Smart Learning System
"""

import sqlite3
import tempfile
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional


class DifficultyLevel(str, Enum):
    """ """

    BEGINNER = ""
    INTERMEDIATE = ""
    ADVANCED = ""
    EXPERT = ""


class QARecommendationEngine:
    """ """

    def __init__(self, db_path: str = "qa_recommendations.db"):
        if db_path == ":memory:" or db_path.startswith(":memory"):
            fd, temp_path = tempfile.mkstemp(prefix="qa_recommendations_", suffix=".db")
            try:
                pass
            finally:
                import os

                os.close(fd)
            self.db_path = temp_path
        else:
            self.db_path = db_path
        self._init_recommendation_db()

    def _init_recommendation_db(self):
        """Initialize recommendation database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # User profiling
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY,
                preferred_category TEXT,
                preferred_difficulty TEXT,
                learning_speed TEXT,
                last_session TIMESTAMP,
                profile_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Recommended questions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                question_id INTEGER NOT NULL,
                recommendation_type TEXT,
                reason TEXT,
                confidence_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                was_acted_upon BOOLEAN DEFAULT 0,
                UNIQUE(user_id, question_id, recommendation_type)
            )
        """)

        # Spaced repetition tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS spaced_repetition (
                user_id TEXT NOT NULL,
                question_id INTEGER NOT NULL,
                interval INTEGER DEFAULT 1,
                ease_factor REAL DEFAULT 2.5,
                next_review TIMESTAMP,
                review_count INTEGER DEFAULT 0,
                PRIMARY KEY (user_id, question_id)
            )
        """)

        conn.commit()
        conn.close()

    def create_user_profile(
        self, user_id: str, preferred_category: str = None, preferred_difficulty: str = None
    ) -> bool:
        """Create user profile"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT OR REPLACE INTO user_profiles
                (user_id, preferred_category, preferred_difficulty, profile_updated)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (user_id, preferred_category, preferred_difficulty),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to create user profile: %s", e)
            return False

    def update_user_profile(self, user_id: str, **kwargs) -> bool:
        """Update user profile"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            set_clause = ", ".join([f"{k} = ?" for k in kwargs.keys()])
            set_clause += ", profile_updated = CURRENT_TIMESTAMP"
            values = list(kwargs.values()) + [user_id]

            cursor.execute(
                f"""
                UPDATE user_profiles
                SET {set_clause}
                WHERE user_id = ?
            """,
                values,
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to update user profile: %s", e)
            return False

    def get_user_profile(self, user_id: str) -> Optional[Dict]:
        """Get user profile"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT user_id, preferred_category, preferred_difficulty,
                       learning_speed, last_session
                FROM user_profiles WHERE user_id = ?
            """,
                (user_id,),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    "user_id": result[0],
                    "preferred_category": result[1],
                    "preferred_difficulty": result[2],
                    "learning_speed": result[3],
                    "last_session": result[4],
                }

            return None
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to get user profile: %s", e)
            return None

    def generate_recommendations(
        self, user_id: str, user_stats: Dict, available_questions: List[Dict], limit: int = 10
    ) -> List[Dict]:
        """Generate personalized recommendations"""
        recommendations = []

        profile = self.get_user_profile(user_id)

        for question in available_questions:
            recommendation = self._evaluate_question(
                user_id=user_id, question=question, user_stats=user_stats, profile=profile
            )

            if recommendation:
                recommendations.append(recommendation)

        # Sort by confidence score
        recommendations.sort(key=lambda x: x["confidence_score"], reverse=True)

        # Save recommendations
        for rec in recommendations[:limit]:
            self._save_recommendation(user_id, rec)

        return recommendations[:limit]

    def _evaluate_question(
        self, user_id: str, question: Dict, user_stats: Dict, profile: Optional[Dict]
    ) -> Optional[Dict]:
        """Evaluate if question is good recommendation"""

        score = 0
        reasons = []

        # Check if already answered correctly
        if question.get("question_id"):
            if user_stats.get("already_correct", {}).get(question["question_id"]):
                return None

        # Category match
        if profile and profile.get("preferred_category"):
            if question.get("category") == profile["preferred_category"]:
                score += 30
                reasons.append("Matches your preferred category")

        # Difficulty progression
        user_accuracy = user_stats.get("overall_accuracy", 50)
        question_difficulty = question.get("difficulty_level", "")

        if user_accuracy < 30:
            if question_difficulty == "":
                score += 25
                reasons.append("Perfect difficulty for your current level")
        elif user_accuracy < 50:
            if question_difficulty in ["", ""]:
                score += 25
                reasons.append("Appropriate challenge level")
        elif user_accuracy < 70:
            if question_difficulty in ["", ""]:
                score += 25
                reasons.append("Good progressive challenge")
        else:
            if question_difficulty in ["", ""]:
                score += 25
                reasons.append("Expert-level content for mastery")

        # Spaced repetition check
        needs_review = self._check_spaced_repetition(user_id, question.get("question_id"))
        if needs_review:
            score += 20
            reasons.append("Time for spaced repetition review")

        # Weak area reinforcement
        if question.get("category") in user_stats.get("weak_areas", []):
            score += 15
            reasons.append("Helps strengthen weak area")

        if score > 0:
            return {
                "question_id": question.get("question_id"),
                "question_text": question.get("question", ""),
                "category": question.get("category"),
                "difficulty_level": question_difficulty,
                "recommendation_type": "personalized",
                "reason": "; ".join(reasons),
                "confidence_score": min(score, 100),
            }

        return None

    def _save_recommendation(self, user_id: str, recommendation: Dict) -> bool:
        """Save recommendation to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT OR IGNORE INTO recommendations
                (user_id, question_id, recommendation_type, reason, confidence_score)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    user_id,
                    recommendation.get("question_id"),
                    recommendation.get("recommendation_type"),
                    recommendation.get("reason"),
                    recommendation.get("confidence_score"),
                ),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to save recommendation: %s", e)
            return False

    def _check_spaced_repetition(self, user_id: str, question_id: int) -> bool:
        """Check if question needs spaced repetition review"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT next_review FROM spaced_repetition
                WHERE user_id = ? AND question_id = ?
            """,
                (user_id, question_id),
            )

            result = cursor.fetchone()
            conn.close()

            if result and result[0]:
                next_review = datetime.fromisoformat(result[0])
                return datetime.now() >= next_review

            return False
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Spaced repetition check failed: %s", e)
            return False

    def update_spaced_repetition(self, user_id: str, question_id: int, is_correct: bool) -> bool:
        """Update spaced repetition interval based on performance"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT interval, ease_factor, review_count FROM spaced_repetition
                WHERE user_id = ? AND question_id = ?
            """,
                (user_id, question_id),
            )

            result = cursor.fetchone()

            if result:
                interval, ease_factor, review_count = result
            else:
                interval = 1
                ease_factor = 2.5
                review_count = 0

            # SM-2 Algorithm
            if is_correct:
                ease_factor = max(1.3, ease_factor + (0.1 - (5 - 5) * (0.08 + (5 - 5) * 0.02)))
                if review_count == 0:
                    interval = 1
                elif review_count == 1:
                    interval = 3
                else:
                    interval = int(interval * ease_factor)
            else:
                ease_factor = max(1.3, ease_factor - 0.2)
                interval = 1

            next_review = datetime.now() + timedelta(days=interval)

            cursor.execute(
                """
                INSERT OR REPLACE INTO spaced_repetition
                (user_id, question_id, interval, ease_factor, next_review, review_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (user_id, question_id, interval, ease_factor, next_review.isoformat(), review_count + 1),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to update spaced repetition: %s", e)
            return False

    def get_next_review_questions(self, user_id: str, limit: int = 5) -> List[Dict]:
        """Get questions due for spaced repetition review"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT question_id, interval, ease_factor, next_review
                FROM spaced_repetition
                WHERE user_id = ? AND next_review <= datetime('now')
                ORDER BY next_review ASC
                LIMIT ?
            """,
                (user_id, limit),
            )

            results = cursor.fetchall()
            conn.close()

            questions = []
            for question_id, interval, ease_factor, next_review in results:
                questions.append(
                    {
                        "question_id": question_id,
                        "interval": interval,
                        "ease_factor": round(ease_factor, 2),
                        "last_review": next_review,
                        "review_type": "spaced_repetition",
                    }
                )

            return questions

        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to fetch next review questions: %s", e)
            return []

    def get_adaptive_quiz(self, user_id: str, user_stats: Dict, size: int = 10) -> List[Dict]:
        """Generate adaptive quiz based on user performance"""
        self.get_user_profile(user_id)

        # Determine optimal difficulty
        accuracy = user_stats.get("overall_accuracy", 50)

        if accuracy < 40:
            DifficultyLevel.BEGINNER.value
        elif accuracy < 60:
            DifficultyLevel.INTERMEDIATE.value
        elif accuracy < 80:
            DifficultyLevel.ADVANCED.value
        else:
            DifficultyLevel.EXPERT.value

        # Would need to integrate with QADatabase to get questions
        return []

    def track_recommendation_effectiveness(self, user_id: str, question_id: int) -> bool:
        """Track if recommended question was acted upon"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                UPDATE recommendations
                SET was_acted_upon = 1
                WHERE user_id = ? AND question_id = ?
            """,
                (user_id, question_id),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to track recommendation effectiveness: %s", e)
            return False

    def get_recommendation_metrics(self, user_id: str = None) -> Dict:
        """Get recommendation system metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            if user_id:
                # User-specific metrics
                cursor.execute(
                    """
                    SELECT COUNT(*), SUM(was_acted_upon), AVG(confidence_score)
                    FROM recommendations WHERE user_id = ?
                """,
                    (user_id,),
                )
            else:
                # System-wide metrics
                cursor.execute("""
                    SELECT COUNT(*), SUM(was_acted_upon), AVG(confidence_score)
                    FROM recommendations
                """)

            result = cursor.fetchone()

            if result:
                total_recommendations = result[0] or 0
                acted_upon = result[1] or 0
                avg_confidence = result[2] or 0

                effectiveness = (acted_upon / total_recommendations * 100) if total_recommendations > 0 else 0

                metrics = {
                    "total_recommendations": total_recommendations,
                    "recommendations_acted_upon": acted_upon,
                    "effectiveness_percentage": round(effectiveness, 2),
                    "average_confidence_score": round(avg_confidence, 2),
                    "metrics_generated_at": datetime.now().isoformat(),
                }

                if user_id:
                    metrics["user_id"] = user_id

                conn.close()
                return metrics

            conn.close()
            return {}

        except sqlite3.DatabaseError as e:
            conn.close()
            import logging

            logging.getLogger(__name__).debug("Failed to compute recommendation metrics: %s", e)
            return {}


# Singleton instance
_recommendation_engine = None


def get_recommendation_engine() -> QARecommendationEngine:
    """Get singleton instance of recommendation engine"""
    global _recommendation_engine
    if _recommendation_engine is None:
        _recommendation_engine = QARecommendationEngine()
    return _recommendation_engine
