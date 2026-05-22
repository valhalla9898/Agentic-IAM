"""

Advanced Utilities & Helper Functions for QA System
"""

# TODO: This module contains many placeholder empty-string enum values
# and dictionary keys (likely lost during translation). These placeholders
# should be reviewed and replaced with meaningful category labels and
# recommendation texts by a domain expert. Automated fixes were avoided
# to prevent semantic regressions.

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Tuple


class QuestionDifficulty(str, Enum):
    """ """

    BEGINNER = ""
    INTERMEDIATE = ""
    ADVANCED = ""
    EXPERT = ""


class QuestionCategory(str, Enum):
    """ """

    SECURITY = ""
    AI = " "
    PROGRAMMING = ""
    NETWORKS = ""
    DATABASES = " "
    MANAGEMENT = ""


class QAUtilities:
    """ """

    @staticmethod
    def calculate_difficulty_score(question_text: str, answer_text: str, category: str) -> int:
        """
        Calculate difficulty score for a question
        Returns score from 1 (easy) to 5 (expert)
        """
        score = 1

        # Length-based scoring
        question_length = len(question_text.split())
        if question_length > 30:
            score += 1
        if question_length > 50:
            score += 1

        # Answer complexity
        answer_length = len(answer_text.split())
        if answer_length > 20:
            score += 1
        if answer_length > 40:
            score += 1

        # Category-based default (placeholders removed to avoid duplicate keys)
        category_difficulty = {}

        base_score = category_difficulty.get(category, 2)
        final_score = min((score + base_score) // 2, 5)

        return max(1, final_score)

    @staticmethod
    def extract_keywords(text: str, limit: int = 10) -> List[str]:
        """
        Extract keywords from text
        """
        # Remove common words
        stopwords = {
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "the",
            "is",
            "a",
            "an",
            "and",
            "or",
            "of",
            "to",
            "in",
            "for",
        }

        words = text.split()
        keywords = [w for w in words if w not in stopwords and len(w) > 3]

        return keywords[:limit]

    @staticmethod
    def calculate_answer_similarity(answer1: str, answer2: str) -> float:
        """
        Calculate similarity between two answers (0-1)
        """
        from difflib import SequenceMatcher

        # Normalize
        a1 = answer1.strip().lower()
        a2 = answer2.strip().lower()

        # Exact match
        if a1 == a2:
            return 1.0

        # Use sequence matching
        similarity = SequenceMatcher(None, a1, a2).ratio()

        return similarity

    @staticmethod
    def categorize_performance(accuracy: float) -> str:
        """
        Categorize user performance based on accuracy
        """
        if accuracy >= 90:
            return ""
        elif accuracy >= 80:
            return ""
        elif accuracy >= 70:
            return " "
        elif accuracy >= 60:
            return ""
        elif accuracy >= 50:
            return ""
        elif accuracy >= 30:
            return ""
        else:
            return " "

    @staticmethod
    def calculate_experience_points(
        correct: bool, difficulty: int, time_spent: int, streak: int = 1
    ) -> int:
        """
        Calculate experience points for answering a question
        """
        if not correct:
            return 5  # Minimum points for attempt

        base_points = 10

        # Difficulty multiplier
        difficulty_multiplier = 1 + (difficulty - 1) * 0.5

        # Time bonus (reward for faster answers)
        time_bonus = 0
        if time_spent < 30:
            time_bonus = 5
        elif time_spent < 60:
            time_bonus = 3
        elif time_spent < 120:
            time_bonus = 1

        # Streak multiplier
        streak_multiplier = 1 + (min(streak, 10) - 1) * 0.1

        total_points = int((base_points * difficulty_multiplier + time_bonus) * streak_multiplier)

        return total_points

    @staticmethod
    def generate_learning_summary(user_stats: Dict) -> Dict:
        """
        Generate a learning summary for user
        """
        accuracy = user_stats.get("overall_accuracy", 0)
        total_attempted = user_stats.get("total_questions_attempted", 0)
        total_correct = user_stats.get("total_correct_answers", 0)

        performance_level = QAUtilities.categorize_performance(accuracy)

        summary = {
            "performance_level": performance_level,
            "accuracy_percentage": round(accuracy, 2),
            "total_attempts": total_attempted,
            "correct_answers": total_correct,
            "wrong_answers": total_attempted - total_correct,
            "recommendations": [],
        }

        # Generate recommendations based on performance
        if accuracy < 40:
            summary["recommendations"].append("    ")
            summary["recommendations"].append("    ")
            summary["recommendations"].append("   ")

        elif accuracy < 60:
            summary["recommendations"].append("    ")
            summary["recommendations"].append("    ")
            summary["recommendations"].append("     ")

        elif accuracy < 80:
            summary["recommendations"].append("   !")
            summary["recommendations"].append("    ")
            summary["recommendations"].append("    ")

        else:
            summary["recommendations"].append(" !   ")
            summary["recommendations"].append("    ")
            summary["recommendations"].append("  ")

        return summary

    @staticmethod
    def estimate_mastery_level(category_stats: Dict) -> Dict:
        """
        Estimate mastery level in a category
        """
        accuracy = category_stats.get("category_accuracy", 0)
        questions_seen = category_stats.get("questions_seen", 0)

        mastery_percentage = min(accuracy * (questions_seen / 20), 100)  # Normalize by exposure

        if mastery_percentage >= 90:
            level = " "
        elif mastery_percentage >= 75:
            level = " "
        elif mastery_percentage >= 60:
            level = ""
        elif mastery_percentage >= 40:
            level = ""
        else:
            level = "  "

        return {
            "category": category_stats.get("category"),
            "mastery_level": level,
            "mastery_percentage": round(mastery_percentage, 2),
            "questions_mastered": int(questions_seen * accuracy / 100),
            "next_milestone": round(questions_seen * 1.5),
        }

    @staticmethod
    def get_motivation_message(streak: int, accuracy: float, level: int) -> str:
        """
        Generate motivational message based on performance
        """
        messages = {
            "excellent": [" ! ⭐", " !!! 🔥", "  ! 👏", "  ! 💪", " ! 🎉"],
            "good": [" ! 👍", "! 😊", "   🛣️", " ! 💯", "    🌟"],
            "fair": ["  ", "   💪", "   ", "  ", "  "],
            "poor": [" ! 💪", "     😌", "   ", "  ", " ! 💥"],
        }

        if accuracy >= 85:
            category = "excellent"
        elif accuracy >= 70:
            category = "good"
        elif accuracy >= 50:
            category = "fair"
        else:
            category = "poor"

        import secrets

        return secrets.choice(messages[category])

    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """
        Format timestamp to readable format in Arabic
        """
        try:
            dt = datetime.fromisoformat(timestamp)
            now = datetime.now()

            diff = now - dt

            if diff.total_seconds() < 60:
                return ""
            elif diff.total_seconds() < 3600:
                minutes = int(diff.total_seconds() / 60)
                return f" {minutes} "
            elif diff.total_seconds() < 86400:
                hours = int(diff.total_seconds() / 3600)
                return f" {hours} "
            elif diff.total_seconds() < 2592000:
                days = diff.days
                return f" {days} "
            else:
                return dt.strftime("%d/%m/%Y")
        except BaseException:
            return timestamp

    @staticmethod
    def validate_question_quality(question: Dict) -> Tuple[bool, List[str]]:
        """
        Validate question quality
        Returns (is_valid, list_of_issues)
        """
        issues = []

        # Check question text
        if not question.get("question") or len(question["question"]) < 10:
            issues.append("  ")

        # Check answers
        if not question.get("answer") or len(question["answer"]) < 3:
            issues.append("     ")

        # Check category
        valid_categories = [c.value for c in QuestionCategory]
        if question.get("category") not in valid_categories:
            issues.append("  ")

        # Check difficulty
        if question.get("difficulty") not in [1, 2, 3, 4, 5]:
            issues.append("   ")

        return len(issues) == 0, issues


# Performance metrics calculator


class PerformanceMetrics:
    """ """

    @staticmethod
    def calculate_learning_velocity(user_stats: Dict, days: int = 7) -> float:
        """
        Calculate how fast user is improving
        """
        # This would need historical data
        # Placeholder calculation
        accuracy = user_stats.get("overall_accuracy", 50)
        attempted = user_stats.get("total_questions_attempted", 1)

        return (accuracy * attempted) / (days * 10)

    @staticmethod
    def estimate_time_to_mastery(
        current_accuracy: float, questions_per_day: float = 5, category: str = None
    ) -> Dict:
        """
        Estimate time needed to reach mastery
        """
        target_accuracy = 85
        gap = target_accuracy - current_accuracy

        if gap <= 0:
            return {"already_mastered": True, "current_accuracy": current_accuracy}

        # Assume 1% improvement per 5 questions
        questions_needed = gap * 5
        days_needed = questions_needed / questions_per_day

        return {
            "days_to_mastery": int(days_needed),
            "questions_needed": int(questions_needed),
            "expected_date": (datetime.now() + timedelta(days=days_needed)).isoformat(),
            "current_accuracy": current_accuracy,
            "target_accuracy": target_accuracy,
        }
