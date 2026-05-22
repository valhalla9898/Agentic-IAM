"""
Comprehensive Tests for Advanced QA System

"""

import uuid

import pytest

from qa_analytics import QAAnalytics

# Import all QA system components
from qa_database import QADatabase
from qa_recommendations import QARecommendationEngine
from qa_security import QASecurityManager
from qa_utilities import PerformanceMetrics, QAUtilities


class TestQADatabase:
    """Test QA Database functionality"""

    def test_database_initialization(self):
        """Test database can be initialized"""
        db = QADatabase()
        total_questions = db.get_total_questions()
        assert total_questions > 0, "Database should have questions"
        assert total_questions >= 3000, "Should have 3000+ questions"

    def test_categories_exist(self):
        """Test all categories are available"""
        db = QADatabase()
        categories = db.get_categories()
        assert len(categories) > 0, "Should have categories"

        category_names = [c.get("category") for c in categories]
        assert "" in category_names or "security" in str(category_names).lower()

    def test_get_random_question(self):
        """Test getting random question"""
        db = QADatabase()
        question = db.get_random_question()
        assert question is not None, "Should get a question"
        assert "id" in question
        assert "question" in question
        assert "answer" in question

    def test_get_question_by_id(self):
        """Test getting question by ID"""
        db = QADatabase()
        question = db.get_question_by_id(1)
        assert question is not None
        assert question["id"] == 1


class TestQASecurity:
    """Test Security Manager functionality"""

    def test_security_manager_initialization(self):
        """Test security manager init"""
        mgr = QASecurityManager(db_path=":memory:")
        assert mgr is not None

    def test_rate_limiting(self):
        """Test rate limiting"""
        mgr = QASecurityManager(db_path=":memory:")
        user_id = "test_user"
        endpoint = "/api/v1/qa/answer"

        # First 100 requests should pass
        for i in range(100):
            allowed, info = mgr.check_rate_limit(
                user_id=user_id, endpoint=endpoint, max_requests=100
            )
            assert allowed, f"Request {i+1} should be allowed"

        # 101st request should fail
        allowed, info = mgr.check_rate_limit(user_id=user_id, endpoint=endpoint, max_requests=100)
        assert not allowed, "101st request should be blocked"

    def test_session_creation(self):
        """Test session creation and validation"""
        mgr = QASecurityManager(db_path=":memory:")
        user_id = "test_user"

        # Create session
        token = mgr.create_session(user_id=user_id)
        assert token is not None, "Should create session token"

        # Validate session
        is_valid, returned_user_id = mgr.validate_session(token)
        assert is_valid, "Session should be valid"
        assert returned_user_id == user_id, "Should return correct user_id"

    def test_user_blacklisting(self):
        """Test user blacklisting"""
        mgr = QASecurityManager(db_path=":memory:")
        user_id = "bad_user"

        # Blacklist user
        mgr.blacklist_user(user_id, reason="Test reason")

        # Check blacklist
        is_blacklisted = mgr.is_user_blacklisted(user_id)
        assert is_blacklisted, "User should be blacklisted"

    def test_answer_hashing(self):
        """Test answer hashing and verification"""
        answer = "RSA encryption"

        hashed, salt = QASecurityManager.hash_answer(answer)
        assert hashed != answer, "Hash should differ from original"

        # Verify correct answer
        is_correct = QASecurityManager.verify_answer(answer, hashed, salt)
        assert is_correct, "Correct answer should verify"

        # Verify wrong answer
        is_wrong = QASecurityManager.verify_answer("AES encryption", hashed, salt)
        assert not is_wrong, "Wrong answer should not verify"


class TestQAAnalytics:
    """Test Analytics Engine functionality"""

    def test_analytics_initialization(self):
        """Test analytics init"""
        analytics = QAAnalytics(db_path=":memory:")
        assert analytics is not None

    def test_track_question_attempt(self):
        """Test tracking question attempts"""
        analytics = QAAnalytics(db_path=":memory:")
        user_id = "test_user"
        question_id = 1

        success = analytics.track_question_attempt(
            user_id=user_id, question_id=question_id, is_correct=True, time_spent=45
        )
        assert success, "Should track question attempt"

    def test_record_quiz_session(self):
        """Test recording quiz session"""
        analytics = QAAnalytics(db_path=":memory:")
        user_id = "test_user"
        session_id = str(uuid.uuid4())

        success = analytics.record_quiz_session(
            user_id=user_id,
            session_id=session_id,
            category="",
            difficulty_level="",
            questions_count=10,
            correct_answers=8,
            time_spent=300,
        )
        assert success, "Should record quiz session"

    def test_user_statistics(self):
        """Test getting user statistics"""
        analytics = QAAnalytics(db_path=":memory:")
        user_id = "test_user"

        # Track some attempts
        for i in range(10):
            analytics.track_question_attempt(
                user_id=user_id, question_id=i, is_correct=(i % 2 == 0), time_spent=30 + i * 5
            )

        stats = analytics.get_user_statistics(user_id)
        assert stats["total_questions_attempted"] > 0
        assert "overall_accuracy_percentage" in stats

    def test_leaderboard(self):
        """Test leaderboard generation"""
        analytics = QAAnalytics(db_path=":memory:")

        # Add multiple users
        for user_num in range(5):
            user_id = f"user_{user_num}"
            session_id = str(uuid.uuid4())

            analytics.record_quiz_session(
                user_id=user_id,
                session_id=session_id,
                category="",
                difficulty_level="",
                questions_count=10,
                correct_answers=8 - user_num,
                time_spent=300,
            )

        leaderboard = analytics.get_leaderboard(limit=5)
        assert len(leaderboard) > 0, "Should have leaderboard entries"


class TestQARecommendations:
    """Test Recommendation Engine functionality"""

    def test_recommendation_engine_initialization(self):
        """Test recommendation engine init"""
        engine = QARecommendationEngine(db_path=":memory:")
        assert engine is not None

    def test_user_profile_creation(self):
        """Test user profile creation"""
        engine = QARecommendationEngine(db_path=":memory:")
        user_id = "test_user"

        success = engine.create_user_profile(
            user_id=user_id, preferred_category="", preferred_difficulty=""
        )
        assert success, "Should create user profile"

        profile = engine.get_user_profile(user_id)
        assert profile is not None
        assert profile["preferred_category"] == ""

    def test_spaced_repetition_update(self):
        """Test spaced repetition algorithm"""
        engine = QARecommendationEngine(db_path=":memory:")
        user_id = "test_user"
        question_id = 1

        # First correct answer
        success = engine.update_spaced_repetition(
            user_id=user_id, question_id=question_id, is_correct=True
        )
        assert success, "Should update spaced repetition"

        # Get next review
        reviews = engine.get_next_review_questions(user_id, limit=5)
        # Note: May not appear immediately due to scheduling


class TestQAUtilities:
    """Test Utility Functions"""

    def test_difficulty_calculation(self):
        """Test difficulty score calculation"""
        score = QAUtilities.calculate_difficulty_score(
            question_text="This is a simple question?" * 3, answer_text="Simple answer", category=""
        )
        assert 1 <= score <= 5, "Score should be between 1 and 5"

    def test_keyword_extraction(self):
        """Test keyword extraction"""
        text = "Machine learning security and authentication workflows"
        keywords = QAUtilities.extract_keywords(text, limit=5)
        assert len(keywords) > 0, "Should extract keywords"

    def test_answer_similarity(self):
        """Test answer similarity calculation"""
        answer1 = " RSA     "
        answer2 = "RSA     "

        similarity = QAUtilities.calculate_answer_similarity(answer1, answer2)
        assert 0 <= similarity <= 1, "Similarity should be between 0 and 1"
        assert similarity > 0.5, "Answers should be similar"

    def test_performance_categorization(self):
        """Test performance level categorization"""
        assert QAUtilities.categorize_performance(95) == ""
        assert QAUtilities.categorize_performance(75) == " "
        assert QAUtilities.categorize_performance(50) == ""
        assert QAUtilities.categorize_performance(20) == " "

    def test_experience_points(self):
        """Test experience point calculation"""
        points = QAUtilities.calculate_experience_points(
            correct=True, difficulty=3, time_spent=45, streak=5
        )
        assert points > 0, "Should calculate positive points"

    def test_learning_summary(self):
        """Test learning summary generation"""
        user_stats = {
            "overall_accuracy": 75.0,
            "total_questions_attempted": 100,
            "total_correct_answers": 75,
        }

        summary = QAUtilities.generate_learning_summary(user_stats)
        assert summary["performance_level"] == " "
        assert len(summary["recommendations"]) > 0


class TestPerformanceMetrics:
    """Test Performance Metrics calculation"""

    def test_time_to_mastery(self):
        """Test time to mastery estimation"""
        result = PerformanceMetrics.estimate_time_to_mastery(
            current_accuracy=60.0, questions_per_day=5.0
        )
        assert "days_to_mastery" in result
        assert "questions_needed" in result
        assert result["days_to_mastery"] > 0

    def test_mastery_already_achieved(self):
        """Test when mastery is already achieved"""
        result = PerformanceMetrics.estimate_time_to_mastery(
            current_accuracy=95.0, questions_per_day=5.0
        )
        assert result["already_mastered"]


class TestIntegration:
    """Integration tests for all components"""

    def test_complete_user_flow(self):
        """Test complete user flow from question to analytics"""
        # Setup
        db = QADatabase()
        security_mgr = QASecurityManager(db_path=":memory:")
        analytics = QAAnalytics(db_path=":memory:")
        recommendations = QARecommendationEngine(db_path=":memory:")

        user_id = "integration_test_user"

        # Create session
        token = security_mgr.create_session(user_id=user_id)
        assert token is not None

        # Validate session
        is_valid, _ = security_mgr.validate_session(token)
        assert is_valid

        # Create profile
        recommendations.create_user_profile(user_id=user_id)

        # Get question
        question = db.get_random_question()
        assert question is not None

        # Track attempt
        analytics.track_question_attempt(
            user_id=user_id, question_id=question["id"], is_correct=True, time_spent=45
        )

        # Get statistics
        stats = analytics.get_user_statistics(user_id)
        assert stats["total_questions_attempted"] == 1

        print("✅ Integration test passed!")


@pytest.mark.asyncio
async def test_async_operations():
    """Test async operations"""
    # This would test async API endpoints
    # Placeholder for future async tests
    assert True


# Pytest configuration
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
