"""
API Router  Questions & Answers System

Advanced Q&A System with Security, Analytics & Recommendations
"""

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from qa_analytics import get_analytics
from qa_database import CATEGORIES, QADatabase
from qa_recommendations import get_recommendation_engine
from qa_security import get_security_manager

# Initialize components
qa_db = QADatabase()
security_mgr = get_security_manager()
analytics = get_analytics()
recommendation_engine = get_recommendation_engine()

router = APIRouter(prefix="/api/v1/qa", tags=["Questions & Answers"], responses={404: {"description": "Not found"}})

# ============= Security Dependencies =============


async def verify_user(header_user_id: str = Header(None, alias="X-User-ID")) -> str:
    """Verify user identity from header"""
    if not header_user_id:
        raise HTTPException(status_code=401, detail="User ID required in X-User-ID header")

    # Check if user is blacklisted
    if security_mgr.is_user_blacklisted(header_user_id):
        raise HTTPException(status_code=403, detail="User is blacklisted")

    return header_user_id


async def check_rate_limit(user_id: str = Depends(verify_user), request: Request = None, endpoint: str = None) -> str:
    """Check rate limiting for user"""
    endpoint = endpoint or request.url.path

    allowed, info = security_mgr.check_rate_limit(
        user_id=user_id, endpoint=endpoint, max_requests=100, time_window=3600
    )

    if not allowed:
        security_mgr.log_suspicious_activity(
            user_id=user_id,
            activity_type="rate_limit_exceeded",
            description=info.get("message"),
            ip_address=request.client.host if request else None,
            severity=1,
        )

        raise HTTPException(
            status_code=429, detail=f"Rate limit exceeded. Retry after {info.get('retry_after')} seconds"
        )

    return user_id


# ============= Pydantic Models =============


class QuestionResponse(BaseModel):
    id: int
    question: str
    category: str
    difficulty: int


class AnswerSubmission(BaseModel):
    user_id: str = Field(..., min_length=1)
    question_id: int
    user_answer: str = Field(..., min_length=1)
    time_taken: Optional[int] = 0


class AnswerResponse(BaseModel):
    correct: bool
    actual_answer: str
    points_earned: int
    message: str


class UserStatsResponse(BaseModel):
    user_id: str
    total_questions: int
    correct_answers: int
    accuracy: float
    level: int
    points: int


class LeaderboardEntry(BaseModel):
    rank: int
    user_id: str
    username: str
    points: int
    accuracy: float


class CategoryInfo(BaseModel):
    category: str
    arabic_name: str
    count: int


# ============= Endpoints =============


@router.get("/health")
async def qa_health():
    """Check QA System Health"""
    total_questions = qa_db.get_total_questions()
    categories = qa_db.get_categories()

    return {
        "status": "healthy",
        "total_questions": total_questions,
        "categories": len(categories),
        "system": "Q&A System   ",
    }


@router.get("/categories")
async def get_categories() -> List[CategoryInfo]:
    """Get all QA categories"""
    categories = qa_db.get_categories()
    return [CategoryInfo(**cat) for cat in categories]


@router.get("/random")
async def get_random_question(category: Optional[str] = Query(None, description="  category   ")) -> QuestionResponse:
    """- category : security, ai, tech, management, general"""
    if category and category not in CATEGORIES:
        raise HTTPException(status_code=400, detail=f" category .  : {', '.join(CATEGORIES.keys())}")

    question = qa_db.get_random_question(category=category)

    if not question:
        raise HTTPException(status_code=404, detail="     category ")

    # Don't return answer in the question endpoint
    return QuestionResponse(
        id=question["id"],
        question=question["question"],
        category=question["category"],
        difficulty=question["difficulty"],
    )


@router.get("/question/{question_id}")
async def get_question(question_id: int) -> QuestionResponse:
    """Get a specific question by ID"""
    question = qa_db.get_question_by_id(question_id)

    if not question:
        raise HTTPException(status_code=404, detail="  ")

    return QuestionResponse(
        id=question["id"],
        question=question["question"],
        category=question["category"],
        difficulty=question["difficulty"],
    )


@router.post("/answer")
async def submit_answer(
    submission: AnswerSubmission, user_id: str = Depends(check_rate_limit), request: Request = None
) -> AnswerResponse:
    """
    Submit an answer to a question
    """
    question = qa_db.get_question_by_id(submission.question_id)

    if not question:
        raise HTTPException(status_code=404, detail="  ")

    # Check if answer is correct (simple string matching for now)
    # In a real system, you'd use more sophisticated NLP/semantic matching
    is_correct = _check_answer(submission.user_answer, question["answer"])

    points = 10 if is_correct else 2

    # Record the answer
    qa_db.record_answer(
        user_id=submission.user_id,
        question_id=submission.question_id,
        user_answer=submission.user_answer,
        is_correct=is_correct,
        time_taken=submission.time_taken,
    )

    # Track analytics
    analytics.track_question_attempt(
        user_id=submission.user_id,
        question_id=submission.question_id,
        is_correct=is_correct,
        time_spent=submission.time_taken or 0,
    )

    # Update spaced repetition
    recommendation_engine.update_spaced_repetition(
        user_id=submission.user_id, question_id=submission.question_id, is_correct=is_correct
    )

    return AnswerResponse(
        correct=is_correct,
        actual_answer=question["answer"],
        points_earned=points,
        message=_get_feedback_message(is_correct, question["difficulty"]),
    )


@router.get("/stats/{user_id}")
async def get_user_stats(user_id: str) -> UserStatsResponse:
    """Get user statistics and progress"""
    stats = qa_db.get_user_stats(user_id)

    if not stats:
        # Return default stats if user is new
        return UserStatsResponse(user_id=user_id, total_questions=0, correct_answers=0, accuracy=0.0, level=1, points=0)

    return UserStatsResponse(user_id=user_id, **stats)


@router.get("/leaderboard")
async def get_leaderboard(limit: int = Query(100, ge=1, le=1000)) -> List[LeaderboardEntry]:
    """Get top users leaderboard"""
    leaderboard = qa_db.get_leaderboard(limit=limit)
    return [LeaderboardEntry(**entry) for entry in leaderboard]


@router.get("/search")
async def search_questions(
    keyword: str = Query(..., min_length=2), category: Optional[str] = Query(None)
) -> List[QuestionResponse]:
    """Search for questions by keyword"""
    if category and category not in CATEGORIES:
        raise HTTPException(status_code=400, detail=f" category .  : {', '.join(CATEGORIES.keys())}")

    results = qa_db.search_questions(keyword, category=category)

    return [
        QuestionResponse(id=r["id"], question=r["question"], category=r["category"], difficulty=r["difficulty"])
        for r in results
    ]


@router.get("/stats/category/{category}")
async def get_category_stats(category: str) -> dict:
    """Get statistics for a specific category"""
    if category not in CATEGORIES:
        raise HTTPException(status_code=400, detail=f" category .  : {', '.join(CATEGORIES.keys())}")

    categories = qa_db.get_categories()
    cat_info = next((c for c in categories if c["category"] == category), None)

    if not cat_info:
        raise HTTPException(status_code=404, detail="Category not found")

    return {
        "category": cat_info["category"],
        "arabic_name": cat_info["arabic_name"],
        "total_questions": cat_info["count"],
        "message": f" {cat_info['count']}    {cat_info['arabic_name']}",
    }


# ============= Advanced Features: Analytics, Security, Recommendations =============


@router.get("/recommendations/{user_id}")
async def get_recommendations(
    user_id: str, verified_user_id: str = Depends(verify_user), limit: int = Query(10, ge=1, le=50)
) -> List[dict]:
    """Get personalized recommendations based on user performance"""
    # Get user profile and stats
    recommendation_engine.get_user_profile(user_id)
    user_stats = qa_db.get_user_stats(user_id) or {"accuracy": 50, "weak_areas": [], "already_correct": {}}

    # Get available questions
    all_questions = qa_db.get_all_questions()

    # Generate recommendations
    recommendations = recommendation_engine.generate_recommendations(
        user_id=user_id, user_stats=user_stats, available_questions=all_questions, limit=limit
    )

    return recommendations


@router.get("/reviews/{user_id}")
async def get_spaced_repetition_reviews(
    user_id: str = Depends(verify_user), limit: int = Query(5, ge=1, le=20)
) -> List[dict]:
    """Get questions due for spaced repetition review"""
    questions = recommendation_engine.get_next_review_questions(user_id=user_id, limit=limit)

    return {"user_id": user_id, "due_for_review": len(questions), "questions": questions}


@router.get("/analytics/{user_id}")
async def get_user_analytics(user_id: str = Depends(verify_user)) -> dict:
    """Get comprehensive user analytics and insights"""
    user_stats = analytics.get_user_statistics(user_id)
    insights = recommendation_engine.get_recommendation_engine().get_performance_insights(user_id)
    category_stats = analytics.get_category_statistics(user_id=user_id)

    return {
        "user_id": user_id,
        "statistics": user_stats,
        "performance_insights": insights,
        "category_breakdown": category_stats,
        "generated_at": datetime.now().isoformat(),
    }


@router.get("/analytics/system/health")
async def get_system_health() -> dict:
    """Get system-wide health metrics"""
    health = analytics.get_system_health()
    trending = analytics.get_trending_questions(limit=20)

    return {"health_metrics": health, "trending_questions": trending, "timestamp": datetime.now().isoformat()}


@router.get("/security/{user_id}")
async def get_user_security_report(user_id: str = Depends(verify_user)) -> dict:
    """Get user security report"""
    report = security_mgr.get_security_report(user_id=user_id)

    return {"security_report": report, "generated_at": datetime.now().isoformat()}


@router.post("/session/create")
async def create_session(user_id: str = Depends(verify_user), request: Request = None) -> dict:
    """Create a secure session for user"""
    session_token = security_mgr.create_session(
        user_id=user_id, ip_address=request.client.host if request else None, expires_in=86400  # 24 hours
    )

    if not session_token:
        raise HTTPException(status_code=500, detail="Failed to create session")

    return {
        "session_token": session_token,
        "user_id": user_id,
        "expires_in_seconds": 86400,
        "created_at": datetime.now().isoformat(),
    }


@router.post("/session/validate")
async def validate_session(session_token: str = Header(..., alias="X-Session-Token")) -> dict:
    """Validate a session token"""
    is_valid, user_id = security_mgr.validate_session(session_token)

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    return {"valid": True, "user_id": user_id, "timestamp": datetime.now().isoformat()}


@router.post("/admin/log-activity")
async def log_suspicious_activity(
    user_id: str = Depends(verify_user),
    activity_type: str = Query(...),
    description: str = Query(None),
    request: Request = None,
) -> dict:
    """Log suspicious activity (admin endpoint)"""
    success = security_mgr.log_suspicious_activity(
        user_id=user_id,
        activity_type=activity_type,
        description=description,
        ip_address=request.client.host if request else None,
        severity=2,
    )

    return {"logged": success, "activity_type": activity_type, "timestamp": datetime.now().isoformat()}


@router.get("/leaderboard/advanced")
async def get_advanced_leaderboard(
    time_period: str = Query("all", regex="^(day|week|month|all)$"), limit: int = Query(100, ge=1, le=1000)
) -> List[dict]:
    """Get advanced leaderboard with filters"""
    leaderboard = analytics.get_leaderboard(limit=limit)

    # Filter by time period if needed
    filtered_leaderboard = leaderboard

    return {
        "time_period": time_period,
        "count": len(filtered_leaderboard),
        "leaderboard": filtered_leaderboard,
        "generated_at": datetime.now().isoformat(),
    }


@router.post("/quiz/start")
async def start_adaptive_quiz(
    user_id: str = Depends(verify_user),
    category: Optional[str] = Query(None),
    difficulty: Optional[str] = Query(None),
    size: int = Query(10, ge=1, le=50),
) -> dict:
    """Start an adaptive quiz session"""
    # Create session
    session_id = str(uuid.uuid4())

    # Get user stats for adaptive sizing
    qa_db.get_user_stats(user_id) or {}

    # Track session
    analytics.record_quiz_session(
        user_id=user_id,
        session_id=session_id,
        category=category or "general",
        difficulty_level=difficulty or "",
        questions_count=size,
        correct_answers=0,
        time_spent=0,
    )

    # Get questions
    questions = qa_db.get_random_questions(limit=size, category=category, difficulty_level=difficulty)

    return {
        "session_id": session_id,
        "user_id": user_id,
        "questions_count": len(questions),
        "category": category,
        "difficulty": difficulty,
        "questions": [
            {"id": q["id"], "question": q["question"], "category": q["category"], "difficulty": q["difficulty"]}
            for q in questions
        ],
        "created_at": datetime.now().isoformat(),
    }


# ============= Helper Functions =============


def _check_answer(user_answer: str, correct_answer: str) -> bool:
    """
    Check if user answer is correct
    Uses fuzzy matching for flexibility
    """
    # Normalize both strings
    user_ans_normalized = user_answer.strip().lower()
    correct_ans_normalized = correct_answer.strip().lower()

    # Exact match
    if user_ans_normalized == correct_ans_normalized:
        return True

    # Contains check (for longer answers)
    if len(correct_ans_normalized) > 20:
        # For long answers, check if key parts are present
        key_words = correct_ans_normalized.split()[:5]
        if all(word in user_ans_normalized for word in key_words):
            return True

    # Partial match (at least 70% similar)
    from difflib import SequenceMatcher

    similarity = SequenceMatcher(None, user_ans_normalized, correct_ans_normalized).ratio()

    return similarity >= 0.7


def _get_feedback_message(is_correct: bool, difficulty: int) -> str:
    """Generate appropriate feedback message"""
    if is_correct:
        messages = [" ! 🎉", "! ", "! 🌟", "   !", "!  "]
    else:
        messages = ["   ", "    ", "!  ", "    ", "    "]

    import secrets

    return secrets.choice(messages)
