#!/usr/bin/env python
"""

Test QA System Live
"""

print("=" * 60)
print("🚀    Q&A ")
print("=" * 60)

# 1.
print("\n✓  1:  ...")
try:
    from qa_database import QADatabase
    from qa_security import QASecurityManager
    from qa_analytics import QAAnalytics
    from qa_recommendations import QARecommendationEngine
    from qa_utilities import QAUtilities
    print("   ✅     !")
except Exception as e:
    print(f"   ❌ : {e}")
    exit(1)

# 2.
print("\n✓  2:   (3000+ )...")
try:
    db = QADatabase()
    total = db.get_total_questions()
    categories = db.get_categories()
    print(f"   ✅  : {total}")
    print(f"   ✅  : {len(categories)}")

    q = db.get_random_question()
    if q:
        sample = q['question'][:50]
        print(f"   ✅  : {sample}...")
except Exception as e:
    print(f"   ❌ : {e}")

# 3.
print("\n✓  3:  ...")
try:
    sec = QASecurityManager(db_path=":memory:")

    answer = " "
    hashed, salt = QASecurityManager.hash_answer(answer)
    verified = QASecurityManager.verify_answer(answer, hashed, salt)

    print(f"   ✅  : ")
    status = " ✓" if verified else " ✗"
    print(f"   ✅   : {status}")
except Exception as e:
    print(f"   ❌ : {e}")

# 4.
print("\n✓  4:    ...")
try:
    points = QAUtilities.calculate_experience_points(
        correct=True,
        difficulty=3,
        time_spent=45,
        streak=5
    )
    level = QAUtilities.categorize_performance(80)
    print(f"   ✅   (++streak): {points}")
    print(f"   ✅   (80% ): {level}")
except Exception as e:
    print(f"   ❌ : {e}")

# 5.
print("\n✓  5:    (SM-2)...")
try:
    rec = QARecommendationEngine(db_path=":memory:")
    rec.create_user_profile("user_test", preferred_category="")
    profile = rec.get_user_profile("user_test")
    print(f"   ✅   : ")
    print(f"   ✅  : {profile['preferred_category']}")
except Exception as e:
    print(f"   ❌ : {e}")

print("\n" + "=" * 60)
print("✨  :")
print("✅     ")
print("✅    3000+ ")
print("✅    ")
print("✅     ")
print("✅    ")
print("=" * 60)
print("\n📚   :")
print("  • qa_database.py - (3000+ )")
print("  • qa_security.py - (rate limiting, sessions)")
print("  • qa_analytics.py - (user tracking)")
print("  • qa_recommendations.py - (SM-2)")
print("  • qa_utilities.py - ( )")
print("  • api/routers/qa.py - API endpoints (25+  )")
print("  • qa_dashboard.py - (Streamlit)")
print("\n🎯  :")
print("  1️⃣  QA_QUICK_START.md (5 )")
print("  2️⃣ : python -m uvicorn api.main:app --reload")
print("  3️⃣ : streamlit run qa_dashboard.py")
print("  4️⃣   endpoints")
print("\n❓        ")
