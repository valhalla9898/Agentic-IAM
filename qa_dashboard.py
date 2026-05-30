"""
Streamlit Dashboard for the Q&A System.
"""

import secrets
import time

import pandas as pd
import streamlit as st

from qa_database import CATEGORIES, QADatabase

# Page configuration
st.set_page_config(
    page_title="🎓 Q&A Dashboard", page_icon="🧠", layout="wide", initial_sidebar_state="expanded"
)

# Initialize session state
if "qa_db" not in st.session_state:
    st.session_state.qa_db = QADatabase()

if "user_id" not in st.session_state:
    st.session_state.user_id = f"user_{secrets.randbelow(9000) + 1000}"

if "current_question" not in st.session_state:
    st.session_state.current_question = None

if "start_time" not in st.session_state:
    st.session_state.start_time = None

# Custom CSS
st.markdown(
    """
<style>
    .main-title {
        text-align: center;
        color: #1f77b4;
        font-size: 3em;
        margin-bottom: 20px;
        font-weight: bold;
    }

    .question-box {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
        margin: 20px 0;
    }

    .answer-box {
        background-color: #e8f5e9;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }

    .success-message {
        background-color: #4caf50;
        color: white;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }

    .error-message {
        background-color: #f44336;
        color: white;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }

    .stats-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Main title
st.markdown("<h1 class='main-title'>🎓 Q&A Dashboard</h1>", unsafe_allow_html=True)
st.markdown("---")

# Sidebar
with st.sidebar:
    st.title("Q&A")
    page = st.radio("Navigation", ["🏠 Home", "❓ Practice", "📊 Statistics", "🏆 Leaderboard", "🔍 Search"])

    st.markdown("---")
    st.info(f"🆔 User ID: {st.session_state.user_id}")

    # System info
    total_q = st.session_state.qa_db.get_total_questions()
    st.success(f"📚 Questions: {total_q}")

# ============= HOME PAGE =============
if page == "🏠 Home":
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            '<div class="stats-card"><h3>Total Questions</h3><h1>3000+</h1></div>', unsafe_allow_html=True
        )

    with col2:
        stats = st.session_state.qa_db.get_user_stats(st.session_state.user_id)
        if stats:
            st.markdown(
                f'<div class="stats-card"><h3>Your Points</h3><h1>{stats["points"]}</h1></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown('<div class="stats-card"><h3>Your Points</h3><h1>0</h1></div>', unsafe_allow_html=True)

    with col3:
        categories = st.session_state.qa_db.get_categories()
        st.markdown(
            f'<div class="stats-card"><h3>Categories</h3><h1>{len(categories)}</h1></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Categories overview
    st.subheader("📂 Categories")

    categories = st.session_state.qa_db.get_categories()

    if categories:
        cols = st.columns(len(categories))

        for idx, (col, cat) in enumerate(zip(cols, categories)):
            with col:
                st.metric(label=cat["arabic_name"], value=cat["count"], delta="")

    st.markdown("---")

    # Features
    st.subheader("✨ Features")

    features = [
        "✅ 3000+ questions",
        "✅ AI topic coverage",
        "✅ Practice mode",
        "✅ Statistics and progress",
        "✅ Leaderboard",
        "✅ Search across questions",
        "✅ Category filtering",
        "✅ Learning-friendly UI",
    ]

    for feature in features:
        st.write(feature)

# ============= QUESTIONS PAGE =============
elif page == "❓ Practice":
    st.subheader("Practice Questions")

    col1, col2 = st.columns([3, 1])

    with col2:
        selected_category = st.selectbox(
            "Category",
            [""] + list(CATEGORIES.keys()),
            format_func=lambda x: "All categories" if x == "" else CATEGORIES[x],
        )

    with col1:
        if st.button("📝 New Question", use_container_width=True):
            category = None if selected_category == "" else selected_category
            st.session_state.current_question = st.session_state.qa_db.get_random_question(
                category=category
            )
            st.session_state.start_time = time.time()

    st.markdown("---")

    if st.session_state.current_question:
        q = st.session_state.current_question

        # Display question
        st.markdown(
            f'<div class="question-box"><h2>❓ Question</h2><h3>{q["question"]}</h3></div>',
            unsafe_allow_html=True,
        )

        # Display category and difficulty
        col1, col2 = st.columns(2)
        with col1:
            st.badge(f"Category: {CATEGORIES.get(q['category'], q['category'])}")
        with col2:
            difficulty_text = (
                " 🟢" if q["difficulty"] == 1 else " 🟡" if q["difficulty"] == 2 else " 🔴"
            )
            st.badge(f"Difficulty: {difficulty_text}")

        st.markdown("---")

        # Answer input
        st.subheader("Your Answer")
        user_answer = st.text_area("Answer", height=100, placeholder="Type your answer here...")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("✅ Submit Answer", use_container_width=True):
                if not user_answer.strip():
                    st.error("Please enter an answer.")
                else:
                    time_taken = (
                        int(time.time() - st.session_state.start_time)
                        if st.session_state.start_time
                        else 0
                    )

                    # Check answer
                    from difflib import SequenceMatcher

                    correct_answer = q["answer"].lower().strip()
                    user_ans_normalized = user_answer.lower().strip()

                    is_correct = (
                        user_ans_normalized == correct_answer
                        or SequenceMatcher(None, user_ans_normalized, correct_answer).ratio() >= 0.7
                    )

                    points = 10 if is_correct else 2

                    # Record answer
                    st.session_state.qa_db.record_answer(
                        user_id=st.session_state.user_id,
                        question_id=q["id"],
                        user_answer=user_answer,
                        is_correct=is_correct,
                        time_taken=time_taken,
                    )

                    # Display result
                    if is_correct:
                        st.success(f"✅ Correct. Points earned: {points}")
                    else:
                        st.error(f"❌ Incorrect. Points earned: {points}")

                    st.markdown(
                        f'<div class="answer-box"><h4>✅ Correct Answer</h4><p>{q["answer"]}</p></div>',
                        unsafe_allow_html=True,
                    )

                    if time_taken > 0:
                        st.info(f"⏱️ Time taken: {time_taken} seconds")

        with col2:
            if st.button("⏭️ Next Question", use_container_width=True):
                category = None if selected_category == "" else selected_category
                st.session_state.current_question = st.session_state.qa_db.get_random_question(
                    category=category
                )
                st.session_state.start_time = time.time()
                st.rerun()

    else:
        st.info("Click 'New Question' to start practicing.")

# ============= STATISTICS PAGE =============
elif page == "📊 Statistics":
    st.subheader("Statistics")

    stats = st.session_state.qa_db.get_user_stats(st.session_state.user_id)

    if stats:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Level", f"Level {stats['level']}", "🎯")

        with col2:
            st.metric("Points", stats["points"], "⭐")

        with col3:
            st.metric("Questions", stats["total_questions"], "❓")

        with col4:
            st.metric("Accuracy", f"{stats['accuracy']:.1f}%", "🎯")

        st.markdown("---")

        # Progress chart
        st.subheader("📈 Progress Chart")

        if stats["total_questions"] > 0:
            progress_data = {
                "label": ["Correct", "Incorrect"],
                "count": [
                    stats["correct_answers"],
                    stats["total_questions"] - stats["correct_answers"],
                ],
            }

            df = pd.DataFrame(progress_data)
            st.bar_chart(df.set_index("label"))

        st.markdown("---")

        # Category performance
        st.subheader("📊 Category Performance")

        categories = st.session_state.qa_db.get_categories()

        for cat in categories:
            with st.expander(f"📌 {cat['arabic_name']} ({cat['count']} )"):
                st.write(f"Questions: {cat['count']}")

    else:
        st.info("No statistics available yet. Start practicing to generate data.")

# ============= LEADERBOARD PAGE =============
elif page == "🏆 Leaderboard":
    st.subheader("🏆 Leaderboard")

    leaderboard = st.session_state.qa_db.get_leaderboard(limit=50)

    if leaderboard:
        # Create DataFrame
        df = pd.DataFrame(
            [
                {
                    "Rank": entry["rank"],
                    "User": entry["user_id"],
                    "Points": entry["points"],
                    "Accuracy": f"{entry['accuracy']:.1f}%",
                }
                for entry in leaderboard
            ]
        )

        st.dataframe(df, use_container_width=True)

        # Check user's position
        st.markdown("---")
        st.subheader("📍 Your Position")

        user_position = next(
            (
                idx + 1
                for idx, entry in enumerate(leaderboard)
                if entry["user_id"] == st.session_state.user_id
            ),
            None,
        )

        if user_position:
            st.success(f"You are ranked #{user_position} 🎉")
        else:
            st.info("No leaderboard position yet.")

    else:
        st.info("No leaderboard data yet.")

# ============= SEARCH PAGE =============
elif page == "🔍 Search":
    st.subheader("🔍 Search")

    search_keyword = st.text_input("Search keyword")

    search_category = st.selectbox(
        "Category (optional)",
        [""] + list(CATEGORIES.keys()),
        format_func=lambda x: "All categories" if x == "" else CATEGORIES[x],
    )

    if st.button("🔎 Search", use_container_width=True):
        if search_keyword:
            category = None if search_category == "" else search_category
            results = st.session_state.qa_db.search_questions(search_keyword, category=category)

            st.markdown(f"### Results: {len(results)}")
            st.markdown("---")

            if results:
                for idx, result in enumerate(results, 1):
                    with st.expander(f"❓ {idx}: {result['question'][:50]}..."):
                        st.write(f"**Question:** {result['question']}")
                        st.write(f"**Category:** {CATEGORIES.get(result['category'], result['category'])}")
                        st.write(f"**Answer:** {result['answer']}")
                        difficulty_text = (
                            " 🟢"
                            if result["difficulty"] == 1
                            else " 🟡" if result["difficulty"] == 2 else " 🔴"
                        )
                        st.write(f"**Difficulty:** {difficulty_text}")
            else:
                st.warning("No matching questions found.")
        else:
            st.warning("Please enter a search keyword.")

# Footer
st.markdown("---")
st.markdown(
    """
<div style="text-align: center; color: #666;">
    <p>🧠 Q&A v1.0 | 3000+ questions</p>
    <p>👨‍💻 Made with ❤️ for Learning</p>
</div>
""",
    unsafe_allow_html=True,
)
