import os

import streamlit as st

from utils.faq_engine import get_faq_engine


def _call_openai(prompt: str, model: str = "gpt-3.5-turbo") -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return f"OPENAI_API_KEY not set. Falling back to local assistant.\n\n{_local_helper(prompt)}"

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        content = resp.choices[0].message.content
        if isinstance(content, str) and content.strip():
            return content.strip()
        return "OpenAI returned an empty response."
    except Exception as exc:
        fallback = _local_helper(prompt)
        return (
            f"OpenAI cloud request failed for model '{model}': {exc}\n\n"
            f"Falling back to the local assistant.\n\n{fallback}"
        )


def _local_helper(prompt: str) -> str:
    # Minimal offline assistant: keyword-based help
    """Smart offline AI assistant with comprehensive answers"""
    p = prompt.lower()

    # Authentication & Login
    if any(keyword in p for keyword in ["login", "auth", "sign in", "password", "credential"]):
        return (
            "🔐 **Authentication & Login Help**\n\n"
            "**Secure Bootstrap:**\n"
            "- Create your first admin with `python setup_admin.py`\n"
            "- Optionally set `AGENTIC_IAM_ADMIN_PASSWORD` before running setup\n"
            "- Do not use shared/static passwords in production\n\n"
            "**Failed Login Solutions:**\n"
            "1. Clear browser cache/cookies\n"
            "2. Check CAPS LOCK is off\n"
            "3. Reset password via Admin panel\n"
            "4. Check account is not locked\n\n"
            "**API Authentication:**\n"
            "```bash\n"
            "POST /api/auth/login\n"
            "{\n"
            '  "username": "<your-admin-user>",\n'
            '  "password": "<your-admin-password>"\n'
            "}\n"
            "```"
        )

    # Agent Management
    if any(keyword in p for keyword in ["agent", "register", "create agent", "agent identity"]):
        return (
            "🤖 **Agent Management**\n\n"
            "**Register New Agent:**\n"
            "1. Go to 'Register Agent' page\n"
            "2. Fill in agent details (name, type, description)\n"
            "3. Click 'Register' button\n"
            "4. Agent ID will be generated automatically\n\n"
            "**Agent Types:**\n"
            "- `llm`: Language Model Agent\n"
            "- `task`: Task Automation Agent\n"
            "- `data`: Data Processing Agent\n"
            "- `api`: API Integration Agent\n"
            "- `custom`: Custom Agent\n\n"
            "**Agent Lifecycle:**\n"
            "- **Active**: Agent is running and can perform actions\n"
            "- **Inactive**: Agent paused but not deleted\n"
            "- **Revoked**: Agent credentials revoked, cannot login\n"
            "- **Archived**: Agent historical record only\n\n"
            "**View Agent Details:**\n"
            "Click on any agent in the agent list to see:\n"
            "- Identity and metadata\n"
            "- Permissions and roles\n"
            "- Activity history\n"
            "- Risk assessment scores"
        )

    # Permissions & Authorization
    if any(keyword in p for keyword in ["permission", "role", "authorize", "access control", "rbac"]):
        return (
            "🔑 **Permissions & Authorization**\n\n"
            "**Role-Based Access Control (RBAC):**\n\n"
            "**Admin Role:**\n"
            "- Full system access\n"
            "- User/Agent management\n"
            "- System configuration\n"
            "- Audit log access\n"
            "- Risk assessment\n\n"
            "**Operator Role:**\n"
            "- Agent management\n"
            "- View users and agents\n"
            "- Execute agent actions\n"
            "- View reports\n\n"
            "**Viewer Role:**\n"
            "- Read-only access\n"
            "- View agents and users\n"
            "- View reports and audit logs\n\n"
            "**User Role:**\n"
            "- Basic access\n"
            "- View own profile\n"
            "- Limited agent access\n\n"
            "**Change User Role:**\n"
            "1. Go to 'User Management'\n"
            "2. Select user\n"
            "3. Change role dropdown\n"
            "4. Save changes"
        )

    # User Management
    if any(keyword in p for keyword in ["user", "create user", "manage user", "delete user", "user admin"]):
        return (
            "👥 **User Management**\n\n"
            "**Create New User:**\n"
            "1. Admin → User Management\n"
            "2. Click 'Create User'\n"
            "3. Enter details:\n"
            " - Username (unique)\n"
            " - Email\n"
            " - Password\n"
            " - Role\n"
            "4. Click 'Create'\n\n"
            "**Edit User:**\n"
            "1. Find user in list\n"
            "2. Click 'Edit'\n"
            "3. Modify details\n"
            "4. Save changes\n\n"
            "**Delete User:**\n"
            "1. Select user\n"
            "2. Click 'Delete'\n"
            "3. Confirm deletion\n\n"
            "**Reset Password:**\n"
            "1. User Management\n"
            "2. Find user\n"
            "3. Click 'Reset Password'\n"
            "4. Send reset email"
        )

    # Security & Compliance
    if any(keyword in p for keyword in ["security", "encrypt", "ssl", "tls", "certificate", "compliance"]):
        return (
            "🔒 **Security Features**\n\n"
            "**Transport Security:**\n"
            "- mTLS (Mutual TLS) support\n"
            "- End-to-end encryption\n"
            "- Certificate validation\n"
            "- Session security\n\n"
            "**Data Protection:**\n"
            "- Password hashing (bcrypt)\n"
            "- Credential encryption\n"
            "- Secure key storage\n"
            "- Quantum-ready cryptography\n\n"
            "**Compliance:**\n"
            "- Audit logging\n"
            "- Activity tracking\n"
            "- Compliance reports\n"
            "- Risk assessment\n\n"
            "**Enable mTLS:**\n"
            "1. Edit `config/settings.py`\n"
            "2. Set `enable_mtls=True`\n"
            "3. Configure TLS certificates\n"
            "4. Restart application"
        )

    # Risk Assessment
    if any(keyword in p for keyword in ["risk", "assessment", "threat", "security score"]):
        return (
            "⚠️ **Risk Assessment**\n\n"
            "**Risk Scoring:**\n"
            "Agents and users get risk scores based on:\n"
            "- Login frequency and patterns\n"
            "- Permission changes\n"
            "- Failed login attempts\n"
            "- Unusual activity\n"
            "- Account age\n\n"
            "**Risk Levels:**\n"
            "- 🟢 **Low (0-30%)**: Normal activity\n"
            "- 🟡 **Medium (30-60%)**: Review recommended\n"
            "- 🔴 **High (60-100%)**: Investigate immediately\n\n"
            "**View Risk Assessment:**\n"
            "1. Go to 'Risk Assessment' tab\n"
            "2. See agents sorted by risk\n"
            "3. Click agent for detailed analysis\n"
            "4. Review activity and recommendations\n\n"
            "**Mitigate Risk:**\n"
            "- Rotate credentials\n"
            "- Review permissions\n"
            "- Disable/revoke if needed\n"
            "- Monitor activity"
        )

    # Reports & Analytics
    if any(keyword in p for keyword in ["report", "analytics", "dashboard", "chart", "metrics"]):
        return (
            "📊 **Reports & Analytics**\n\n"
            "**Available Reports:**\n"
            "- User Activity Report\n"
            "- Agent Performance Report\n"
            "- Authentication Report\n"
            "- Risk Assessment Report\n"
            "- Compliance Report\n\n"
            "**Dashboard Metrics:**\n"
            "- Total Users & Agents\n"
            "- Active Sessions\n"
            "- Failed Logins\n"
            "- High-Risk Agents\n"
            "- Recent Activities\n\n"
            "**Generate Report:**\n"
            "1. Go to 'Reports' section\n"
            "2. Select report type\n"
            "3. Choose date range\n"
            "4. Click 'Generate'\n"
            "5. Download or export\n\n"
            "**Export Formats:**\n"
            "- PDF\n"
            "- Excel\n"
            "- CSV\n"
            "- JSON"
        )

    # Default response with suggestions
    return (
        "🤖 **AI Assistant Ready!**\n\n"
        "I can help you with:\n\n"
        "1. **🔐 Login & Authentication** - Help with credentials and access\n"
        "2. **🤖 Agent Management** - Register and manage AI agents\n"
        "3. **🔑 Permissions** - Set up roles and access control\n"
        "4. **👥 User Management** - Create and manage users\n"
        "5. **🔒 Security** - Encryption, mTLS, compliance\n"
        "6. **⚠️ Risk Assessment** - Security scoring and monitoring\n"
        "7. **📊 Reports** - Analytics and reporting\n\n"
        "**Try asking:**\n"
        '- "How do I login?"\n'
        '- "How to create a new user?"\n'
        '- "What are the available roles?"\n'
        '- "How do I register an agent?"\n'
        '- "What is risk assessment?"\n\n'
        "Or describe what you need help with!"
    )


def show_ai_assistant():
    st.header("🤖 AI Assistant - Smart Q&A Engine")
    st.write(
        "🚀 Ask any question about Agentic-IAM (Arabic or English, typos OK!) and get multiple answer options to choose from."
    )

    # Initialize session state for answer selection
    if "faq_answers" not in st.session_state:
        st.session_state.faq_answers = None
    if "faq_selected_option" not in st.session_state:
        st.session_state.faq_selected_option = None

    # Tab 1: Smart FAQ
    tab1, tab2, tab3 = st.tabs(["💡 Smart FAQ", "🔍 Browse Categories", "⚙️ Advanced"])

    with tab1:
        st.subheader("Ask Your Question")

        col1, col2 = st.columns([4, 1])
        with col1:
            user_question = st.text_input(
                "Type your question (English or , spelling errors are OK!)",
                placeholder="E.g., '   ?' or 'How do I register an agent?'",
            )

        with col2:
            num_answers = st.selectbox("Answer options:", [3, 5, 8], index=1)

        if st.button("🔍 Search for Answers", key="faq_search"):
            if not user_question or not user_question.strip():
                st.warning("⚠️ Please enter a question first!")
            else:
                with st.spinner("🔎 Searching FAQ database..."):
                    try:
                        faq_engine = get_faq_engine()
                        answers = faq_engine.get_answers(user_question, top_k=num_answers)
                        st.session_state.faq_answers = answers
                        st.session_state.faq_selected_option = None

                        if not answers:
                            st.info("❌ No answers found. Try different keywords or check 'Browse Categories' tab.")
                        else:
                            st.success(f"✅ Found {len(answers)} answer options!")
                    except Exception as e:
                        st.error(f"❌ Error searching FAQ: {str(e)}")

        # Display answer options
        if st.session_state.faq_answers:
            st.markdown("---")
            st.subheader(f"📋 Answer Options ({len(st.session_state.faq_answers)} found)")

            answers = st.session_state.faq_answers

            # Display each option as a card
            for i, answer in enumerate(answers):
                with st.container():
                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.markdown(f"**Option {i+1}:** {answer['category']}")
                        st.caption(f"Level: {answer['difficulty'].upper()}")

                    with col2:
                        if st.button(f"View Option {i+1}", key=f"view_ans_{i}"):
                            st.session_state.faq_selected_option = i

                    with col3:
                        if st.button("Copy", key=f"copy_ans_{i}"):
                            st.success("✅ Copied to clipboard (implementation needed)")

                    # Show preview
                    preview = answer["answer"][:150] + "..." if len(answer["answer"]) > 150 else answer["answer"]
                    st.markdown(f"> {preview}")
                    st.markdown("---")

            # Display selected answer in full
            if st.session_state.faq_selected_option is not None:
                selected_idx = st.session_state.faq_selected_option
                selected_answer = answers[selected_idx]

                st.markdown("---")
                st.subheader(f"📖 Full Answer - Option {selected_idx + 1}")

                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**Category:** {selected_answer['category']}")
                    st.markdown(f"**Difficulty Level:** {selected_answer['difficulty'].upper()}")

                with col2:
                    if selected_answer.get("related_topics"):
                        st.markdown("**Related Topics:**")
                        for topic in selected_answer["related_topics"]:
                            st.caption(f"📌 {topic}")

                st.markdown("---")
                st.markdown(selected_answer["answer"])
                st.markdown("---")

                # Related topics
                if selected_answer.get("related_topics"):
                    st.markdown("**🔗 Related Topics:**")
                    for topic in selected_answer["related_topics"]:
                        st.caption(f"• {topic}")

    with tab2:
        st.subheader("📚 Browse by Category")

        try:
            faq_engine = get_faq_engine()
            categories = faq_engine.get_faq_categories()

            if categories:
                selected_category = st.selectbox("Choose a category:", categories)

                if st.button("📖 Show Category Questions"):
                    questions = faq_engine.get_questions_by_category(selected_category)

                    if questions:
                        st.success(f"Found {len(questions)} questions in this category")

                        for item in questions[:10]:  # Show first 10
                            st.markdown(f"**Q:** {item.get('question_en', '')}")
                            if item.get("question_ar"):
                                st.caption(f"(: {item['question_ar']})")

                            answers = item.get("answers", [])
                            if answers:
                                for ans in answers[:2]:  # Show first 2 answers
                                    with st.expander(f"Answer ({ans.get('difficulty', 'beginner').upper()})"):
                                        st.markdown(ans.get("text", ""))
                            st.markdown("---")
                    else:
                        st.info("No questions found in this category")
            else:
                st.warning("No categories available")
        except Exception as e:
            st.error(f"Error loading categories: {str(e)}")

    with tab3:
        st.subheader("⚙️ Advanced Options")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**FAQ Engine Stats**")
            try:
                faq_engine = get_faq_engine()
                st.metric("Total Questions", len(faq_engine.question_cache))
                st.metric("Categories", len(faq_engine.get_faq_categories()))
            except BaseException:
                st.info("FAQ engine not initialized")

        with col2:
            st.markdown("**Advanced Features**")

            # Spelling check
            if st.checkbox("Show spelling corrections"):
                test_text = st.text_input("Test spelling correction:")
                if test_text:
                    try:
                        faq_engine = get_faq_engine()
                        corrected = faq_engine.correct_spelling(test_text)
                        st.info(f"Corrected: {corrected}")
                    except BaseException:
                        st.error("Error correcting spelling")

            # OpenAI integration
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                with st.expander("🤖 Enable OpenAI (Optional)"):
                    key_input = st.text_input("OPENAI_API_KEY", type="password")
                    if key_input:
                        os.environ["OPENAI_API_KEY"] = key_input
                        st.success("✅ API key set for this session")

        st.markdown("---")

        # Reload FAQ data
        if st.button("🔄 Reload FAQ Database"):
            try:
                faq_engine = get_faq_engine()
                faq_engine.faq_data = faq_engine._load_faq()
                faq_engine._build_cache()
                st.success("✅ FAQ database reloaded!")
            except Exception as e:
                st.error(f"❌ Error reloading: {str(e)}")
