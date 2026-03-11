import streamlit as st
import os
from typing import Optional
from . import ai_kb


def _call_openai(prompt: str, model: str = "gpt-3.5-turbo") -> str:
    try:
        import openai
    except Exception:
        return "OpenAI SDK not installed. Set OPENAI_API_KEY and install `openai` to enable cloud assistant."

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "OPENAI_API_KEY not set. Provide the key to use OpenAI assistant."

    openai.api_key = api_key
    try:
        resp = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"OpenAI request failed: {e}"


def _local_helper(prompt: str) -> str:
    # Minimal offline assistant: keyword-based help
    p = prompt.lower()
    if "login" in p or "auth" in p:
        return (
            "Login help:\n- Use the demo credentials on the login page (admin/operator/user).\n"
            "- If you need to create a user, go to User Management (Admin).\n- For API login, POST /api/auth/login with username/password."
        )
    if "mtls" in p or "certificate" in p:
        return (
            "mTLS guidance:\n- Enable mTLS in `config/settings.py` by setting `enable_mtls=True`.\n"
            "- Configure your TLS terminator (NGINX/Ingress) to forward `x-ssl-client-verify` and `x-forwarded-client-cert`."
        )
    if "secrets" in p or "vault" in p:
        return (
            "Secrets guidance:\n- Use the SecretManager scaffold at `secrets/key_vault.py`.\n"
            "- Set AZURE_KEYVAULT_URL or put env vars like SECRET_KEY/ENCRYPTION_KEY."
        )
    # Fallback: echo with short tips
    return "I can help with: login, mTLS, secrets, Playwright tests, and basic usage. Ask about one of those topics."


def show_ai_assistant():
    st.header("🤖 AI Assistant")
    st.write("Ask the assistant to explain features, or get quick how-to steps.")

    col1, col2 = st.columns([3, 1])
    with col1:
        prompt = st.text_area("Ask a question or describe what you want help with", height=160)
    with col2:
        model = st.selectbox("Model", ["local", "knowledge", "openai:gpt-3.5-turbo"], index=0)
        if st.button("Ask"):
            if not prompt or not prompt.strip():
                st.warning("Please enter a question or prompt")
            else:
                with st.spinner("Generating answer..."):
                    if model == "local":
                        answer = _local_helper(prompt)
                    elif model == "knowledge":
                        # Query the local file-indexed KB (build it if missing)
                        idx = ai_kb._load_index()
                        if not idx:
                            ok, msg = ai_kb.build_index()
                            st.info(msg)
                        results = ai_kb.query_kb(prompt, top_k=6)
                        if not results:
                            answer = "No relevant document snippets found in the KB. Try a different query or enable OpenAI integration."
                        else:
                            pieces = []
                            for r in results:
                                pieces.append(f"Source: {r['path']}\n---\n{r['snippet'][:1200]}\n")
                            answer = "\n\n".join(pieces)
                            # display highlighted snippets
                            st.markdown("**Top KB snippets:**")
                            for r in results:
                                st.markdown(f"**{r['path']}**", unsafe_allow_html=True)
                                st.markdown(r.get('html', r['snippet'])[:2000], unsafe_allow_html=True)
                            if st.button("Summarize KB results (OpenAI)"):
                                summ_prompt = "Summarize the following snippets and provide actionable recommendations:\n\n" + "\n\n".join(pieces)
                                summary = _call_openai(summ_prompt, model="gpt-3.5-turbo")
                                st.markdown("**Summary (OpenAI):**")
                                st.info(summary)
                    else:
                        # parse model token like openai:NAME
                        if model.startswith("openai:"):
                            _, m = model.split(":", 1)
                            answer = _call_openai(prompt, model=m)
                        else:
                            answer = _call_openai(prompt)

                st.markdown("**Assistant response:**")
                st.info(answer)

    st.markdown("---")
    st.markdown("**Tips:** Use concise prompts like 'How to enable mTLS' or 'Explain trust scoring' to get focused responses.")
    st.markdown("---")
    if st.button("(Re)build KB index now"):
        with st.spinner("Building KB index (this may take a moment)..."):
            ok, msg = ai_kb.build_index()
            if ok:
                st.success(msg)
            else:
                st.error(msg)
