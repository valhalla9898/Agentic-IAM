"""Simple command-line entry point for the Agentic-IAM AI assistant."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _call_openai(prompt: str, model: str = "gpt-3.5-turbo") -> str:
    try:
        import openai
    except Exception:
        return "OpenAI SDK not installed. Install `openai` and set OPENAI_API_KEY to use cloud mode."

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "OPENAI_API_KEY not set. Provide the key to use cloud mode."

    openai.api_key = api_key
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        return f"OpenAI request failed: {exc}"


def _local_helper(prompt: str) -> str:
    prompt_lower = prompt.lower()
    if "login" in prompt_lower or "auth" in prompt_lower:
        return (
            "Login help:\n- Use the demo credentials on the login page (admin/operator/user).\n"
            "- If you need to create a user, go to User Management (Admin).\n"
            "- For API login, POST /api/auth/login with username/password."
        )
    if "mtls" in prompt_lower or "certificate" in prompt_lower:
        return (
            "mTLS guidance:\n- Enable mTLS in config/settings.py by setting enable_mtls=True.\n"
            "- Configure your TLS terminator (NGINX/Ingress) to forward x-ssl-client-verify and x-forwarded-client-cert."
        )
    if "secrets" in prompt_lower or "vault" in prompt_lower:
        return (
            "Secrets guidance:\n- Use the SecretManager scaffold at secrets/key_vault.py.\n"
            "- Set AZURE_KEYVAULT_URL or put env vars like SECRET_KEY/ENCRYPTION_KEY."
        )
    return "I can help with: login, mTLS, secrets, Playwright tests, and basic usage. Ask about one of those topics."


def _knowledge_helper(prompt: str) -> str:
    from dashboard.components import ai_kb

    ok, msg = ai_kb.build_index()
    if not ok:
        return msg

    index = ai_kb._load_index()
    if not index:
        return "Knowledge index could not be loaded after build."

    results = ai_kb.query_kb(prompt, top_k=6)
    if not results:
        return "No relevant document snippets found in the KB. Try a different query or use --model local."

    pieces = []
    for result in results:
        pieces.append(f"Source: {result['path']}\n---\n{result['snippet'][:1200]}")
    return "\n\n".join(pieces)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ask the Agentic-IAM assistant a question.")
    parser.add_argument("prompt", help="Question to send to the assistant")
    parser.add_argument(
        "--model",
        default="local",
        choices=["local", "knowledge", "openai:gpt-3.5-turbo"],
        help="Assistant mode to use",
    )
    args = parser.parse_args()

    if args.model == "local":
        answer = _local_helper(args.prompt)
    elif args.model == "knowledge":
        answer = _knowledge_helper(args.prompt)
    else:
        _, model_name = args.model.split(":", 1)
        answer = _call_openai(args.prompt, model=model_name)

    print(answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())