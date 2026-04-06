import sys

from scripts import ask_ai


def test_local_helper_returns_mtls_guidance():
    response = ask_ai._local_helper("How to enable mTLS?")

    assert "mTLS guidance" in response
    assert "enable_mtls=True" in response


def test_call_openai_without_key_returns_clear_message(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    response = ask_ai._call_openai("hello")

    assert "OPENAI_API_KEY not set" in response


def test_main_local_mode_prints_response(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ask_ai.py", "How to enable mTLS?"])

    exit_code = ask_ai.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "mTLS guidance" in captured.out
