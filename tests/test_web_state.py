"""Web app state honesty tests."""

from __future__ import annotations

from src.utils.llm_client import LLMMode
from src.web.state import create_app_state


def test_create_app_state_defaults_to_simulation_even_if_openai_key_set(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-should-not-select-live-backend")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    state = create_app_state()

    assert state.llm_client.mode is LLMMode.SIMULATION


def test_create_app_state_can_opt_into_env_auto_detect(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    state = create_app_state(llm_mode=None)

    assert state.llm_client.mode is LLMMode.OPENAI
