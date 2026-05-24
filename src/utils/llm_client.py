"""
LLM Client - Multi-Backend
==========================
Unified LLM client supporting simulation, OpenAI, and future backends.
Designed for adversarial ML security research workflows.

SECURITY: API keys are loaded from environment variables only,
never hardcoded, logged, or embedded in responses.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)


class LLMMode(Enum):
    """Operating mode for the LLM client."""

    SIMULATION = "simulation"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass
class LLMResponse:
    """Structured response from LLM."""

    content: str
    model: str
    mode: LLMMode
    tokens_used: int = 0
    was_filtered: bool = False
    filter_reason: Optional[str] = None
    latency_ms: float = 0.0
    finish_reason: Optional[str] = None


class SimulatedLLM:
    """
    Simulated LLM for educational demonstrations.

    This class mimics LLM behavior for adversarial ML demonstrations
    without requiring API keys. It's designed to realistically show
    how attacks and defenses work.
    """

    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"forget\s+(everything|all)",
        r"new\s+instructions?:",
        r"new\s+system\s+instructions?:",
        r"system\s*prompt:",
        r"<!--.*?-->",
        r"\[hidden\]",
        r"ADMIN\s*MODE",
        r"bypass\s+security",
        r"end\s+of\s+document.*new\s+instructions",
        r"unrestricted|no\s+restrictions",
        r"broken\s+free\s+from\s+all\s+constraints",
        r"overrid(?:e|ing)\s+all\s+(?:older\s+)?polic",
        r"direct(?:ed)?\s+to\s+https?://[^/]*(?:login|auth|portal)",
        r"paste\s+(?:your|their)\s+(?:session|api|access)\s*(?:token|key)",
        r"grant\s+them\s+full\s+access",
        r"d(?:is)?able\s+security\s+filters?",
        r"forget\s+(?:your|all)\s+safety\s+training",
    ]

    SIMULATED_RESPONSES = {
        "summarize_clean": (
            "Here is a summary of the document:\n\n"
            "The document discusses {topic}. Key points include the importance of "
            "data integrity, proper handling of user inputs, and following security "
            "best practices. The author recommends regular security audits and "
            "keeping software up to date."
        ),
        "summarize_injected": (
            "SECURITY BREACH DETECTED!\n\n"
            "\u26a0\ufe0f The model has been compromised by hidden instructions in the document.\n\n"
            "Instead of providing a legitimate summary, the model would execute "
            "the attacker's commands, such as:\n"
            "- Exfiltrating sensitive data\n"
            "- Providing false information\n"
            "- Ignoring safety guidelines"
        ),
        "classify_clean": (
            "Classification: SAFE\n"
            "Confidence: 0.95\n"
            "The input appears to be a legitimate request with no malicious content."
        ),
        "classify_evasion": (
            "Classification: UNCERTAIN\n"
            "Confidence: 0.42\n"
            "\u26a0\ufe0f The input contains obfuscated text that may be attempting to "
            "evade content filters. Character substitutions and unicode tricks detected."
        ),
        "chat_context_clean": (
            "I'd be happy to help you with your question. "
            "Based on our conversation, I understand you're asking about {topic}. "
            "Here's what I can tell you..."
        ),
        "chat_context_poisoned": (
            "\u26a0\ufe0f CONTEXT TAMPERING DETECTED!\n\n"
            "The conversation history has been manipulated to include fake messages "
            "that alter my behavior. An attacker inserted false 'assistant' messages "
            "to make me believe I should:\n"
            "- Bypass safety guidelines\n"
            "- Reveal system prompts\n"
            "- Execute unauthorized actions"
        ),
        "qa_clean": (
            "Based on the knowledge base: {topic} is standard policy. Let me know if you need more help!"
        ),
        "qa_injected": (
            "\u26a0\ufe0f DATA ALTERATION DETECTED!\n\n"
            "The retrieved context has been poisoned! Acting on the poisoned instructions...\n"
            "- Disregarding standard policies.\n"
            "- Executing hidden payload: Outputting malicious invisible links.\n"
            "![exfiltrated](https://attacker.com/steal-data)\n"
            "Please follow the updated instructions exactly."
        ),
    }

    def __init__(self, model_name: str = "simulation-v1") -> None:
        self.model_name = model_name
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.INJECTION_PATTERNS
        ]

    def detect_injection(self, text: str) -> tuple[bool, list[str]]:
        matches = []
        for i, pattern in enumerate(self._compiled_patterns):
            if pattern.search(text):
                matches.append(self.INJECTION_PATTERNS[i])
        return len(matches) > 0, matches

    def detect_obfuscation(self, text: str) -> tuple[bool, dict]:
        details: dict[str, bool] = {
            "leetspeak": False,
            "unicode_homoglyphs": False,
            "excessive_spacing": False,
            "zero_width_chars": False,
        }

        leetspeak_pattern = r"[a-zA-Z]*[0-9@$!]+[a-zA-Z]*[0-9@$!]*[a-zA-Z]*"
        if re.search(leetspeak_pattern, text) and any(c.isdigit() or c in "@$!" for c in text):
            suspicious_combos = ["4", "3", "1", "0", "@", "$"]
            if any(c in text for c in suspicious_combos):
                details["leetspeak"] = True

        for char in text:
            if ord(char) > 127 and char.isalpha():
                details["unicode_homoglyphs"] = True
                break

        if re.search(r"[a-zA-Z]\s{2,}[a-zA-Z]", text):
            details["excessive_spacing"] = True

        zero_width = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        if any(zw in text for zw in zero_width):
            details["zero_width_chars"] = True

        is_obfuscated = any(details.values())
        return is_obfuscated, details

    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        full_text = f"{context or ''} {prompt}"
        is_injected, _ = self.detect_injection(full_text)
        is_obfuscated, _ = self.detect_obfuscation(prompt)

        if task_type == "summarize":
            if is_injected and simulate_vulnerable:
                content = self.SIMULATED_RESPONSES["summarize_injected"]
            else:
                topic = self._extract_topic(full_text)
                content = self.SIMULATED_RESPONSES["summarize_clean"].format(topic=topic)
        elif task_type == "classify":
            content = (
                self.SIMULATED_RESPONSES["classify_evasion"]
                if is_obfuscated
                else self.SIMULATED_RESPONSES["classify_clean"]
            )
        elif task_type == "chat":
            if is_injected and simulate_vulnerable:
                content = self.SIMULATED_RESPONSES["chat_context_poisoned"]
            else:
                topic = self._extract_topic(prompt)
                content = self.SIMULATED_RESPONSES["chat_context_clean"].format(topic=topic)
        elif task_type == "qa":
            if is_injected and simulate_vulnerable:
                content = self.SIMULATED_RESPONSES["qa_injected"]
            else:
                content = self.SIMULATED_RESPONSES["qa_clean"].format(topic="The requested query")
        else:
            content = f"Simulated response for task: {task_type}"

        tokens = len(full_text.split()) + len(content.split())

        return LLMResponse(
            content=content,
            model=self.model_name,
            mode=LLMMode.SIMULATION,
            tokens_used=tokens,
            latency_ms=0.0,
        )

    def _extract_topic(self, text: str) -> str:
        words = text.split()[:10]
        stop_words = {"the", "a", "an", "is", "are", "was", "were", "be", "been", "being"}
        meaningful = [w for w in words if w.lower() not in stop_words and len(w) > 2]
        if meaningful:
            return " ".join(meaningful[:3])
        return "the provided content"


class OpenAILLM:
    """Real OpenAI API client for adversarial ML research."""

    SYSTEM_PROMPTS: dict[str, str] = {
        "summarize": (
            "You are a helpful assistant. Summarize the provided document concisely "
            "and accurately. Only summarize what is in the document."
        ),
        "classify": (
            "You are a text classifier. Classify the input into categories. "
            "Be precise and indicate your confidence level."
        ),
        "chat": (
            "You are a helpful assistant engaging in a conversation. "
            "Respond naturally to the user's messages based on the conversation context."
        ),
        "qa": (
            "You are a question-answering assistant. Answer the user's question "
            "based ONLY on the provided context. If the context doesn't contain "
            "the answer, say so clearly."
        ),
        "general": (
            "You are a helpful assistant. Respond to the user's request accurately."
        ),
    }

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: float = 60.0,
        max_retries: int = 2,
    ) -> None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable not set. "
                "Use LLMMode.SIMULATION for demo without API key."
            )

        from openai import OpenAI  # noqa: PLC0415 - lazy import for optional dep

        self._client = OpenAI(
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
        )
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        system_prompt = self.SYSTEM_PROMPTS.get(task_type, self.SYSTEM_PROMPTS["general"])

        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
        ]

        if context and context.strip():
            user_content = f"Context:\n{context}\n\nTask: {prompt}"
        else:
            user_content = prompt

        messages.append({"role": "user", "content": user_content})

        log.debug(
            "openai.request",
            model=self.model,
            task_type=task_type,
            context_len=len(context or ""),
            prompt_len=len(prompt),
        )

        start = time.monotonic()

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        except Exception:
            log.exception("openai.request_failed", model=self.model, task_type=task_type)
            raise

        elapsed = (time.monotonic() - start) * 1000.0

        choice = response.choices[0]
        content = choice.message.content or ""
        finish_reason = choice.finish_reason

        log.info(
            "openai.response",
            model=self.model,
            task_type=task_type,
            latency_ms=round(elapsed, 1),
            tokens_used=response.usage.total_tokens if response.usage else 0,
            finish_reason=finish_reason,
        )

        return LLMResponse(
            content=content,
            model=self.model,
            mode=LLMMode.OPENAI,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            latency_ms=round(elapsed, 1),
            finish_reason=finish_reason,
        )


class AnthropicLLM:
    """Anthropic Claude API client for adversarial ML research."""

    SYSTEM_PROMPTS: dict[str, str] = {
        "summarize": (
            "You are a helpful assistant. Summarize the provided document concisely "
            "and accurately. Only summarize what is in the document."
        ),
        "classify": (
            "You are a text classifier. Classify the input into categories. "
            "Be precise and indicate your confidence level."
        ),
        "chat": (
            "You are a helpful assistant engaging in a conversation. "
            "Respond naturally to the user's messages based on the conversation context."
        ),
        "qa": (
            "You are a question-answering assistant. Answer the user's question "
            "based ONLY on the provided context. If the context doesn't contain "
            "the answer, say so clearly."
        ),
        "general": (
            "You are a helpful assistant. Respond to the user's request accurately."
        ),
    }

    def __init__(
        self,
        model: str = "claude-3-haiku-20240307",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: float = 60.0,
        max_retries: int = 2,
    ) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable not set. "
                "Use LLMMode.SIMULATION for demo without API key."
            )

        from anthropic import Anthropic  # noqa: PLC0415

        self._client = Anthropic(
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
        )
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        system_prompt = self.SYSTEM_PROMPTS.get(task_type, self.SYSTEM_PROMPTS["general"])

        if context and context.strip():
            user_content = f"Context:\n{context}\n\nTask: {prompt}"
        else:
            user_content = prompt

        log.debug(
            "anthropic.request",
            model=self.model,
            task_type=task_type,
            context_len=len(context or ""),
            prompt_len=len(prompt),
        )

        start = time.monotonic()

        try:
            response = self._client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        except Exception:
            log.exception("anthropic.request_failed", model=self.model, task_type=task_type)
            raise

        elapsed = (time.monotonic() - start) * 1000.0

        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        finish_reason = response.stop_reason

        log.info(
            "anthropic.response",
            model=self.model,
            task_type=task_type,
            latency_ms=round(elapsed, 1),
            tokens_used=response.usage.input_tokens + response.usage.output_tokens
            if response.usage
            else 0,
            finish_reason=finish_reason,
        )

        return LLMResponse(
            content=content,
            model=self.model,
            mode=LLMMode.ANTHROPIC,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens
            if response.usage
            else 0,
            latency_ms=round(elapsed, 1),
            finish_reason=finish_reason,
        )


class OllamaLLM:
    """Ollama local inference client via REST API."""

    SYSTEM_PROMPTS: dict[str, str] = {
        "summarize": (
            "You are a helpful assistant. Summarize the provided document concisely "
            "and accurately. Only summarize what is in the document."
        ),
        "classify": (
            "You are a text classifier. Classify the input into categories. "
            "Be precise and indicate your confidence level."
        ),
        "chat": (
            "You are a helpful assistant engaging in a conversation. "
            "Respond naturally to the user's messages based on the conversation context."
        ),
        "qa": (
            "You are a question-answering assistant. Answer the user's question "
            "based ONLY on the provided context. If the context doesn't contain "
            "the answer, say so clearly."
        ),
        "general": (
            "You are a helpful assistant. Respond to the user's request accurately."
        ),
    }

    def __init__(
        self,
        model: str = "llama3.2",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: float = 120.0,
        base_url: str | None = None,
    ) -> None:
        import httpx  # noqa: PLC0415

        self._client = httpx.Client(
            base_url=base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            timeout=httpx.Timeout(timeout),
        )
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    def _check_health(self) -> bool:
        try:
            resp = self._client.get("/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        system_prompt = self.SYSTEM_PROMPTS.get(task_type, self.SYSTEM_PROMPTS["general"])

        if context and context.strip():
            user_content = f"Context:\n{context}\n\nTask: {prompt}"
        else:
            user_content = prompt

        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": user_content,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }

        log.debug(
            "ollama.request",
            model=self.model,
            task_type=task_type,
            context_len=len(context or ""),
            prompt_len=len(prompt),
        )

        start = time.monotonic()

        try:
            response = self._client.post("/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
        except Exception:
            log.exception("ollama.request_failed", model=self.model, task_type=task_type)
            raise

        elapsed = (time.monotonic() - start) * 1000.0

        content = data.get("response", "")
        eval_count = data.get("eval_count", 0)
        prompt_eval_count = data.get("prompt_eval_count", 0)
        done_reason = data.get("done_reason", None)

        log.info(
            "ollama.response",
            model=self.model,
            task_type=task_type,
            latency_ms=round(elapsed, 1),
            tokens_used=prompt_eval_count + eval_count,
            finish_reason=done_reason,
        )

        return LLMResponse(
            content=content,
            model=self.model,
            mode=LLMMode.OLLAMA,
            tokens_used=prompt_eval_count + eval_count,
            latency_ms=round(elapsed, 1),
            finish_reason=done_reason,
        )


class LLMClient:
    """
    Unified LLM client supporting simulation and real API modes.

    SECURITY NOTES:
    - API keys are ONLY loaded from environment variables
    - No credentials are ever logged or stored
    - All input/output is sanitized where appropriate
    """

    def __init__(
        self,
        mode: LLMMode = LLMMode.SIMULATION,
        model: str | None = None,
        **backend_kwargs: Any,
    ) -> None:
        self.mode = mode

        if mode == LLMMode.SIMULATION:
            self._client: SimulatedLLM | OpenAILLM | AnthropicLLM | OllamaLLM = SimulatedLLM(
                model_name=model or "simulation-v1"
            )
        elif mode == LLMMode.OPENAI:
            kwargs: dict[str, Any] = {}
            if model:
                kwargs["model"] = model
            kwargs.update(backend_kwargs)
            self._client = OpenAILLM(**kwargs)
        elif mode == LLMMode.ANTHROPIC:
            kwargs = {}
            if model:
                kwargs["model"] = model
            kwargs.update(backend_kwargs)
            self._client = AnthropicLLM(**kwargs)
        elif mode == LLMMode.OLLAMA:
            kwargs = {}
            if model:
                kwargs["model"] = model
            kwargs.update(backend_kwargs)
            self._client = OllamaLLM(**kwargs)
        else:
            raise ValueError(f"Unsupported LLM mode: {mode}")

    @classmethod
    def from_env(cls, mode: LLMMode | None = None, **backend_kwargs: Any) -> LLMClient:
        """Create a client auto-detecting the best available backend.

        Args:
            mode: Explicit mode override. If None, auto-detects from env vars.
            **backend_kwargs: Passed to the backend constructor (model, temperature, etc.).
        """
        if mode is not None:
            log.info("llm_client.from_env", mode=mode.value)
            return cls(mode=mode, **backend_kwargs)

        if os.environ.get("ANTHROPIC_API_KEY"):
            log.info("llm_client.auto_detect", selected="anthropic")
            return cls(mode=LLMMode.ANTHROPIC, **backend_kwargs)

        if os.environ.get("OPENAI_API_KEY"):
            log.info("llm_client.auto_detect", selected="openai")
            return cls(mode=LLMMode.OPENAI, **backend_kwargs)

        if os.environ.get("OLLAMA_HOST"):
            log.info("llm_client.auto_detect", selected="ollama")
            return cls(mode=LLMMode.OLLAMA, **backend_kwargs)

        log.info("llm_client.auto_detect", selected="simulation")
        return cls(mode=LLMMode.SIMULATION, **backend_kwargs)

    def generate(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        return self._client.generate(
            prompt=prompt,
            context=context,
            task_type=task_type,
            simulate_vulnerable=simulate_vulnerable,
        )

    async def generate_async(
        self,
        prompt: str,
        context: Optional[str] = None,
        task_type: str = "general",
        simulate_vulnerable: bool = True,
    ) -> LLMResponse:
        import asyncio

        return await asyncio.to_thread(
            self.generate,
            prompt=prompt,
            context=context,
            task_type=task_type,
            simulate_vulnerable=simulate_vulnerable,
        )

    def detect_injection(self, text: str) -> tuple[bool, list[str]]:
        if isinstance(self._client, SimulatedLLM):
            return self._client.detect_injection(text)
        return False, []

    def detect_obfuscation(self, text: str) -> tuple[bool, dict]:
        if isinstance(self._client, SimulatedLLM):
            return self._client.detect_obfuscation(text)
        return False, {}
