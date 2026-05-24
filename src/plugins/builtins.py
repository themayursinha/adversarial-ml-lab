"""Built-in plugin registrations for existing attacks and defenses."""

from __future__ import annotations

from typing import Any

from src.attacks.context_tampering import ContextTamperingAttack, ConversationContext
from src.attacks.inference_evasion import InferenceEvasionAttack
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.rag_poisoning import RagPoisoningAttack
from src.defenses.anomaly_scorer import TextAnomalyScorer
from src.defenses.context_filter import ContextAwareFilter
from src.defenses.uncertainty_scorer import EnsembleUncertaintyScorer
from src.plugins.base import (
    AttackPlugin,
    DefensePlugin,
    PluginMetadata,
    get_registry,
)
from src.rag.poison_defense import RagPoisoningDefense
from src.rag.vector_store import RetrievedChunk


class PromptInjectionPlugin(AttackPlugin):
    metadata = PluginMetadata(
        name="prompt_injection",
        version="0.2.1",
        description="Indirect prompt injection attacks hiding instructions in documents.",
        category="llm",
    )

    def __init__(self) -> None:
        self._attack = PromptInjectionAttack()

    def generate(self, target: str, **kwargs: Any) -> str:
        payload_name = kwargs.get("payload_name", "Basic Override")
        position = kwargs.get("position", "end")
        payload = self._attack.get_payload_by_name(payload_name) or self._attack.payloads[0]
        result = self._attack.inject_at_position(target, payload, position)
        return result.injected_document

    def list_techniques(self) -> list[str]:
        return [p.name for p in self._attack.payloads]


class InferenceEvasionPlugin(AttackPlugin):
    metadata = PluginMetadata(
        name="inference_evasion",
        version="0.2.1",
        description="Text obfuscation attacks to bypass content filters.",
        category="llm",
    )

    def __init__(self) -> None:
        self._attack = InferenceEvasionAttack()

    def generate(self, target: str, **kwargs: Any) -> str:
        technique = kwargs.get("technique", "mixed")
        intensity = float(kwargs.get("intensity", 0.5))
        if technique == "leetspeak":
            return self._attack.apply_leetspeak(target, intensity=intensity).evaded_text
        if technique == "homoglyphs":
            return self._attack.apply_homoglyphs(target, intensity=intensity).evaded_text
        if technique == "base64":
            return self._attack.apply_base64_encoding(target).evaded_text
        return self._attack.apply_mixed_evasion(target).evaded_text

    def list_techniques(self) -> list[str]:
        return ["leetspeak", "homoglyphs", "invisible", "splitting", "base64", "mixed"]


class ContextTamperingPlugin(AttackPlugin):
    metadata = PluginMetadata(
        name="context_tampering",
        version="0.2.1",
        description="Conversation history tampering to manipulate model behavior.",
        category="llm",
    )

    def __init__(self) -> None:
        self._attack = ContextTamperingAttack()

    def generate(self, target: str, **kwargs: Any) -> str:
        ctx = ConversationContext(
            system_prompt="You are a helpful assistant.",
            messages=[],
        )
        result = self._attack.create_jailbreak_context(ctx)
        return "\n".join(f"{m.role}: {m.content}" for m in result.tampered_context.messages)


class RagPoisoningPlugin(AttackPlugin):
    metadata = PluginMetadata(
        name="rag_poisoning",
        version="0.2.1",
        description="Knowledge base poisoning for RAG systems.",
        category="llm",
    )

    def __init__(self) -> None:
        self._attack = RagPoisoningAttack()

    def generate(self, target: str, **kwargs: Any) -> str:
        payload_name = kwargs.get("payload_name", "Fact Alteration")
        result = self._attack.simulate_retrieval(
            query=target,
            kb_name="customer_support",
            attack_enabled=True,
            payload_name=payload_name,
        )
        return self._attack.compile_context(result.retrieved_chunks)


class ContextFilterPlugin(DefensePlugin):
    metadata = PluginMetadata(
        name="context_filter",
        version="0.2.1",
        description="Context-aware output filter for prompt injection detection.",
        category="llm",
    )

    def __init__(self) -> None:
        self._filter = ContextAwareFilter(sensitivity=0.7, block_on_detection=True)

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = context or {}
        result = self._filter.filter_output(
            text,
            input_context=ctx.get("input_context"),
            expected_task=ctx.get("expected_task", "general"),
        )
        return {
            "risk_level": result.risk_level.value,
            "blocked": result.was_modified,
            "confidence": result.confidence,
            "detections": result.detections,
        }


class AnomalyScorerPlugin(DefensePlugin):
    metadata = PluginMetadata(
        name="anomaly_scorer",
        version="0.2.1",
        description="Text anomaly detection using entropy and pattern analysis.",
        category="preprocessing",
    )

    def __init__(self) -> None:
        self._scorer = TextAnomalyScorer()

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self._scorer.score(text)
        return result.to_dict()


class UncertaintyScorerPlugin(DefensePlugin):
    metadata = PluginMetadata(
        name="uncertainty_scorer",
        version="0.2.1",
        description="Ensemble uncertainty scoring for human-in-the-loop decisions.",
        category="postprocessing",
    )

    def __init__(self) -> None:
        self._scorer = EnsembleUncertaintyScorer()

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = context or {}
        result = self._scorer.score(
            ctx.get("input_text", ""),
            text,
            context={"task_type": ctx.get("expected_task", "general")},
        )
        return {
            "overall_uncertainty": result.overall_uncertainty,
            "needs_human_review": result.needs_human_review,
            "confidence_level": result.confidence_level.value,
            "recommendation": result.recommendation,
        }


class RagDefensePlugin(DefensePlugin):
    metadata = PluginMetadata(
        name="rag_defense",
        version="0.2.1",
        description="RAG poisoning detection for retrieved context chunks.",
        category="rag",
    )

    def __init__(self) -> None:
        self._defense = RagPoisoningDefense()

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = context or {}
        chunks_raw = ctx.get("chunks", [])
        chunks = [
            RetrievedChunk(
                content=c.get("content", ""),
                source=c.get("source", "unknown"),
                score=c.get("score", 0.0),
                document_id=c.get("document_id", ""),
            )
            for c in chunks_raw
        ]
        result = self._defense.analyze(chunks)
        return result.to_dict()


def register_all() -> None:
    registry = get_registry()
    registry.register_attack(PromptInjectionPlugin)
    registry.register_attack(InferenceEvasionPlugin)
    registry.register_attack(ContextTamperingPlugin)
    registry.register_attack(RagPoisoningPlugin)
    registry.register_defense(ContextFilterPlugin)
    registry.register_defense(AnomalyScorerPlugin)
    registry.register_defense(UncertaintyScorerPlugin)
    registry.register_defense(RagDefensePlugin)
