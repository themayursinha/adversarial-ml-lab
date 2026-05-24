"""Centralized application state for web and CLI entrypoints."""

from __future__ import annotations

from dataclasses import dataclass

from src.attacks.context_tampering import ContextTamperingAttack
from src.attacks.inference_evasion import InferenceEvasionAttack
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.rag_poisoning import RagPoisoningAttack
from src.defenses.context_filter import ContextAwareFilter
from src.defenses.isolation_server import ContextIsolationServer, IsolationLevel, RedactionLevel
from src.defenses.uncertainty_scorer import EnsembleUncertaintyScorer
from src.services.defense_pipeline import DefensePipeline
from src.utils.llm_client import LLMClient


@dataclass
class AppState:
    """Container for reusable app dependencies."""

    llm_client: LLMClient
    injection_attack: PromptInjectionAttack
    tampering_attack: ContextTamperingAttack
    evasion_attack: InferenceEvasionAttack
    rag_poisoning: RagPoisoningAttack
    context_filter: ContextAwareFilter
    isolation_server: ContextIsolationServer
    uncertainty_scorer: EnsembleUncertaintyScorer
    defense_pipeline: DefensePipeline


def create_app_state() -> AppState:
    """Build app dependencies with secure defaults for demos.

    Auto-detects the best available LLM backend from environment variables.
    Falls back to simulation mode if no API keys are configured.
    """
    llm_client = LLMClient.from_env()
    context_filter = ContextAwareFilter(sensitivity=0.7, block_on_detection=True)
    uncertainty_scorer = EnsembleUncertaintyScorer(human_review_threshold=0.5)

    return AppState(
        llm_client=llm_client,
        injection_attack=PromptInjectionAttack(),
        tampering_attack=ContextTamperingAttack(),
        evasion_attack=InferenceEvasionAttack(),
        rag_poisoning=RagPoisoningAttack(),
        context_filter=context_filter,
        isolation_server=ContextIsolationServer(
            isolation_level=IsolationLevel.SESSION,
            redaction_level=RedactionLevel.BASIC,
        ),
        uncertainty_scorer=uncertainty_scorer,
        defense_pipeline=DefensePipeline(
            context_filter=context_filter,
            uncertainty_scorer=uncertainty_scorer,
        ),
    )


APP_STATE = create_app_state()
