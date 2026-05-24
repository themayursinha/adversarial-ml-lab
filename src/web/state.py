"""Centralized application state for web and CLI entrypoints."""

from __future__ import annotations

from dataclasses import dataclass

from src.attacks.context_tampering import ContextTamperingAttack
from src.attacks.inference_evasion import InferenceEvasionAttack
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.rag_poisoning import RagPoisoningAttack
from src.config.loader import AppConfig, get_default_config
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
    config: AppConfig


def create_app_state(config: AppConfig | None = None) -> AppState:
    """Build app dependencies from configuration.

    Auto-detects the best available LLM backend from environment variables.
    Falls back to simulation mode if no API keys are configured.
    """
    cfg = config or get_default_config()

    llm_client = LLMClient.from_env()
    context_filter = ContextAwareFilter(
        sensitivity=cfg.defense.context_filter.sensitivity,
        block_on_detection=cfg.defense.context_filter.block_on_detection,
    )
    uncertainty_scorer = EnsembleUncertaintyScorer(
        human_review_threshold=cfg.uncertainty.human_review_threshold,
        aggregation=cfg.uncertainty.aggregation,
    )

    isolation_level = IsolationLevel[cfg.defense.isolation.level.upper()]
    redaction_level = RedactionLevel[cfg.defense.isolation.redaction_level.upper()]

    return AppState(
        llm_client=llm_client,
        injection_attack=PromptInjectionAttack(),
        tampering_attack=ContextTamperingAttack(),
        evasion_attack=InferenceEvasionAttack(),
        rag_poisoning=RagPoisoningAttack(),
        context_filter=context_filter,
        isolation_server=ContextIsolationServer(
            isolation_level=isolation_level,
            redaction_level=redaction_level,
            max_session_age_minutes=cfg.defense.isolation.max_session_age_minutes,
            max_context_length=cfg.defense.isolation.max_context_length,
        ),
        uncertainty_scorer=uncertainty_scorer,
        defense_pipeline=DefensePipeline(
            context_filter=context_filter,
            uncertainty_scorer=uncertainty_scorer,
        ),
        config=cfg,
    )


APP_STATE = create_app_state()
