"""Typed configuration loader using OmegaConf."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from omegaconf import OmegaConf


@dataclass
class LLMBackendConfig:
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout: float = 60.0
    max_retries: int = 2


@dataclass
class LLMConfig:
    default_mode: str = "simulation"
    simulation: LLMBackendConfig = field(default_factory=lambda: LLMBackendConfig(model="simulation-v1"))
    openai: LLMBackendConfig = field(default_factory=LLMBackendConfig)
    anthropic: LLMBackendConfig = field(default_factory=lambda: LLMBackendConfig(model="claude-3-haiku-20240307"))
    ollama: LLMBackendConfig = field(default_factory=lambda: LLMBackendConfig(model="llama3.2", timeout=120.0))


@dataclass
class ContextFilterConfig:
    sensitivity: float = 0.7
    block_on_detection: bool = True


@dataclass
class IsolationConfig:
    level: str = "session"
    redaction_level: str = "basic"
    max_session_age_minutes: int = 30
    max_context_length: int = 50


@dataclass
class DefenseConfig:
    context_filter: ContextFilterConfig = field(default_factory=ContextFilterConfig)
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    anomaly_scorer: AnomalyConfig = field(default_factory=lambda: AnomalyConfig())


@dataclass
class AnomalyConfig:
    entropy_threshold: float = 4.2
    symbol_density_threshold: float = 0.25
    unicode_ratio_threshold: float = 0.15
    repetition_threshold: float = 0.3
    trigram_perplexity_threshold: float = 400.0
    anomaly_threshold: float = 0.6


@dataclass
class UncertaintyConfig:
    human_review_threshold: float = 0.5
    aggregation: str = "weighted_mean"


@dataclass
class EvalConfig:
    default_suite: str = "baseline"
    max_concurrency: int = 10
    simulate_vulnerable: bool = True


@dataclass
class ScanConfig:
    default_task: str = "summarize"
    simulate_vulnerable: bool = False


@dataclass
class AppConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    defense: DefenseConfig = field(default_factory=DefenseConfig)
    uncertainty: UncertaintyConfig = field(default_factory=UncertaintyConfig)
    eval: EvalConfig = field(default_factory=EvalConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load application configuration from YAML file.

    Args:
        config_path: Path to config YAML file. Defaults to configs/config.yaml.

    Returns:
        AppConfig with all settings resolved.
    """
    if config_path is None:
        config_path = Path("configs/config.yaml")

    raw = OmegaConf.load(config_path)
    schema = OmegaConf.structured(AppConfig)
    merged = OmegaConf.merge(schema, raw)
    return cast(AppConfig, OmegaConf.to_object(merged))


def get_default_config() -> AppConfig:
    """Return default configuration without loading a file."""
    schema = OmegaConf.structured(AppConfig)
    return cast(AppConfig, OmegaConf.to_object(schema))
