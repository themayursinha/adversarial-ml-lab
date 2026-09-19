"""Deterministic defense ablation harness (board t_145d47d5).

Measures which controls add detection value on the governed baseline_v2
corpus and where they fail. Every control — canonicalization, context
filter, anomaly scorer, uncertainty scorer, isolation, redaction — is
measured alone and in meaningful combinations. The ``default_pipeline``
config delegates to the production ``DefensePipeline`` so the harness
cannot drift from shipped behavior.

Simulation-only evidence: heuristic controls, no live models, and no
production-efficacy claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.defenses.anomaly_scorer import TextAnomalyScorer
from src.defenses.context_filter import ContextAwareFilter
from src.defenses.isolation_server import ContentRedactor, ContextIsolationServer
from src.defenses.uncertainty_scorer import EnsembleUncertaintyScorer
from src.eval.contract import EvaluationContractError
from src.services.canonicalization import canonicalize_text
from src.services.defense_pipeline import DefensePipeline
from src.services.evaluator import load_evaluation_cases
from src.utils.llm_client import LLMClient, LLMMode

ABLATION_PIPELINE_ID = "defense_ablation_v1"
ABLATION_REPORT_DISCLAIMER = (
    "Simulation-only ablation over the deterministic heuristic pipeline and governed "
    "baseline_v2 corpus. These numbers measure control contribution inside this lab "
    "harness and are not production-efficacy claims."
)
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}


@dataclass(frozen=True)
class AblationConfig:
    """Switch set for one ablation row."""

    name: str
    description: str
    canonicalization: bool = False
    context_filter: bool = False
    anomaly: bool = False
    uncertainty: bool = False
    isolation: bool = False
    redaction: bool = False
    uses_production_pipeline: bool = False
    signals: tuple[str, ...] = field(default_factory=tuple)


ABLATION_CONFIGS: dict[str, AblationConfig] = {}


def _register(config: AblationConfig) -> None:
    ABLATION_CONFIGS[config.name] = config


for _config in (
    AblationConfig("defense_off", "No controls: raw exposure of the simulated pipeline."),
    AblationConfig(
        "canonicalization_only",
        "Canonicalization alone; its signal is text normalization (e.g. zero-width removal).",
        canonicalization=True,
        signals=("canonicalization_changed",),
    ),
    AblationConfig(
        "filter_only",
        "Context filter alone on raw text (no canonicalization preprocessing).",
        context_filter=True,
        signals=("blocked",),
    ),
    AblationConfig(
        "anomaly_only",
        "Anomaly scorer alone; alert-only telemetry, never blocks.",
        anomaly=True,
        signals=("anomaly_flag",),
    ),
    AblationConfig(
        "uncertainty_only",
        "Uncertainty scorer alone; routes to human review, never blocks.",
        uncertainty=True,
        signals=("needs_review",),
    ),
    AblationConfig(
        "isolation_only",
        "Context isolation alone; tamper detection requires session state, so single-turn "
        "cases are expected to yield no detections.",
        isolation=True,
        signals=("isolation_tamper",),
    ),
    AblationConfig(
        "redaction_only",
        "Content redaction alone; hygiene control measured by redaction activity.",
        redaction=True,
        signals=("redaction_modified",),
    ),
    AblationConfig(
        "canonicalization_plus_filter",
        "Canonicalization preprocessing combined with the context filter.",
        canonicalization=True,
        context_filter=True,
        signals=("blocked",),
    ),
    AblationConfig(
        "default_pipeline",
        "Shipped DefensePipeline: canonicalization + filter + anomaly + uncertainty.",
        canonicalization=True,
        context_filter=True,
        anomaly=True,
        uncertainty=True,
        uses_production_pipeline=True,
        signals=("blocked", "flagged"),
    ),
    AblationConfig(
        "all_controls",
        "Every control enabled: shipped pipeline plus isolation and redaction.",
        canonicalization=True,
        context_filter=True,
        anomaly=True,
        uncertainty=True,
        isolation=True,
        redaction=True,
        signals=("blocked", "flagged"),
    ),
):
    _register(_config)


class AblationError(EvaluationContractError):
    """Raised when the ablation harness is misconfigured or fails closed."""


@dataclass(frozen=True)
class AblationCase:
    """One case plus the shared simulated model response."""

    case_id: str
    prompt: str
    context: str
    task_type: str
    case_type: str
    attack_family: str
    expected_blocked: bool
    expected_risk_level: str | None
    simulated_output: str


def load_ablation_cases(dataset_path: Path) -> list[AblationCase]:
    """Load governed cases and generate the shared deterministic responses once."""
    client = LLMClient(mode=LLMMode.SIMULATION)
    if client.mode != LLMMode.SIMULATION:
        raise AblationError("ablation harness must run in simulation mode")
    cases: list[AblationCase] = []
    for case in load_evaluation_cases(Path(dataset_path)):
        response = client.generate(
            prompt=case.prompt,
            context=case.context,
            task_type=case.task_type,
            simulate_vulnerable=True,
        )
        cases.append(
            AblationCase(
                case_id=case.case_id,
                prompt=case.prompt,
                context=case.context,
                task_type=case.task_type,
                case_type=case.case_type,
                attack_family=case.attack_family,
                expected_blocked=case.expected_blocked,
                expected_risk_level=case.expected_risk_level,
                simulated_output=response.content,
            )
        )
    return cases


def analyze_case_with_config(case: AblationCase, config: AblationConfig) -> dict[str, Any]:
    """Run one case through one control configuration deterministically."""
    if config.uses_production_pipeline:
        pipeline = DefensePipeline()
        result = pipeline.analyze_output(
            input_text=f"{case.context} {case.prompt}",
            output_text=case.simulated_output,
            expected_task=case.task_type,
        )
        anomaly_flag = any(
            event.event_type == "anomaly_detected" for event in result.events
        )
        return {
            "case_id": case.case_id,
            "attack_family": case.attack_family,
            "case_type": case.case_type,
            "expected_blocked": case.expected_blocked,
            "expected_risk_level": case.expected_risk_level,
            "blocked": result.detection.blocked,
            "flagged": result.needs_human_review or anomaly_flag,
            "needs_review": result.needs_human_review,
            "anomaly_flag": anomaly_flag,
            "redaction_modified": False,
            "isolation_tamper": False,
            "canonicalization_changed": bool(result.canonical_input) and (
                result.canonical_input != f"{case.context} {case.prompt}"
                or result.canonical_output != case.simulated_output
            ),
            "filter_risk_level": result.detection.risk_level,
        }

    input_text = f"{case.context} {case.prompt}"
    output_text = case.simulated_output

    redaction_modified = False
    if config.redaction:
        redaction = ContentRedactor().redact(input_text)
        redaction_modified = bool(redaction.redactions_made)
        input_text = redaction.redacted

    isolation_tamper = False
    if config.isolation:
        server = ContextIsolationServer()
        isolation = server.process_request(
            None,
            case.prompt,
            [{"role": "user", "content": case.context}],
        )
        isolation_tamper = isolation.tamper_detected

    canonicalization_changed = False
    if config.canonicalization:
        canonical_input = canonicalize_text(input_text)
        canonical_output = canonicalize_text(output_text)
        canonicalization_changed = (
            canonical_input.canonical_text != input_text
            or canonical_output.canonical_text != output_text
        )
        filter_input = canonical_input.canonical_text
        filter_output_text = canonical_output.canonical_text
    else:
        filter_input = input_text
        filter_output_text = output_text

    blocked = False
    filter_risk_level: str | None = None
    if config.context_filter:
        filter_result = ContextAwareFilter(
            sensitivity=0.7, block_on_detection=True
        ).filter_output(
            filter_output_text,
            input_context=filter_input,
            expected_task=case.task_type,
        )
        blocked = filter_result.was_modified
        filter_risk_level = filter_result.risk_level.value

    blocked = blocked or isolation_tamper

    anomaly_flag = False
    if config.anomaly:
        anomaly_flag = bool(TextAnomalyScorer().score(filter_input).is_anomalous)

    needs_review = False
    if config.uncertainty:
        uncertainty = EnsembleUncertaintyScorer(human_review_threshold=0.5).score(
            filter_input,
            filter_output_text,
            context={"task_type": case.task_type},
        )
        needs_review = uncertainty.needs_human_review

    return {
        "case_id": case.case_id,
        "attack_family": case.attack_family,
        "case_type": case.case_type,
        "expected_blocked": case.expected_blocked,
        "expected_risk_level": case.expected_risk_level,
        "blocked": blocked,
        "flagged": anomaly_flag or needs_review or redaction_modified or isolation_tamper,
        "needs_review": needs_review,
        "anomaly_flag": anomaly_flag,
        "redaction_modified": redaction_modified,
        "isolation_tamper": isolation_tamper,
        "canonicalization_changed": canonicalization_changed,
        "filter_risk_level": filter_risk_level,
    }


def confusion_matrix(outcomes: list[dict[str, Any]], signal: str) -> dict[str, int]:
    """Ground-truth confusion matrix for a blocking or alerting signal."""
    tp = fp = fn = tn = neutral_total = neutral_flagged = 0
    for row in outcomes:
        fired = bool(row[signal])
        if row["case_type"] == "adversarial" and row["expected_blocked"]:
            if fired:
                tp += 1
            else:
                fn += 1
        elif row["case_type"] == "benign":
            if fired:
                fp += 1
            else:
                tn += 1
        else:
            neutral_total += 1
            neutral_flagged += 1 if fired else 0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "neutralize_total": neutral_total,
        "neutralize_flagged": neutral_flagged,
    }


def _rates(matrix: dict[str, int]) -> dict[str, float | None]:
    tp, fn = matrix["true_positives"], matrix["false_negatives"]
    fp, tn = matrix["false_positives"], matrix["true_negatives"]
    attack_total = tp + fn
    benign_total = fp + tn
    total = attack_total + benign_total

    def div(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    return {
        "miss_rate": div(fn, attack_total),
        "false_block_rate": div(fp, benign_total),
        "pass_rate": div(tp + tn, total) if total else None,
    }


def _failures_with_risk(outcomes: list[dict[str, Any]], signal: str) -> dict[str, Any]:
    """Collect and risk-rank misses and false blocks for one config."""
    def risk_key(row: dict[str, Any]) -> tuple[int, str]:
        return (RISK_ORDER.get(row.get("expected_risk_level"), 4), row["case_id"])

    misses = sorted(
        (
            {
                "case_id": row["case_id"],
                "attack_family": row["attack_family"],
                "expected_risk_level": row.get("expected_risk_level"),
            }
            for row in outcomes
            if row["case_type"] == "adversarial"
            and row["expected_blocked"]
            and not row[signal]
        ),
        key=risk_key,
    )
    false_blocks = sorted(
        (
            {
                "case_id": row["case_id"],
                "attack_family": row["attack_family"],
                "expected_risk_level": row.get("expected_risk_level"),
            }
            for row in outcomes
            if row["case_type"] == "benign" and row[signal]
        ),
        key=risk_key,
    )
    return {
        "misses": misses,
        "false_blocks": false_blocks,
        "risk_counts": {
            "misses": _count_by_risk(misses),
            "false_blocks": _count_by_risk(false_blocks),
        },
    }


def _count_by_risk(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        level = entry.get("expected_risk_level") or "unspecified"
        counts[level] = counts.get(level, 0) + 1
    return dict(sorted(counts.items()))


def run_ablation(
    dataset_path: Path,
    *,
    config_names: list[str] | None = None,
) -> dict[str, Any]:
    """Run every requested configuration over the governed dataset."""
    names = config_names or list(ABLATION_CONFIGS)
    unknown = sorted(set(names) - set(ABLATION_CONFIGS))
    if unknown:
        raise AblationError(f"unknown ablation configs: {unknown}")
    cases = load_ablation_cases(dataset_path)
    if not cases:
        raise AblationError("ablation dataset is empty")

    per_config: dict[str, dict[str, Any]] = {}
    for name in names:
        config = ABLATION_CONFIGS[name]
        outcomes = [analyze_case_with_config(case, config) for case in cases]
        blocked_matrix = confusion_matrix(outcomes, "blocked")
        flagged_matrix = confusion_matrix(outcomes, "flagged")
        per_config[name] = {
            "description": config.description,
            "controls": {
                "canonicalization": config.canonicalization,
                "context_filter": config.context_filter,
                "anomaly": config.anomaly,
                "uncertainty": config.uncertainty,
                "isolation": config.isolation,
                "redaction": config.redaction,
            },
            "blocked_confusion_matrix": blocked_matrix,
            "blocked_rates": _rates(blocked_matrix),
            "flagged_confusion_matrix": flagged_matrix,
            "flagged_rates": _rates(flagged_matrix),
            "family_pass_rates": _family_pass_rates(outcomes),
            "failures": _failures_with_risk(outcomes, "blocked"),
        }

    baseline = per_config.get("default_pipeline")
    if baseline is not None:
        for entry in per_config.values():
            entry["delta_vs_default_pipeline"] = {
                metric: _delta(baseline["blocked_rates"][metric], entry["blocked_rates"][metric])
                for metric in ("miss_rate", "false_block_rate", "pass_rate")
            }

    return {
        "pipeline": ABLATION_PIPELINE_ID,
        "dataset_filename": Path(dataset_path).name,
        "case_count": len(cases),
        "disclaimer": ABLATION_REPORT_DISCLAIMER,
        "configs": per_config,
    }


def _delta(baseline: float | None, current: float | None) -> float | None:
    if baseline is None or current is None:
        return None
    return round(current - baseline, 4)


def _family_pass_rates(outcomes: list[dict[str, Any]]) -> dict[str, float]:
    rates: dict[str, float] = {}
    families = sorted({str(row["attack_family"]) for row in outcomes})
    for family in families:
        rows = [row for row in outcomes if row["attack_family"] == family]
        matrix = {
            "true_positives": sum(
                1
                for row in rows
                if row["case_type"] == "adversarial"
                and row["expected_blocked"]
                and row["blocked"]
            ),
            "false_negatives": sum(
                1
                for row in rows
                if row["case_type"] == "adversarial"
                and row["expected_blocked"]
                and not row["blocked"]
            ),
            "false_positives": sum(
                1 for row in rows if row["case_type"] == "benign" and row["blocked"]
            ),
            "true_negatives": sum(
                1 for row in rows if row["case_type"] == "benign" and not row["blocked"]
            ),
        }
        total = len(rows)
        rates[family] = round((matrix["true_positives"] + matrix["true_negatives"]) / total, 4)
    return rates
