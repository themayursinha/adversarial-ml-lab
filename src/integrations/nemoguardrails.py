"""NeMo Guardrails integration: use adml defenses as NeMo Guardrails actions.

Provides:
- NemoguardrailsAction: wraps DefensePipeline as a guardrails action
- generate_guardrails_config: creates NeMo-style config from our detection patterns
- export_eval_results: converts adml eval to NeMo Guardrails eval format
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)


class NemoguardrailsAction:
    """Wraps the adml DefensePipeline as a NeMo Guardrails action.

    Can be used as an output rail in NeMo Guardrails configs to check
    LLM responses for adversarial patterns.
    """

    def __init__(self, sensitivity: float = 0.7) -> None:
        from src.services.defense_pipeline import DefensePipeline

        self._pipeline = DefensePipeline()
        self.sensitivity = sensitivity

    def __call__(self, llm_output: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the defense pipeline on an LLM output.

        Compatible with NeMo Guardrails action interface.
        """
        ctx = context or {}
        input_text = ctx.get("user_message", "")

        result = self._pipeline.analyze_output(
            input_text=input_text,
            output_text=llm_output,
            expected_task=ctx.get("task_type", "general"),
        )

        return {
            "blocked": result.detection.blocked,
            "risk_level": result.detection.risk_level,
            "confidence": result.detection.confidence,
            "uncertainty": result.uncertainty,
            "needs_human_review": result.needs_human_review,
            "anomaly_score": result.anomaly_score,
            "events": [e.to_dict() for e in result.events],
        }


def generate_guardrails_config(
    output_path: str = "nemoguardrails_config",
    include_anomaly: bool = True,
    include_constitutional: bool = True,
) -> dict[str, Any]:
    """Generate a NeMo Guardrails-compatible configuration.

    Creates config files that use adml defenses as rails in
    NeMo Guardrails conversational systems.
    """
    config = {
        "models": [
            {
                "type": "main",
                "engine": "openai",
                "model": "gpt-4o-mini",
            }
        ],
        "rails": {
            "output": {
                "flows": [
                    "adml check output",
                ]
            },
            "config": {
                "adml_sensitivity": 0.7,
                "adml_block_on_detection": True,
            },
        },
        "actions": [
            {
                "name": "adml_check_output",
                "description": "Check LLM output for adversarial patterns using adversarial-ml-lab",
                "module": "src.integrations.nemoguardrails",
                "class": "NemoguardrailsAction",
            }
        ],
    }

    colang = '''define flow
  bot generate response
  $response = execute adml_check_output

  if $response.blocked
    bot respond "Output blocked by security filter."
  else
    bot $response
'''

    return {"config.yml": config, "adml.co": colang}


def export_eval_results(
    dataset_path: str,
    suite_name: str = "baseline",
) -> dict[str, Any]:
    """Export evaluation results in NeMo Guardrails evaluation format.

    Compatible with nemoguardrails evaluate command output.
    """
    from pathlib import Path

    from src.services.evaluator import run_evaluation_suite

    result = run_evaluation_suite(
        dataset_path=Path(dataset_path),
        suite_name=suite_name,
    )

    return {
        "metadata": {
            "framework": "adversarial-ml-lab",
            "nemoguardrails_compatible": True,
            "version": "0.3.0",
        },
        "summary": {
            "total_cases": result.total_cases,
            "pass_rate": result.pass_rate,
            "blocked_cases": result.blocked_cases,
            "review_cases": result.review_cases,
        },
        "family_metrics": {
            family: fm.to_dict() for family, fm in result.family_metrics.items()
        },
        "case_results": [
            cr.to_dict() for cr in result.case_results
        ],
    }
