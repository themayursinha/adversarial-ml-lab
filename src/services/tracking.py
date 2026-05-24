"""Experiment tracking via Weights & Biases.

Logs scan results, evaluation metrics, and fuzz reports to W&B
for experiment reproducibility and dashboard visualization.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class WandbConfig:
    enabled: bool = False
    project: str = "adversarial-ml-lab"
    entity: str | None = None
    run_name: str | None = None
    tags: list[str] | None = None


class ExperimentTracker:
    """W&B experiment tracker for adversarial ML workflows."""

    def __init__(self, config: WandbConfig | None = None) -> None:
        self._cfg = config or WandbConfig()
        self._run: Any = None
        self._init_from_env()

    def _init_from_env(self) -> None:
        if os.environ.get("WANDB_API_KEY"):
            self._cfg.enabled = True
        if os.environ.get("WANDB_PROJECT"):
            self._cfg.project = os.environ["WANDB_PROJECT"]

    @property
    def is_available(self) -> bool:
        return self._cfg.enabled and self._run is not None

    def start(self, run_name: str, tags: list[str] | None = None) -> None:
        if not self._cfg.enabled:
            log.debug("wandb.skipped", reason="not_enabled")
            return

        try:
            import wandb  # noqa: PLC0415
        except ImportError:
            log.warning("wandb.not_installed")
            return

        name = run_name or f"run-{int(time.time())}"
        tags = tags or []

        self._run = wandb.init(
            project=self._cfg.project,
            entity=self._cfg.entity,
            name=name,
            tags=tags,
            reinit=True,
        )
        log.info("wandb.started", project=self._cfg.project, run=name)

    def log_scan(self, metrics: dict[str, Any]) -> None:
        self._log("scan", metrics)

    def log_eval(self, metrics: dict[str, Any]) -> None:
        self._log("eval", metrics)

    def log_fuzz(self, metrics: dict[str, Any]) -> None:
        self._log("fuzz", metrics)

    def _log(self, step_type: str, metrics: dict[str, Any]) -> None:
        if not self.is_available or self._run is None:
            return
        payload = {"type": step_type}
        payload.update(metrics)
        self._run.log(payload)

    def finish(self) -> None:
        if self._run is not None:
            self._run.finish()
            self._run = None
            log.info("wandb.finished")


_tracker: ExperimentTracker | None = None


def get_tracker() -> ExperimentTracker:
    global _tracker
    if _tracker is None:
        _tracker = ExperimentTracker()
    return _tracker
