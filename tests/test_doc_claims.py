"""Falsifiable checks that public security docs map to live symbols and tests."""

from __future__ import annotations

import ast
import importlib
import re
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

from src.utils.llm_client import LLMClient, LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]

# Each row: (label, module path, symbol, exact pytest node id under tests/)
CONTROL_SYMBOL_CLAIMS: list[tuple[str, str, str, str]] = [
    (
        "LLM01 prompt injection demos",
        "src.attacks.prompt_injection",
        "PromptInjectionAttack",
        "tests/test_modules.py::TestPromptInjection::test_payload_listing",
    ),
    (
        "LLM01 mitigation pipeline",
        "src.services.defense_pipeline",
        "DefensePipeline",
        "tests/test_security_pipeline.py::test_defense_pipeline_emits_detection_events",
    ),
    (
        "LLM01 context-aware filter",
        "src.defenses.context_filter",
        "ContextAwareFilter",
        "tests/test_modules.py::TestContextFilter::test_detects_injection_indicators",
    ),
    (
        "LLM02 sensitive data redaction",
        "src.defenses.isolation_server",
        "ContentRedactor",
        "tests/test_modules.py::TestIsolationServer::test_redaction",
    ),
    (
        "Session isolation",
        "src.defenses.isolation_server",
        "ContextIsolationServer",
        "tests/test_modules.py::TestIsolationServer::test_session_isolation",
    ),
    (
        "Input canonicalization",
        "src.services.canonicalization",
        "canonicalize_text",
        "tests/test_security_pipeline.py::test_canonicalize_text_removes_zero_width",
    ),
    (
        "RAG chunk poisoning defense",
        "src.rag.poison_defense",
        "RagPoisoningDefense",
        "tests/test_security_pipeline.py::test_defense_pipeline_analyze_rag_context_flags_poisoned_chunk",
    ),
    (
        "Anomaly pre-filter on raw input",
        "src.defenses.anomaly_scorer",
        "TextAnomalyScorer",
        "tests/test_security_pipeline.py::test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization",
    ),
    (
        "Pipeline stage order (anomaly before canonicalize)",
        "src.services.defense_pipeline",
        "DefensePipeline",
        "tests/test_security_pipeline.py::test_defense_pipeline_scores_anomaly_on_raw_input_before_canonicalization",
    ),
    (
        "Baseline eval harness",
        "src.services.evaluator",
        "run_evaluation_suite",
        "tests/test_cli.py::test_run_eval_command_uses_packaged_dataset_by_default",
    ),
    (
        "FastAPI scan surface (optional)",
        "src.api.server",
        "create_app",
        "tests/test_api.py::test_health_endpoint",
    ),
    (
        "Simulation-first LLM constructor default",
        "src.utils.llm_client",
        "LLMClient",
        "tests/test_doc_claims.py::test_llm_client_defaults_to_simulation_mode",
    ),
    (
        "Optional live backends via from_env",
        "src.utils.llm_client",
        "LLMClient",
        "tests/test_modules.py::TestLLMClient::test_from_env_auto_detects_openai",
    ),
    (
        "CLI scan uses simulation when env empty",
        "src.utils.llm_client",
        "LLMClient",
        "tests/test_cli.py::test_run_scan_command_emits_json",
    ),
]


@lru_cache(maxsize=1)
def _collected_pytest_node_ids() -> frozenset[str]:
    """Build node ids from test modules via AST (matches pytest nodeid shape)."""
    nodes: set[str] = set()
    tests_dir = REPO_ROOT / "tests"
    for path in sorted(tests_dir.glob("test_*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_functions: list[str] = []
        classes: dict[str, list[str]] = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                module_functions.append(node.name)
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                methods = [
                    n.name
                    for n in node.body
                    if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
                ]
                classes[node.name] = methods
        for func in module_functions:
            nodes.add(f"{rel}::{func}")
        for cls, methods in classes.items():
            for func in methods:
                nodes.add(f"{rel}::{cls}::{func}")
    return frozenset(nodes)


@pytest.mark.parametrize(
    "label,module_path,symbol,test_hint",
    CONTROL_SYMBOL_CLAIMS,
    ids=[row[0] for row in CONTROL_SYMBOL_CLAIMS],
)
def test_control_mapping_symbol_and_test_exist(
    label: str, module_path: str, symbol: str, test_hint: str
) -> None:
    module = importlib.import_module(module_path)
    assert hasattr(module, symbol), f"{label}: missing {symbol} in {module_path}"
    collected = _collected_pytest_node_ids()
    assert test_hint in collected, (
        f"{label}: pytest node {test_hint!r} not collected; "
        f"update docs/claim-map.md or add the test"
    )


def test_claim_map_document_exists() -> None:
    claim_map = REPO_ROOT / "docs" / "claim-map.md"
    assert claim_map.is_file(), "docs/claim-map.md must exist for P1 reconciliation"
    text = claim_map.read_text(encoding="utf-8")
    assert "Simulation-first" in text
    assert "Residual gaps" in text


def test_llm_client_defaults_to_simulation_mode() -> None:
    client = LLMClient()
    assert client.mode is LLMMode.SIMULATION


def test_documented_cli_commands_exist() -> None:
    from src.cli import build_parser

    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    assert sub.choices is not None
    for name in ("scan", "eval", "serve", "api", "fuzz", "rag"):
        assert name in sub.choices, f"README/roadmap references adml {name}"


def test_dockerfile_default_entrypoint_runs_gradio_app() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["python", "app.py"]' in dockerfile


def test_compose_api_overrides_entrypoint_and_simulation_first_env() -> None:
    compose_path = REPO_ROOT / "docker-compose.yml"
    raw = compose_path.read_text(encoding="utf-8")
    assert not any(line.strip().startswith("version:") for line in raw.splitlines()[:3])
    compose = yaml.safe_load(raw)
    api = compose["services"]["api"]
    assert api["entrypoint"] == ["python", "-m", "src.cli"]
    assert api["command"] == ["api", "--host", "0.0.0.0", "--port", "7861"]
    env_lines = api["environment"]
    ollama_entries = [line for line in env_lines if line.startswith("OLLAMA_HOST=")]
    assert ollama_entries == ["OLLAMA_HOST=${OLLAMA_HOST:-}"]


def test_make_compose_targets_ollama_host_semantics() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^up:\n\tdocker compose up -d api\s*$", makefile, re.MULTILINE)
    assert "OLLAMA_HOST=http://ollama:11434 docker compose --profile llm" in makefile
    assert "OLLAMA_HOST=http://ollama:11434 docker compose --profile full" in makefile
    up_ollama_hits = len(re.findall(r"^up:\n\tOLLAMA_HOST=", makefile, re.MULTILINE))
    assert up_ollama_hits == 0
