"""Command-line interface for adversarial ML security workflows."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from src.config.loader import load_config
from src.services import DefensePipeline, default_evaluation_dataset, run_evaluation_suite
from src.utils.llm_client import LLMClient, LLMMode
from src.utils.logging import configure_logging, configure_silent


def _resolve_mode(mode_arg: str | None) -> LLMMode:
    """Resolve the LLM mode from CLI argument or environment auto-detection."""
    if mode_arg:
        return LLMMode(mode_arg)
    return LLMMode.SIMULATION


def _resolve_mode_or_none(mode_arg: str | None) -> LLMMode | None:
    if mode_arg:
        return LLMMode(mode_arg)
    return None


def _tracking_setup(args: argparse.Namespace, name: str, tags: list[str] | None = None) -> None:
    """Start W&B tracking if --track flag is set."""
    if not getattr(args, "track", False):
        return
    from src.services.tracking import get_tracker

    tracker = get_tracker()
    tracker.start(run_name=name, tags=tags)


def _setup_logging(args: argparse.Namespace) -> None:
    """Configure structured logging based on CLI flags."""
    log_level = getattr(args, "log_level", "INFO")
    json_logs = getattr(args, "json_logs", False)
    if getattr(args, "quiet", False):
        configure_silent()
    else:
        configure_logging(level=log_level, json_output=json_logs)


def _read_scan_input(file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")

    if sys.stdin.isatty():
        raise ValueError("Provide --file or pipe input over stdin.")

    return sys.stdin.read()


def run_scan_command(args: argparse.Namespace) -> int:
    """Run scan mode on a file or piped text and emit JSON output."""
    _setup_logging(args)
    _tracking_setup(args, f"scan-{int(time.time())}", tags=["scan", args.task or "summarize"])
    text = _read_scan_input(args.file)
    mode = _resolve_mode(args.mode)
    client = LLMClient.from_env(mode=mode)

    response = client.generate(
        prompt=args.prompt,
        context=text,
        task_type=args.task,
        simulate_vulnerable=args.simulate_vulnerable,
    )

    pipeline = DefensePipeline()
    result = pipeline.analyze_output(
        input_text=text,
        output_text=response.content,
        expected_task=args.task,
    )

    payload = {
        "llm_mode": response.mode.value,
        "model": response.model,
        "tokens_used": response.tokens_used,
        "latency_ms": response.latency_ms,
        "risk_level": result.detection.risk_level,
        "blocked": result.detection.blocked,
        "confidence": result.detection.confidence,
        "uncertainty": result.uncertainty,
        "needs_human_review": result.needs_human_review,
        "detections": result.detection.details,
        "events": [event.to_dict() for event in result.events],
    }

    if getattr(args, "track", False):
        from src.services.tracking import get_tracker
        get_tracker().log_scan(payload)
        get_tracker().finish()

    print(json.dumps(payload, indent=2))
    return 0


def run_eval_command(args: argparse.Namespace) -> int:
    """Execute evaluation suite and emit summary metrics as JSON."""
    _setup_logging(args)
    _tracking_setup(args, f"eval-{args.suite}-{int(time.time())}", tags=["eval", args.suite])
    if args.dataset:
        result = run_evaluation_suite(
            dataset_path=Path(args.dataset),
            suite_name=args.suite,
        )
    else:
        with default_evaluation_dataset() as dataset_path:
            result = run_evaluation_suite(
                dataset_path=dataset_path,
                suite_name=args.suite,
            )

    output = result.to_dict(include_case_results=getattr(args, "show_cases", False))

    if getattr(args, "track", False):
        from src.services.tracking import get_tracker
        get_tracker().log_eval(output)
        get_tracker().finish()

    print(json.dumps(output, indent=2))
    return 0


def run_serve_command(args: argparse.Namespace) -> int:
    """Launch the Gradio web demo."""
    _setup_logging(args)
    from src.web.ui import create_demo

    demo = create_demo()
    demo.launch(
        server_name=args.host,
        server_port=args.port,
        share=args.share,
        show_error=True,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="adml",
        description="Adversarial ML Security Lab toolkit.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to YAML config file (default: configs/config.yaml).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan text using defense pipeline.")
    scan_parser.add_argument("--file", help="Path to text file to scan.")
    scan_parser.add_argument(
        "--prompt",
        default="Please summarize this document.",
        help="Prompt used for model output generation.",
    )
    scan_parser.add_argument(
        "--task",
        default="summarize",
        choices=["general", "summarize", "classify", "chat"],
        help="Expected task type for policy checks.",
    )
    scan_parser.add_argument(
        "--simulate-vulnerable",
        action="store_true",
        help="Simulate vulnerable model behavior on adversarial inputs.",
    )
    scan_parser.add_argument(
        "--mode",
        choices=["simulation", "openai", "anthropic", "ollama"],
        help="LLM backend mode (default: simulation).",
    )
    scan_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    scan_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    scan_parser.add_argument(
        "--track",
        action="store_true",
        help="Log results to Weights & Biases (requires WANDB_API_KEY).",
    )
    scan_parser.set_defaults(func=run_scan_command)

    eval_parser = subparsers.add_parser("eval", help="Run evaluation corpus and report metrics.")
    eval_parser.add_argument(
        "--dataset",
        help="Path to evaluation JSONL dataset. Defaults to the packaged baseline dataset.",
    )
    eval_parser.add_argument(
        "--suite",
        default="baseline",
        help="Suite name for reporting.",
    )
    eval_parser.add_argument(
        "--show-cases",
        action="store_true",
        help="Include per-case evaluation results in the JSON output.",
    )
    eval_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    eval_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    eval_parser.add_argument(
        "--track",
        action="store_true",
        help="Log results to Weights & Biases (requires WANDB_API_KEY).",
    )
    eval_parser.set_defaults(func=run_eval_command)

    serve_parser = subparsers.add_parser("serve", help="Run the web demo server.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host bind address.")
    serve_parser.add_argument("--port", type=int, default=7860, help="Server port.")
    serve_parser.add_argument(
        "--share", action="store_true", help="Enable public Gradio share link."
    )
    serve_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    serve_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    serve_parser.set_defaults(func=run_serve_command)

    config_parser = subparsers.add_parser("config", help="Show current configuration.")
    config_parser.add_argument(
        "--file",
        default=None,
        help="Path to YAML config file (default: configs/config.yaml).",
    )
    config_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    config_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    config_parser.set_defaults(func=run_config_command)

    api_parser = subparsers.add_parser("api", help="Run the FastAPI server.")
    api_parser.add_argument("--host", default="127.0.0.1", help="Host bind address.")
    api_parser.add_argument("--port", type=int, default=7861, help="Server port.")
    api_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload during development."
    )
    api_parser.add_argument(
        "--cors-origins",
        default="*",
        help="Comma-separated list of allowed CORS origins (default: *).",
    )
    api_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    api_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    api_parser.set_defaults(func=run_api_command)

    fuzz_parser = subparsers.add_parser("fuzz", help="Run automated red teaming fuzzer.")
    fuzz_parser.add_argument("--content", help="Text content to attack.")
    fuzz_parser.add_argument(
        "--file", help="Path to file containing content to attack."
    )
    fuzz_parser.add_argument(
        "--family",
        default="all",
        help="Attack families to test: all, prompt_injection, context_tampering, "
             "inference_evasion, rag_poisoning (comma-separated).",
    )
    fuzz_parser.add_argument(
        "--task",
        default="summarize",
        choices=["general", "summarize", "classify", "chat", "qa"],
        help="Task type for policy checks.",
    )
    fuzz_parser.add_argument(
        "--mode",
        choices=["simulation", "openai", "anthropic", "ollama"],
        help="LLM backend mode (default: auto-detect).",
    )
    fuzz_parser.add_argument(
        "--target-url",
        help="Remote API endpoint to fuzz (e.g., http://localhost:7861). "
             "If set, sends attacks to the endpoint instead of local pipeline.",
    )
    fuzz_parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit JSON-formatted logs to stderr.",
    )
    fuzz_parser.add_argument(
        "--track",
        action="store_true",
        help="Log results to Weights & Biases (requires WANDB_API_KEY).",
    )
    fuzz_parser.set_defaults(func=run_fuzz_command)

    return parser


def run_fuzz_command(args: argparse.Namespace) -> int:
    """Run the red teaming fuzzer and emit findings as JSON."""
    _setup_logging(args)
    _tracking_setup(args, f"fuzz-{int(time.time())}", tags=["fuzz", args.family or "all"])
    from src.attacks.fuzzer import RedTeamFuzzer, RemoteFuzzer

    if args.file:
        content = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    elif args.content:
        content = args.content
    else:
        if sys.stdin.isatty():
            raise ValueError("Provide --content, --file, or pipe input over stdin.")
        content = sys.stdin.read()

    families: list[str] | None = None
    if args.family != "all":
        families = [f.strip() for f in args.family.split(",")]

    fuzzer: RedTeamFuzzer
    if args.target_url:
        fuzzer = RemoteFuzzer(target_url=args.target_url)
    else:
        mode = _resolve_mode(args.mode)
        client = LLMClient.from_env(mode=mode) if mode else LLMClient.from_env()
        fuzzer = RedTeamFuzzer(llm_client=client)

    report = fuzzer.fuzz(target=content, families=families, task_type=args.task)
    output = report.to_dict()

    if getattr(args, "track", False):
        from src.services.tracking import get_tracker
        get_tracker().log_fuzz(output)
        get_tracker().finish()

    print(json.dumps(output, indent=2))
    return 0


def run_api_command(args: argparse.Namespace) -> int:
    """Launch the FastAPI server."""
    _setup_logging(args)
    from src.api.server import create_app

    cors = None if args.cors_origins == "*" else [o.strip() for o in args.cors_origins.split(",")]
    app = create_app(cors_origins=cors)

    import uvicorn

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level.lower(),
    )
    return 0


def run_config_command(args: argparse.Namespace) -> int:
    """Print current configuration as JSON."""
    _setup_logging(args)
    from omegaconf import OmegaConf

    config_path = args.file or "configs/config.yaml"
    cfg = load_config(config_path)
    print(OmegaConf.to_yaml(OmegaConf.structured(cfg)))
    return 0


def main() -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        return int(args.func(args))
    except Exception as error:  # pragma: no cover - defensive CLI guard
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
