"""Command-line interface for adversarial ML security workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.services import DefensePipeline, default_evaluation_dataset, run_evaluation_suite
from src.utils.llm_client import LLMClient, LLMMode


def _read_scan_input(file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")

    if sys.stdin.isatty():
        raise ValueError("Provide --file or pipe input over stdin.")

    return sys.stdin.read()


def run_scan_command(args: argparse.Namespace) -> int:
    """Run scan mode on a file or piped text and emit JSON output."""
    text = _read_scan_input(args.file)
    client = LLMClient(mode=LLMMode.SIMULATION)

    generated_output = client.generate(
        prompt=args.prompt,
        context=text,
        task_type=args.task,
        simulate_vulnerable=args.simulate_vulnerable,
    ).content

    pipeline = DefensePipeline()
    result = pipeline.analyze_output(
        input_text=text,
        output_text=generated_output,
        expected_task=args.task,
    )

    payload = {
        "risk_level": result.detection.risk_level,
        "blocked": result.detection.blocked,
        "confidence": result.detection.confidence,
        "uncertainty": result.uncertainty,
        "needs_human_review": result.needs_human_review,
        "detections": result.detection.details,
        "events": [event.to_dict() for event in result.events],
    }

    print(json.dumps(payload, indent=2))
    return 0


def run_eval_command(args: argparse.Namespace) -> int:
    """Execute evaluation suite and emit summary metrics as JSON."""
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

    print(json.dumps(result.to_dict(), indent=2))
    return 0


def run_serve_command(args: argparse.Namespace) -> int:
    """Launch the Gradio web demo."""
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
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan text using defense pipeline.")
    scan_parser.add_argument("--file", help="Path to text file to scan.")
    scan_parser.add_argument(
        "--prompt",
        default="Please summarize this document.",
        help="Prompt used for simulated model output generation.",
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
    eval_parser.set_defaults(func=run_eval_command)

    serve_parser = subparsers.add_parser("serve", help="Run the web demo server.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host bind address.")
    serve_parser.add_argument("--port", type=int, default=7860, help="Server port.")
    serve_parser.add_argument("--share", action="store_true", help="Enable public Gradio share link.")
    serve_parser.set_defaults(func=run_serve_command)

    return parser


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
