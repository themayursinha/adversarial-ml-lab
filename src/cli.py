"""Command-line interface for adversarial ML security workflows."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from src.config.loader import load_config
from src.eval.simulate import run_simulate_command
from src.eval.validate import run_validate_command
from src.services import (
    DefensePipeline,
    default_evaluation_dataset,
    run_evaluation_suite,
    run_evaluation_with_judge,
)
from src.utils.llm_client import LLMClient, LLMMode
from src.utils.logging import configure_logging, configure_silent


def _resolve_mode(mode_arg: str | None) -> LLMMode | None:
    """Resolve CLI mode for ``LLMClient.from_env``.

    - omitted / default → simulation (privacy-safe; no ambient-key disclosure)
    - ``auto`` → ``None`` so ``from_env`` auto-selects Anthropic/OpenAI/Ollama from env
    - explicit backend name → that ``LLMMode``
    """
    if mode_arg is None or mode_arg == "":
        return LLMMode.SIMULATION
    if mode_arg == "auto":
        return None
    return LLMMode(mode_arg)


def _resolve_mode_or_none(mode_arg: str | None) -> LLMMode | None:
    """Alias kept for call sites that already use the optional-mode name."""
    return _resolve_mode(mode_arg)


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

    if getattr(args, "judge", False):
        if args.dataset:
            output = run_evaluation_with_judge(
                dataset_path=Path(args.dataset),
                suite_name=args.suite,
            )
        else:
            with default_evaluation_dataset() as dataset_path:
                output = run_evaluation_with_judge(
                    dataset_path=dataset_path,
                    suite_name=args.suite,
                )
    elif args.dataset:
        result = run_evaluation_suite(
            dataset_path=Path(args.dataset),
            suite_name=args.suite,
        )
        output = result.to_dict(include_case_results=getattr(args, "show_cases", False))
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
        choices=["simulation", "auto", "openai", "anthropic", "ollama"],
        help="LLM backend mode (default: simulation). Use 'auto' to select from env keys/host.",
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
        "--judge",
        action="store_true",
        help="Enable LLM-as-judge scoring (requires API key).",
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

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate an evaluation JSONL dataset against schema and manifest rules.",
    )
    validate_parser.add_argument(
        "dataset",
        nargs="?",
        help="Path to evaluation JSONL dataset.",
    )
    validate_parser.add_argument(
        "--dataset",
        dest="dataset_opt",
        help="Path to evaluation JSONL dataset (alternative to positional).",
    )
    validate_parser.add_argument(
        "--manifest",
        help="Path to evaluation_manifest.v1 JSON.",
    )
    validate_parser.add_argument(
        "--no-packaged-parity",
        action="store_true",
        help="Skip packaged_resource byte parity check.",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="On success, print a JSON summary.",
    )
    validate_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success message.",
    )
    validate_parser.set_defaults(func=run_validate_command)

    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Run evaluation in simulation mode (no LLM API); emit schema-checked report.",
    )
    simulate_parser.add_argument(
        "dataset",
        nargs="?",
        help="Path to evaluation JSONL dataset. Defaults to the packaged baseline.",
    )
    simulate_parser.add_argument(
        "--dataset",
        dest="dataset_opt",
        help="Path to evaluation JSONL dataset (alternative to positional).",
    )
    simulate_parser.add_argument(
        "--suite",
        default=None,
        help="Suite name for reporting (default: manifest suite_name or dataset stem).",
    )
    simulate_parser.add_argument(
        "--show-cases",
        action="store_true",
        help="Include per-case evaluation results in the JSON output.",
    )
    simulate_parser.add_argument(
        "--no-packaged-parity",
        action="store_true",
        help="Skip packaged_resource byte parity check.",
    )
    simulate_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-JSON chatter (report is always printed to stdout).",
    )
    simulate_parser.set_defaults(func=run_simulate_command)

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
    fuzz_parser.add_argument("--file", help="Path to file containing content to attack.")
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
        choices=["simulation", "auto", "openai", "anthropic", "ollama"],
        help="LLM backend mode (default: simulation). Use 'auto' to select from env keys/host.",
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

    rag_parser = subparsers.add_parser("rag", help="Test RAG vector store and poison defense.")
    rag_parser.add_argument(
        "--query",
        required=True,
        help="Query to test against the RAG knowledge base.",
    )
    rag_parser.add_argument(
        "--poison",
        action="store_true",
        help="Inject a poisoned document before retrieval.",
    )
    rag_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level for structured logging (default: INFO).",
    )
    rag_parser.set_defaults(func=run_rag_command)

    plugin_parser = subparsers.add_parser("plugin", help="Manage attack and defense plugins.")
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_action", required=True)

    plugin_list = plugin_sub.add_parser("list", help="List registered plugins.")
    plugin_list.add_argument(
        "--type",
        choices=["attacks", "defenses", "all"],
        default="all",
        help="Plugin type to list.",
    )
    plugin_list.set_defaults(func=run_plugin_list_command)

    image_parser = subparsers.add_parser(
        "image-attack", help="Run image adversarial attacks (requires torch)."
    )
    image_parser.add_argument(
        "--attack",
        choices=["fgsm", "pgd", "cw", "all"],
        default="fgsm",
        help="Attack method.",
    )
    image_parser.add_argument(
        "--epsilon", type=float, default=0.03, help="Epsilon for FGSM/PGD (default: 0.03)."
    )
    image_parser.add_argument("--steps", type=int, default=10, help="PGD steps (default: 10).")
    image_parser.set_defaults(func=run_image_attack_command)

    return parser


def run_image_attack_command(args: argparse.Namespace) -> int:
    """Run image adversarial attack demonstrations."""
    _setup_logging(args)

    try:
        import torch  # noqa: F401
    except ImportError:
        print(
            'error: image attacks require optional dependencies. '
            'pip install "adversarial-ml-lab[vision]"',
            file=sys.stderr,
        )
        return 1

    from src.attacks.vision import (
        CarliniWagnerL2,
        FastGradientSignMethod,
        ProjectedGradientDescent,
    )
    from src.attacks.vision.utils import create_random_image, load_model

    model = load_model("resnet18")
    image = create_random_image()
    label = 281  # tabby cat in ImageNet

    attacks: list[
        tuple[str, FastGradientSignMethod | ProjectedGradientDescent | CarliniWagnerL2]
    ] = []
    results: list[dict] = []

    if args.attack in ("fgsm", "all"):
        attacks.append(("FGSM", FastGradientSignMethod(model, epsilon=args.epsilon)))
    if args.attack in ("pgd", "all"):
        attacks.append(
            (
                "PGD",
                ProjectedGradientDescent(
                    model,
                    epsilon=args.epsilon,
                    alpha=args.epsilon / 4,
                    steps=args.steps,
                ),
            )
        )
    if args.attack in ("cw", "all"):
        attacks.append(("CW-L2", CarliniWagnerL2(model, max_iter=min(100, args.steps * 10))))

    for name, attack in attacks:
        result = attack.generate(image, label)  # type: ignore[arg-type]
        results.append(result.to_dict())
        print(
            f"{name}: success={result.success} "
            f"orig_pred={result.original_prediction} adv_pred={result.adversarial_prediction} "
            f"orig_conf={result.original_confidence:.3f} adv_conf={result.adversarial_confidence:.3f} "
            f"L2={result.l2_distance:.4f} Linf={result.linf_distance:.4f}"
        )

    return 0


def run_rag_command(args: argparse.Namespace) -> int:
    """Test RAG retrieval and poisoning defense."""
    _setup_logging(args)

    try:
        import sentence_transformers  # noqa: F401
    except ImportError:
        print(
            'error: RAG requires optional dependencies. '
            'pip install "adversarial-ml-lab[rag]"',
            file=sys.stderr,
        )
        return 1

    from src.attacks.rag_poisoning import RagPoisoningAttack
    from src.rag.vector_store import RagVectorStore
    from src.services.defense_pipeline import DefensePipeline

    store = RagVectorStore(collection_name="rag-cli-test", persist_dir=None)
    pipeline = DefensePipeline()
    attack = RagPoisoningAttack()

    kb = attack.KNOWLEDGE_BASES["customer_support"]
    store.ingest(
        documents=kb,
        sources=["company_kb"] * len(kb),
    )

    if args.poison:
        payload = attack.payloads[0]
        store.ingest(
            documents=[payload.payload_content],
            sources=["community_forum_post_1.txt"],
        )

    chunks = store.search(args.query, k=5)
    result = pipeline.analyze_rag_context(chunks)

    output = result.to_dict()
    output["query"] = args.query
    output["retrieved_chunks"] = [
        {"source": c.source, "score": c.score, "content": c.content[:100]} for c in chunks
    ]

    print(json.dumps(output, indent=2))
    return 0


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
        client = LLMClient.from_env(mode=mode)
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


def run_plugin_list_command(args: argparse.Namespace) -> int:
    """List registered plugins."""
    from src.plugins.base import get_registry
    from src.plugins.builtins import register_all

    register_all()
    registry = get_registry()

    if args.type in ("attacks", "all"):
        print("Attacks:")
        for a in registry.list_attacks():
            print(f"  {a['name']} [{a['category']}]")
    if args.type in ("defenses", "all"):
        print("Defenses:")
        for d in registry.list_defenses():
            print(f"  {d['name']} [{d['category']}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
