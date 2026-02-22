# Adversarial ML Security Lab

Interactive attack/defense toolkit for AI security engineers.

## What This Project Demonstrates

- Indirect prompt injection and output filtering
- Conversation context tampering and session isolation
- Inference evasion (obfuscation) and uncertainty-driven review
- Local content scanning for prompt-risk and sensitive-data indicators

## Quick Start

```bash
git clone https://github.com/themayursinha/adversarial-ml-lab.git
cd adversarial-ml-lab
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

Run web UI:

```bash
venv/bin/python app.py
```

Run CLI:

```bash
venv/bin/python -m src.cli scan --file README.md --task summarize
venv/bin/python -m src.cli eval --dataset evals/datasets/baseline.jsonl
venv/bin/python -m src.cli serve --host 0.0.0.0 --port 7860
```

## Architecture

```text
src/
  attacks/      # attack generators and sample inputs
  defenses/     # filtering, isolation, uncertainty scoring
  domain/       # typed security event/result models
  services/     # canonicalization, defense pipeline, evaluator
  web/          # Gradio state, controllers, UI
  cli.py        # CLI entrypoint (scan/eval/serve)
tests/          # unit and integration tests
docs/           # threat model, control mapping, deployment guidance
evals/          # evaluation corpora
```

## Security Posture

- Simulation mode by default (no external API dependency)
- Canonicalization before output safety checks
- Structured security events for detections and review gates
- Governance artifacts: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`

## Development Commands

```bash
make lint
make typecheck
make test
make security
make eval
```

## Docker

The project uses Chainguard Python images with a non-root runtime profile.

```bash
docker build -t adversarial-ml-lab .
docker run -p 7860:7860 adversarial-ml-lab
```

## License

MIT
