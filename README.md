# Adversarial ML Security Lab

Interactive demonstrations of adversarial ML attacks and defenses for LLM security.

## Overview

This project demonstrates three attack/defense pairs commonly encountered in LLM security:

| Attack | Defense |
|--------|---------|
| Indirect Prompt Injection | Context-Aware Output Filters |
| Model Context Tampering | Context-Isolated Server with Redaction |
| Inference Evasion | Ensemble Uncertainty Scoring |

A fourth tab allows users to upload their own files or paste content for vulnerability scanning.

## Installation

```bash
git clone https://github.com/themayursinha/adversarial-ml-lab.git
cd adversarial-ml-lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Open http://localhost:7860

## Project Structure

```
src/
  attacks/        # Injection, tampering, evasion implementations
  defenses/       # Filters, isolation server, uncertainty scorer
  utils/          # Simulated LLM client
tests/            # Unit tests
app.py            # Gradio web interface
```

## Testing

```bash
pytest tests/ -v
```

## License

MIT
