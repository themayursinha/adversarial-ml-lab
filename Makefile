PYTHON ?= venv/bin/python

.PHONY: setup lint typecheck test security eval run

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt

lint:
	$(PYTHON) -m ruff check src tests app.py

typecheck:
	$(PYTHON) -m mypy src app.py --ignore-missing-imports

test:
	$(PYTHON) -m pytest -q

security:
	$(PYTHON) -m bandit -r src -ll
	$(PYTHON) -m pip_audit -r requirements.txt

eval:
	$(PYTHON) -m src.cli eval --dataset evals/datasets/baseline.jsonl --suite baseline

run:
	$(PYTHON) app.py
