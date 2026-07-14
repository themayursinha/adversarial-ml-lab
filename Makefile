PYTHON ?= venv/bin/python
PIP ?= $(PYTHON) -m pip

.PHONY: setup setup-dev lint typecheck test security eval package release-check run up up-full up-llm down logs

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

setup-dev:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt

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
	$(PYTHON) -m src.cli eval --suite baseline

package:
	$(PYTHON) -m build --no-isolation
	$(PYTHON) -m twine check dist/*

release-check: lint typecheck test security package
	TMP_VENV=$$(mktemp -d /tmp/adml-release-check.XXXXXX); \
		WHEEL_FILE=$$(ls -t dist/*.whl | head -n 1); \
		python3 -m venv "$$TMP_VENV"; \
		"$$TMP_VENV/bin/python" -m pip install --upgrade pip; \
		"$$TMP_VENV/bin/pip" install "$$WHEEL_FILE"; \
		"$$TMP_VENV/bin/adml" --help >/dev/null; \
		"$$TMP_VENV/bin/adml" eval --suite baseline >/dev/null

run:
	$(PYTHON) app.py

up:
	docker compose up -d api

up-full:
	OLLAMA_HOST=http://ollama:11434 docker compose --profile full up -d

up-llm:
	OLLAMA_HOST=http://ollama:11434 docker compose --profile llm up -d api ollama

down:
	docker compose down

logs:
	docker compose logs -f
