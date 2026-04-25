SHELL := /bin/bash
UV ?= uv
PYTHON_VERSIONS ?= 3.10 3.11 3.12 3.13
UV_SYNC_FLAGS ?= --all-extras --group dev
PIP_NO_BINARY_FIX ?= "lxml,xmlsec"
PYSENTRY_MIN_VERSION_CHECK := python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"

.PHONY: default help qa ci-qa qa-lowest ci-qa-lowest

default: help

help:
	@echo "Available targets:" \
	; echo "  help   - show this message" \
	; echo "  qa     - run QA with current Python" \
	; echo "  ci-qa  - run QA across $(PYTHON_VERSIONS)" \
	; echo "  qa-lowest     - run pytest with lowest compatible direct deps" \
	; echo "  ci-qa-lowest  - run lowest-direct pytest across $(PYTHON_VERSIONS)"

qa:
	@set -euo pipefail; \
	$(UV) sync $(UV_SYNC_FLAGS); \
	PIP_NO_BINARY=$(PIP_NO_BINARY_FIX) $(UV) run pip install --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec; \
	$(UV) run ruff check; \
	$(UV) run ruff format --check; \
	$(UV) run ty check; \
	$(UV) run mypy; \
	$(UV) run vale README.md CONTRIBUTING.md docs; \
	$(UV) run pytest; \
	$(UV) run bandit -r fastapi_opa --exclude="fastapi_opa/example_oidc.py,fastapi_opa/example_saml.py"; \
	if $(UV) run $(PYSENTRY_MIN_VERSION_CHECK); then \
		$(UV) run pysentry-rs; \
	else \
		echo "Skipping pysentry-rs (requires >=3.9)"; \
	fi

ci-qa:
	@set -euo pipefail; \
	for v in $(PYTHON_VERSIONS); do \
		echo "===> Running QA with Python $$v"; \
		$(UV) python install $$v; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) sync --python $$v $(UV_SYNC_FLAGS); \
		PIP_NO_BINARY=$(PIP_NO_BINARY_FIX) UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v pip install --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v ruff check; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v ruff format --check; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v ty check; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v mypy; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v vale README.md CONTRIBUTING.md docs; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v pytest; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v bandit -r fastapi_opa --exclude="fastapi_opa/example_oidc.py,fastapi_opa/example_saml.py"; \
		if UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v $(PYSENTRY_MIN_VERSION_CHECK); then \
			UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v pysentry-rs; \
		else \
			echo "Skipping pysentry-rs on Python $$v (requires >=3.9)"; \
		fi; \
	done

qa-lowest:
	@set -euo pipefail; \
	$(UV) venv .venv-lowest --clear; \
	$(UV) pip install --python .venv-lowest/bin/python -r pyproject.toml --all-extras --resolution lowest-direct; \
	$(UV) pip install --python .venv-lowest/bin/python --group dev --resolution lowest-direct; \
	PIP_NO_BINARY=$(PIP_NO_BINARY_FIX) $(UV) pip install --python .venv-lowest/bin/python --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec; \
	.venv-lowest/bin/python -m pytest

ci-qa-lowest:
	@set -euo pipefail; \
	for v in $(PYTHON_VERSIONS); do \
		echo "===> Running lowest-direct compatibility tests with Python $$v"; \
		$(UV) python install $$v; \
		$(UV) venv .venv-lowest-$$v --python $$v --clear; \
		$(UV) pip install --python .venv-lowest-$$v/bin/python -r pyproject.toml --all-extras --resolution lowest-direct; \
		$(UV) pip install --python .venv-lowest-$$v/bin/python --group dev --resolution lowest-direct; \
		PIP_NO_BINARY=$(PIP_NO_BINARY_FIX) $(UV) pip install --python .venv-lowest-$$v/bin/python --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec; \
		.venv-lowest-$$v/bin/python -m pytest; \
	done
