SHELL := /bin/bash
UV ?= uv
PYTHON_VERSIONS ?= 3.8 3.9 3.10 3.11 3.12 3.13
UV_SYNC_FLAGS ?= --all-extras --group dev
PIP_NO_BINARY_FIX ?= "lxml,xmlsec"
PYSENTRY_MIN_VERSION_CHECK := python -c "import sys; raise SystemExit(sys.version_info < (3, 9))"

.PHONY: default help qa ci-qa

default: help

help:
	@echo "Available targets:" \
	; echo "  help   - show this message" \
	; echo "  qa     - run QA with current Python" \
	; echo "  ci-qa  - run QA across $(PYTHON_VERSIONS)"

qa:
	@set -euo pipefail; \
	$(UV) sync $(UV_SYNC_FLAGS); \
	PIP_NO_BINARY=$(PIP_NO_BINARY_FIX) $(UV) run pip install --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec; \
	$(UV) run ruff check; \
	$(UV) run ruff format --check; \
	$(UV) run vale README.md CONTRIBUTING.md; \
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
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v vale README.md CONTRIBUTING.md; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v pytest; \
		UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v bandit -r fastapi_opa --exclude="fastapi_opa/example_oidc.py,fastapi_opa/example_saml.py"; \
		if UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v $(PYSENTRY_MIN_VERSION_CHECK); then \
			UV_PROJECT_ENVIRONMENT=.venv-$$v $(UV) run --python $$v pysentry-rs; \
		else \
			echo "Skipping pysentry-rs on Python $$v (requires >=3.9)"; \
		fi; \
	done
