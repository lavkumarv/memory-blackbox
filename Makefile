.PHONY: install lint format typecheck test cov demo check

install:  ## Install the package with dev extras into the uv venv
	uv sync --all-extras

lint:  ## Run ruff lint checks
	uv run ruff check .

format:  ## Format the codebase with ruff
	uv run ruff format .

typecheck:  ## Run mypy in strict mode
	uv run mypy

test:  ## Run the test suite
	uv run pytest

cov:  ## Run tests with coverage on the core packages
	uv run pytest --cov --cov-report=term-missing

demo:  ## Run the end-to-end incident-replay demo (implemented in M11)
	uv run memory-blackbox demo

check: lint typecheck test  ## Run lint, typecheck, and tests
