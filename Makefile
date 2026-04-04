.PHONY: test lint type-check security clean install dev

install:
	pip install -e ".[all]" --break-system-packages

dev:
	pip install -e ".[dev]" --break-system-packages

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ --cov=cuttix --cov-report=html --cov-report=term

lint:
	ruff check cuttix/ tests/
	ruff format --check cuttix/ tests/

format:
	ruff format cuttix/ tests/
	ruff check --fix cuttix/ tests/

type-check:
	mypy cuttix/

security:
	bandit -r cuttix/ -c pyproject.toml || true
	pip-audit || true

clean:
	rm -rf build/ dist/ *.egg-info .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

all: lint type-check test security
