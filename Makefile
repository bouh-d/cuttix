.PHONY: help install dev test test-cov lint format type-check security \
        clean build binary license all

PYTHON ?= python
PIP    ?= $(PYTHON) -m pip

help:
	@echo "Cuttix — common dev tasks"
	@echo ""
	@echo "  install       Install Cuttix with every runtime extra."
	@echo "  dev           Editable install with dev + GUI tooling."
	@echo "  test          Run the test suite (headless Qt)."
	@echo "  test-cov      Run tests with coverage report."
	@echo "  lint          Ruff check + format check."
	@echo "  format        Ruff auto-fix + format."
	@echo "  type-check    mypy."
	@echo "  security      bandit + pip-audit."
	@echo "  build         Build sdist + wheel into dist/."
	@echo "  binary        Build a standalone binary with PyInstaller."
	@echo "  license       Fetch the full GPLv3 text into LICENSE.full."
	@echo "  clean         Remove build artefacts and caches."

install:
	$(PIP) install -e '.[all]'

dev:
	$(PIP) install -e '.[dev,gui,capture,pdf]'

test:
	QT_QPA_PLATFORM=offscreen pytest -q

test-cov:
	QT_QPA_PLATFORM=offscreen pytest --cov=cuttix --cov-report=term-missing --cov-report=html

lint:
	ruff check cuttix tests
	ruff format --check cuttix tests

format:
	ruff format cuttix tests
	ruff check --fix cuttix tests

type-check:
	mypy cuttix

security:
	bandit -r cuttix -c pyproject.toml || true
	pip-audit || true

build:
	$(PIP) install --upgrade build
	$(PYTHON) -m build

binary:
	$(PIP) install --upgrade pyinstaller
	pyinstaller scripts/cuttix.spec

license:
	@echo "Downloading GPLv3 text from https://www.gnu.org/licenses/gpl-3.0.txt"
	curl -fsSL https://www.gnu.org/licenses/gpl-3.0.txt -o LICENSE.full

clean:
	rm -rf build dist *.egg-info .coverage htmlcov .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

all: lint type-check test
