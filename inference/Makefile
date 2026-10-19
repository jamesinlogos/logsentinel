.PHONY: setup test lint typecheck format check train evaluate model e2e-restart run docker-build clean

PYTHON ?= python
CAPTURES ?= ../sentinelcap/captures
ARTIFACTS ?= artifacts
# ../scripts: the repository scripts follow the same ruff rules (tests/test_repository_*.py
# run them); --config makes ruff use this project's settings for them too.
LINTED = src tests training ../scripts
RUFF = $(PYTHON) -m ruff
# Capture runs kept for the independent check (inference/README.md section 9.1 rule 10): never trained on,
# never used to pick the threshold, scored at the end of `make evaluate`. A run that captures
# the reference samples again belongs here too (train and evaluate stop if one is missing).
HOLDOUT ?= 20261009T033557Z 20261009T120629Z
HOLDOUT_ARGS = $(foreach run,$(HOLDOUT),--holdout $(run))

setup:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(RUFF) check --config pyproject.toml $(LINTED)
	$(RUFF) format --check --config pyproject.toml $(LINTED)

typecheck:
	$(PYTHON) -m mypy

format:
	$(RUFF) format --config pyproject.toml $(LINTED)

check: lint typecheck test

train:
	$(PYTHON) -m training.train --captures $(CAPTURES) --artifacts $(ARTIFACTS) $(HOLDOUT_ARGS)

evaluate:
	$(PYTHON) -m training.evaluate --captures $(CAPTURES) --artifacts $(ARTIFACTS) $(HOLDOUT_ARGS)

# Train, then pick the threshold: the model is only complete after both.
model: train evaluate

# Needs a running broker (BOOTSTRAP) and a capture session dir (SESSION):
# kills the service mid-stream and checks that no detection is lost (inference/README.md section 9.2).
BOOTSTRAP ?= localhost:9092
SESSION ?= $(CAPTURES)/20261001T011932Z/blackbasta/11129aad3b5baa1d118ec0ee3922278c194e43f6e2f0fcef221c65e5f4490d3b
e2e-restart:
	$(PYTHON) -m training.e2e_restart --capture $(SESSION) --bootstrap $(BOOTSTRAP) --artifacts $(ARTIFACTS)

run:
	$(PYTHON) -m inference

docker-build:
	docker compose -f ../docker-compose.yml build inference

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache
