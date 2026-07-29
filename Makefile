.PHONY: test lint typecheck demo build clean

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -v

lint:
	ruff check dontlie test_*.py demo/scripts

typecheck:
	mypy --strict dontlie/storage.py dontlie/sign.py

demo:
	bash demo/scripts/run_offline_demo.sh
	$(PYTHON) demo/scripts/tamper_walkthrough.py demo/work
	$(PYTHON) demo/scripts/cleanup.py

build:
	python -m build

clean:
	$(PYTHON) demo/scripts/cleanup.py || true
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
