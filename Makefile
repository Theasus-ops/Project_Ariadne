# Ariadne — common tasks. Run `make help` for the list.

.PHONY: help install dev test lint intel serve docker-build docker-run

help:
	@echo "install       pip install the package"
	@echo "dev           install with dev + pdf extras"
	@echo "test          run the deterministic test suite"
	@echo "lint          run ruff"
	@echo "intel         pull ~28k attribution labels"
	@echo "serve         launch the web console"
	@echo "docker-build  build the container image"
	@echo "docker-run    run the web console in a container on :8000"

install:
	pip install -e .

dev:
	pip install -e ".[dev,pdf]"

test:
	pytest -q

lint:
	ruff check ariadne/ tests/

intel:
	ariadne update-intel

serve:
	ariadne serve

docker-build:
	docker build -t ariadne .

docker-run:
	docker run --rm -p 8000:8000 -v ariadne-data:/app ariadne
