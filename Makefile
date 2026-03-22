.PHONY: help install dev test lint format run clean

help:
	@echo "Available commands:"
	@echo "  make dev      Install all dependencies"
	@echo "  make install  Install production dependencies only"
	@echo "  make run      Start the MCP server"
	@echo "  make test     Run tests"
	@echo "  make lint     Check code style"
	@echo "  make format   Auto-format code"
	@echo "  make clean    Remove build artifacts"

install:
	uv sync --no-dev

dev:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

run:
	uv run SentinelMCP

clean:
	rm -rf .venv .ruff_cache .pytest_cache __pycache__ src/**/__pycache__ tests/__pycache__
