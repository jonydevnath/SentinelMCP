# MCP Server Development Guide

Python MCP server built with FastMCP 2.0 using src-layout.

## Renaming the Project

The template uses `SentinelMCP` as the package name. To rename, update ALL of these:

1. `src/SentinelMCP/` → `src/your_name/` (directory)
2. `pyproject.toml` → name, `[project.scripts]` key+value, `[tool.hatch.build.targets.wheel]` packages
3. `mcpize.yaml` → `entry: src/your_name/server.py` and `command: .venv/bin/python -m your_name.server`
4. `Dockerfile` → `CMD [".venv/bin/python", "-m", "your_name.server"]`
5. `Makefile` → `uv run your-name` (run target)
6. `src/*/server.py` → `FastMCP("your-name")`
7. `tests/test_tools.py` → `from your_name.tools import ...`

Directory name uses underscores (`your_name`), package name uses hyphens (`your-name`).
Missing any of these causes broken imports or failed deploys.

## Project Structure

```
├── src/SentinelMCP/
│   ├── __init__.py     # Package version
│   ├── tools.py        # Pure tool functions (testable)
│   ├── server.py       # FastMCP app entry point
│   └── py.typed        # PEP 561 type marker
├── tests/
│   ├── __init__.py     # Test package marker
│   ├── conftest.py     # Pytest fixtures
│   └── test_tools.py   # Tool unit tests
├── pyproject.toml      # Dependencies and tool config
├── Makefile            # Common commands
├── Dockerfile          # Container build
├── mcpize.yaml         # MCPize deployment
└── .env.example        # Environment template
```

## Commands

```bash
make help       # Show available commands
make dev        # Install all dependencies
make run        # Start server locally
make test       # Run pytest
make lint       # Check with ruff
make format     # Auto-format code
```

## Adding Tools

### 1. Define pure function in tools.py

```python
def calculate(a: str, b: str, operation: str = "add") -> dict[str, str]:
    """Perform arithmetic operation.

    Args:
        a: First number as string.
        b: Second number as string.
        operation: One of: add, subtract, multiply.

    Returns:
        Dictionary with result.
    """
    x, y = int(a), int(b)
    ops = {"add": x + y, "subtract": x - y, "multiply": x * y}
    return {"result": str(ops.get(operation, 0))}
```

### 2. Register in server.py

```python
from .tools import calculate
mcp.tool()(calculate)
```

### 3. Add tests in tests/test_tools.py

```python
class TestCalculate:
    def test_add(self):
        assert calculate("2", "3") == {"result": "5"}
    
    def test_subtract(self):
        assert calculate("5", "3", "subtract") == {"result": "2"}
```

## Async Tools (for I/O)

```python
# tools.py
async def fetch_url(url: str) -> dict[str, str]:
    """Fetch content from URL.

    Args:
        url: URL to fetch.

    Returns:
        Response status and length.
    """
    import httpx
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
        return {"status": str(r.status_code), "length": str(len(r.text))}
```

Note: Add `httpx` to dependencies in pyproject.toml if using HTTP.

## Adding Resources

```python
# tools.py
def get_config() -> str:
    """Return app configuration."""
    import json
    from os import getenv
    return json.dumps({"env": getenv("ENV", "dev"), "version": "1.0"})

# server.py
mcp.resource("config://app")(get_config)
```

## Adding Prompts

```python
# tools.py
def review_prompt(code: str, lang: str = "python") -> str:
    """Generate code review prompt."""
    return f"Review this {lang} code:\n\n```{lang}\n{code}\n```"

# server.py
mcp.prompt()(review_prompt)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

## Testing

```bash
make test                    # Run all tests
uv run pytest -v             # Verbose output
uv run pytest -k "hello"     # Filter by name
uv run pytest --cov          # With coverage (add pytest-cov to dev deps)
```

## Deployment

```bash
mcpize deploy
```

## Best Practices

1. **Pure functions**: Define tools in tools.py without FastMCP decorators
2. **Return strings**: Use `dict[str, str]` — convert numbers with `str()`
3. **Async for I/O**: HTTP calls, database queries, file operations
4. **Logging**: Use `logger.info("msg %s", val)` not f-strings
5. **Docstrings**: Google-style, they become tool descriptions for LLM
6. **Testing**: One test class per tool, test edge cases
7. **Config**: Always use `getenv()` with sensible defaults
