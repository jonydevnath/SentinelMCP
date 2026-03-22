# SentinelMCP

[![MCPize](https://mcpize.com/badge/@mcpize/mcpize?type=hosted)](https://mcpize.com)

MCP server built with [FastMCP 2.0](https://gofastmcp.com) for [MCPize](https://mcpize.com).

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

## Quick Start

```bash
make dev        # Install all dependencies
make run        # Start server
```

Server runs at `http://localhost:8080/mcp`

## Rename Your Project

Replace `SentinelMCP` / `SentinelMCP` with your project name in these files:

```bash
# 1. Rename the package directory
mv src/SentinelMCP src/your_project_name

# 2. Update all references (replace your_project_name / your-project-name)
```

| File | What to change |
|------|---------------|
| `pyproject.toml` | `name`, `[project.scripts]`, `[tool.hatch.build.targets.wheel]` |
| `mcpize.yaml` | `entry` path, `startCommand.command` module path |
| `Dockerfile` | `CMD` module path |
| `Makefile` | `uv run` script name in `run` target |
| `src/*/server.py` | `FastMCP("your-project-name")` |
| `tests/test_tools.py` | `from your_project_name.tools import ...` |

> **Important**: The directory name uses underscores (`your_project_name`), while the package name in pyproject.toml uses hyphens (`your-project-name`). Both `mcpize.yaml` entry and Dockerfile CMD must match the directory name.

## Development

```bash
make test       # Run tests
make lint       # Check code style
make format     # Auto-format code
```

## Tools

| Tool | Description |
|------|-------------|
| `hello` | Returns a greeting message |
| `echo` | Echoes input with timestamp |
| `delayed_echo` | Async echo with configurable delay |

## Testing

```bash
# npx @anthropic-ai/mcp-inspector http://localhost:8080/mcp
npx @modelcontextprotocol/inspector http://localhost:8080/mcp
```

## Deploy

```bash
mcpize deploy
```

## Project Structure

```
├── src/SentinelMCP/
│   ├── __init__.py
│   ├── server.py       # MCP server and tools
│   └── py.typed        # PEP 561 marker
├── tests/
│   └── test_tools.py
├── pyproject.toml
├── Makefile
└── Dockerfile
```

## License

MIT
