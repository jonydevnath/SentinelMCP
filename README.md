# SentinelMCP

[![MCPize](https://mcpize.com/badge/@mcpize/mcpize?type=hosted)](https://mcpize.com)

MCP server built with [FastMCP 2.0](https://gofastmcp.com) for [MCPize](https://mcpize.com). It exposes security-focused tools: secret scanning, static code checks, dependency auditing, input-handling heuristics, and a combined report with a 0–100 score.

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

Tools are registered in pipeline order (run the first four on your project, then aggregate with `security_summary`).

| Tool | Input | Output |
|------|--------|--------|
| `scan_secrets` | `project_path` — root directory to scan | `project`, `count`, `findings` (JSON: `file`, `line`, `type`: API key / password / token). Skips `node_modules`, `.git`, `.venv`, etc. |
| `analyze_code_security` | `file_path` and/or `code` — source file or snippet | `source`, `count`, `findings` (JSON: `issue_type`, `severity`, `explanation`, `suggested_fix`, `line`). Detects SQL injection-style patterns, `eval`/`exec`, hardcoded credentials. |
| `check_dependencies` | `dep_file_path` — must be `requirements.txt` or `package.json` | `file`, `ecosystem` (`python` / `node`), `count`, `vulnerabilities` (JSON). Python: [pip-audit](https://pypi.org/project/pip-audit/). Node: `npm audit --json`. |
| `validate_input` | `file_path` and/or `code` | `source`, `count`, `findings` (JSON: `unsafe_pattern`, `recommendation`, `line`). Heuristics for unsafe handling of user-controlled data. |
| `security_summary` | `scan_secrets_json`, `analyze_code_security_json`, `check_dependencies_json`, `validate_input_json` — each optional, full JSON string of that tool’s return dict | `summary`, `severity_breakdown` (JSON), `security_score` (0–100), `total_issues` |

All tools return `dict[str, str]`; nested lists are JSON-encoded strings for MCP compatibility.

**Suggested workflow**

1. `scan_secrets` on the repo root.  
2. `analyze_code_security` per file or on snippets (or script a walk over `*.py`).  
3. `check_dependencies` on `requirements.txt` or `package.json`.  
4. `validate_input` on the same files or templates.  
5. `security_summary` with the four JSON blobs (`json.dumps` each tool result) for one combined score and severity counts.

**Limits**

- Pattern-based only; expect false positives/negatives.  
- `check_dependencies` needs `npm` on `PATH` for Node; Python audits use the bundled `pip-audit`.  
- `security_summary` maps dependency severities from npm; pip-audit entries often appear as `unknown` in the breakdown.

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
│   ├── server.py       # FastMCP app, middleware, tool registration
│   ├── tools.py        # Tool implementations (pure functions)
│   └── py.typed        # PEP 561 marker
├── tests/
│   ├── conftest.py
│   └── test_tools.py
├── pyproject.toml
├── Makefile
└── Dockerfile
```

## License

MIT
