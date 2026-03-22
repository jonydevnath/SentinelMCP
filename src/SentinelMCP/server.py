"""MCP server entry point."""

import contextlib
import json
import logging
import signal
import time
from os import getenv

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from rich.console import Console
from starlette.requests import Request
from starlette.responses import JSONResponse

from .tools import (
    analyze_code_security,
    check_dependencies,
    scan_secrets,
    security_summary,
    validate_input,
)

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=getenv("LOG_LEVEL", "INFO"),
)

# ============================================================================
# Dev Logging Middleware
# ============================================================================

console = Console()
IS_DEV = getenv("ENV", "development") != "production"


def truncate(s: str, max_len: int = 60) -> str:
    """Truncate string with ellipsis."""
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def format_latency(ms: float) -> str:
    """Color-code latency: green <100ms, yellow 100-500ms, red >500ms."""
    if ms < 100:
        return f"[green]{ms:.0f}ms[/green]"
    if ms < 500:
        return f"[yellow]{ms:.0f}ms[/yellow]"
    return f"[red]{ms:.0f}ms[/red]"


def timestamp() -> str:
    """Get current time as HH:MM:SS."""
    return time.strftime("%H:%M:%S")


class DevLoggingMiddleware(Middleware):
    """Colorized dev logging middleware for MCP requests/responses."""

    async def on_message(self, context: MiddlewareContext, call_next):
        """Log all MCP messages with timing."""
        if not IS_DEV:
            return await call_next(context)

        method = context.method
        message = context.message

        # Skip noisy notifications
        if method == "notifications/initialized":
            return await call_next(context)

        # Log request
        if method == "tools/call" and message:
            tool_name = getattr(message, "name", "unknown")
            tool_args = getattr(message, "arguments", {})
            args_str = truncate(json.dumps(tool_args)) if tool_args else ""
            console.print(
                f"[dim][{timestamp()}][/dim] [cyan]→[/cyan] tools/call [bold]{tool_name}[/bold]"
                + (f" [dim]{args_str}[/dim]" if args_str else "")
            )
        else:
            params_str = ""
            if message:
                with contextlib.suppress(Exception):
                    params_str = (
                        f" [dim]{truncate(json.dumps(message, default=str))}[/dim]"
                    )
            console.print(f"[dim][{timestamp()}][/dim] [cyan]→[/cyan] {method}{params_str}")

        # Execute and time
        start = time.time()
        result = await call_next(context)
        latency_ms = (time.time() - start) * 1000

        # Log response
        latency = format_latency(latency_ms)

        if hasattr(result, "isError") and result.isError:
            error_msg = truncate(str(result))
            console.print(
                f"[dim][{timestamp()}][/dim] [red]✖[/red] {method}"
                f" [red]{error_msg}[/red] ({latency})"
            )
        elif method == "tools/call":
            # Extract tool result for display
            try:
                content = getattr(result, "content", [])
                if content and hasattr(content[0], "text"):
                    result_text = truncate(content[0].text)
                    console.print(
                        f"[dim][{timestamp()}][/dim] [green]←[/green] {result_text} ({latency})"
                    )
                else:
                    console.print(
                        f"[dim][{timestamp()}][/dim] [green]✓[/green] tools/call ({latency})"
                    )
            except Exception:
                console.print(
                    f"[dim][{timestamp()}][/dim] [green]✓[/green] tools/call ({latency})"
                )
        else:
            console.print(f"[dim][{timestamp()}][/dim] [green]✓[/green] {method} ({latency})")

        return result


# ============================================================================
# MCP Server Setup
# ============================================================================

mcp = FastMCP("SentinelMCP")

# Add dev logging middleware
mcp.add_middleware(DevLoggingMiddleware())

# Health endpoint
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})


# Register tools
mcp.tool()(scan_secrets)
mcp.tool()(analyze_code_security)
mcp.tool()(check_dependencies)
mcp.tool()(validate_input)
mcp.tool()(security_summary)


def main() -> None:
    """Run the MCP server with graceful shutdown."""
    port = int(getenv("PORT", "8080"))

    console.print()
    console.print("[bold]MCP Server running on[/bold]", f"[cyan]http://localhost:{port}[/cyan]")
    console.print(f"  [dim]Health:[/dim] http://localhost:{port}/health")
    console.print(f"  [dim]MCP:[/dim]    http://localhost:{port}/mcp")

    if IS_DEV:
        console.print()
        console.print("[dim]" + "─" * 50 + "[/dim]")
        console.print()

    def handle_sigterm(*_):
        console.print("[dim]Received SIGTERM, shutting down...[/dim]")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
    )


if __name__ == "__main__":
    main()
