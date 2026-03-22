"""MCP server tools - pure functions for testing."""

import json
import re
import subprocess
import sys
from pathlib import Path

# (pattern name, secret type, regex). Types: API key, password, token
_SECRET_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "openai_sk",
        "API key",
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
    ),
    (
        "aws_access_key",
        "API key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "github_pat",
        "token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "generic_api_key_assign",
        "API key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|client_secret|secret_key)\s*[=:]\s*"
            r"['\"]?([^\s#'\"]{8,})['\"]?"
        ),
    ),
    (
        "password_assign",
        "password",
        re.compile(
            r"(?i)(?<![a-zA-Z0-9])(?:password|passwd|pwd)\s*[=:]\s*"
            r"['\"]?([^\s#'\"]{4,})['\"]?"
        ),
    ),
    (
        "bearer_token",
        "token",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b"),
    ),
    (
        "jwt_like",
        "token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "slack_token",
        "token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
)

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
        ".eggs",
    }
)

_TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".env",
        ".md",
        ".txt",
        ".sh",
        ".bash",
        ".zsh",
        ".cfg",
        ".ini",
        ".properties",
        ".xml",
        ".html",
        ".css",
        ".scss",
        ".sql",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".swift",
        ".php",
        ".cs",
        ".dockerfile",
    }
)


def _is_placeholder_value(value: str) -> bool:
    v = value.strip().lower()
    if len(v) < 4:
        return True
    placeholders = {
        "password",
        "changeme",
        "secret",
        "your-api-key",
        "your_api_key",
        "api_key_here",
        "placeholder",
        "example",
        "test",
        "dummy",
        "<redacted>",
        "redacted",
        "none",
    }
    if v in placeholders or v.startswith("${") or v.endswith("}"):
        return True
    return bool(all(c in "*xX-" for c in v) and len(v) <= 32)


def _iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        name = path.name.lower()
        if name == "dockerfile" or path.suffix.lower() in _TEXT_SUFFIXES:
            files.append(path)
    return sorted(files)


def _line_matches(line: str) -> list[str]:
    """Return list of secret types matched on this line (may repeat if multiple rules)."""
    found: list[str] = []
    for _rule_name, secret_type, pattern in _SECRET_RULES:
        for m in pattern.finditer(line):
            if m.lastindex:
                inner = m.group(1)
                if _is_placeholder_value(inner):
                    continue
                found.append(secret_type)
            else:
                found.append(secret_type)
    return found


def scan_secrets(project_path: str) -> dict[str, str]:
    """Scan project files for hardcoded secrets (heuristic patterns).

    Walks text-like files under the given directory and reports lines that
    match common API key, password, and token patterns.

    Args:
        project_path: Absolute or relative path to the project root directory.

    Returns:
        Dictionary with resolved path, count, and JSON list of findings.
        Each finding has: file, line, type (API key, password, or token).
    """
    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        return {
            "project": str(root),
            "count": "0",
            "findings": json.dumps([]),
            "error": "path is not a directory",
        }

    results: list[dict[str, str | int]] = []
    for file_path in _iter_scan_files(root):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(file_path.relative_to(root))
        for line_no, line in enumerate(text.splitlines(), start=1):
            for secret_type in _line_matches(line):
                results.append(
                    {
                        "file": rel,
                        "line": line_no,
                        "type": secret_type,
                    }
                )

    return {
        "project": str(root),
        "count": str(len(results)),
        "findings": json.dumps(results),
    }



# (regex, issue_type, severity, explanation, suggested_fix)
_SECURITY_LINE_PATTERNS: tuple[tuple[re.Pattern[str], str, str, str, str], ...] = (
    (
        re.compile(r"\beval\s*\("),
        "Unsafe eval",
        "high",
        "eval() executes arbitrary strings as code; input can be attacker-controlled.",
        "Remove eval() or replace with a safe parser, allowlist, or structured data (e.g. JSON).",
    ),
    (
        re.compile(r"\bexec\s*\("),
        "Unsafe exec",
        "high",
        "exec() runs arbitrary Python code from strings; it is unsafe with untrusted input.",
        "Avoid exec(); use safer APIs, importlib, or explicit logic without dynamic code.",
    ),
    (
        re.compile(r"\.execute\s*\(\s*f[\"']"),
        "SQL injection risk",
        "high",
        "SQL built with an f-string can embed untrusted data into the query.",
        "Use bound parameters: cursor.execute(\"SELECT ... WHERE id = ?\", (id,)).",
    ),
    (
        re.compile(r"\.executemany\s*\(\s*f[\"']"),
        "SQL injection risk",
        "high",
        "SQL built with an f-string in executemany can embed untrusted data.",
        "Use parameterized statements with placeholders and a sequence of parameter tuples.",
    ),
    (
        re.compile(r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*%"),
        "SQL injection risk",
        "medium",
        "Old-style % formatting on SQL strings can concatenate untrusted values into the query.",
        "Use bound parameters: cursor.execute(\"SELECT ... WHERE id = ?\", (value,)).",
    ),
    (
        re.compile(r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        "SQL injection risk",
        "high",
        "String concatenation builds SQL from pieces; values may be attacker-controlled.",
        "Use parameterized queries; never concatenate user input into SQL strings.",
    ),
    (
        re.compile(r"\.raw\s*\(\s*f[\"']"),
        "SQL injection risk",
        "high",
        "Django raw() with an f-string can embed untrusted data in raw SQL.",
        "Use raw() with %s placeholders and a params list, or the ORM query API.",
    ),
)


def _findings_for_line(line: str, line_no: int) -> list[dict[str, str | int]]:
    out: list[dict[str, str | int]] = []
    for pattern, issue_type, severity, explanation, fix in _SECURITY_LINE_PATTERNS:
        if pattern.search(line):
            out.append(
                {
                    "issue_type": issue_type,
                    "severity": severity,
                    "explanation": explanation,
                    "suggested_fix": fix,
                    "line": line_no,
                }
            )
    for secret_type in _line_matches(line):
        sev = "high" if secret_type in ("API key", "token") else "medium"
        out.append(
            {
                "issue_type": "Hardcoded credential",
                "severity": sev,
                "explanation": f"Possible hardcoded {secret_type} detected by pattern.",
                "suggested_fix": (
                    "Load secrets from environment variables or a secrets manager; "
                    "never commit keys."
                ),
                "line": line_no,
            }
        )
    return out


def analyze_code_security(file_path: str = "", code: str = "") -> dict[str, str]:
    """Analyze source code for common insecure patterns.

    Supply either a readable file path or a code string. If both are given, the
    file is used when it exists; otherwise the code snippet is analyzed.

    Args:
        file_path: Path to a source file (optional).
        code: Raw source code to analyze (optional).

    Returns:
        Dictionary with source label, count, and JSON list of findings. Each finding
        has issue_type, severity (low/medium/high), explanation, suggested_fix, line.
    """
    fp = (file_path or "").strip()
    raw = (code or "").strip()

    if fp:
        path = Path(fp).expanduser().resolve()
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            source = str(path)
        elif raw:
            content = raw
            source = "snippet"
        else:
            return {
                "source": fp,
                "count": "0",
                "findings": json.dumps([]),
                "error": "file not found or not a file",
            }
    elif raw:
        content = raw
        source = "snippet"
    else:
        return {
            "source": "",
            "count": "0",
            "findings": json.dumps([]),
            "error": "provide file_path or code",
        }

    findings: list[dict[str, str | int]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        findings.extend(_findings_for_line(line, line_no))

    return {
        "source": source,
        "count": str(len(findings)),
        "findings": json.dumps(findings),
    }



def _parse_pip_audit_output(stdout: str) -> tuple[list[dict[str, str]], str | None]:
    """Parse pip-audit JSON; return (vulnerabilities, error_message)."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "pip-audit returned invalid JSON"
    out: list[dict[str, str]] = []
    for dep in data.get("dependencies", []):
        if "skip_reason" in dep:
            continue
        name = dep.get("name", "")
        version = str(dep.get("version", ""))
        for vuln in dep.get("vulns", []):
            vid = str(vuln.get("id", ""))
            fixes = ",".join(str(x) for x in vuln.get("fix_versions", []))
            out.append(
                {
                    "package": name,
                    "version": version,
                    "severity": "unknown",
                    "vulnerability_id": vid,
                    "fix_versions": fixes,
                    "source": "pip-audit",
                }
            )
    return out, None


def _parse_npm_audit_output(data: dict) -> tuple[list[dict[str, str]], str | None]:
    """Parse npm audit JSON; return (vulnerabilities, error_message)."""
    err = data.get("error")
    if err:
        if isinstance(err, dict):
            return [], str(err.get("summary", err.get("detail", "npm audit failed")))
        return [], str(err)
    out: list[dict[str, str]] = []
    for pkg_name, vuln in data.get("vulnerabilities", {}).items():
        sev = str(vuln.get("severity", "unknown"))
        via = vuln.get("via", [])
        if isinstance(via, list) and via:
            for entry in via:
                if isinstance(entry, dict):
                    title = str(entry.get("title", entry.get("name", "")))
                    sev = str(entry.get("severity", sev))
                    out.append(
                        {
                            "package": str(pkg_name),
                            "severity": sev,
                            "title": title,
                            "source": "npm audit",
                        }
                    )
                elif isinstance(entry, str):
                    out.append(
                        {
                            "package": str(pkg_name),
                            "severity": sev,
                            "title": entry,
                            "source": "npm audit",
                        }
                    )
        else:
            out.append(
                {
                    "package": str(pkg_name),
                    "severity": sev,
                    "title": "",
                    "source": "npm audit",
                }
            )
    return out, None


def _run_pip_audit(requirements_file: Path) -> tuple[list[dict[str, str]], str | None]:
    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements_file),
        "-f",
        "json",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(requirements_file.parent),
        )
    except FileNotFoundError:
        return [], "Python interpreter or pip-audit module not available"
    text = (proc.stdout or "").strip()
    if not text and proc.stderr:
        return [], proc.stderr.strip()[:2000]
    vulns, err = _parse_pip_audit_output(text)
    if err:
        return [], err
    return vulns, None


def _run_npm_audit(package_json: Path) -> tuple[list[dict[str, str]], str | None]:
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(package_json.parent),
        )
    except FileNotFoundError:
        return [], "npm not found on PATH"
    text = proc.stdout or ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], "npm audit returned invalid JSON"
    return _parse_npm_audit_output(data)


def check_dependencies(dep_file_path: str) -> dict[str, str]:
    """Check dependencies for known vulnerabilities using pip-audit or npm audit.

    Args:
        dep_file_path: Path to a requirements.txt or package.json file.

    Returns:
        Dictionary with file path, ecosystem, count, and JSON list of findings.
        Each finding includes package name, severity (npm audit; pip-audit uses
        unknown severity when not provided by the tool), and source.
    """
    raw = (dep_file_path or "").strip()
    if not raw:
        return {
            "file": "",
            "ecosystem": "",
            "count": "0",
            "vulnerabilities": json.dumps([]),
            "error": "provide dep_file_path to requirements.txt or package.json",
        }

    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        return {
            "file": str(path),
            "ecosystem": "",
            "count": "0",
            "vulnerabilities": json.dumps([]),
            "error": "file not found or not a file",
        }

    name = path.name.lower()
    if name == "requirements.txt":
        vulns, err = _run_pip_audit(path)
        if err:
            return {
                "file": str(path),
                "ecosystem": "python",
                "count": "0",
                "vulnerabilities": json.dumps([]),
                "error": err,
            }
        return {
            "file": str(path),
            "ecosystem": "python",
            "count": str(len(vulns)),
            "vulnerabilities": json.dumps(vulns),
        }

    if name == "package.json":
        vulns, err = _run_npm_audit(path)
        if err:
            return {
                "file": str(path),
                "ecosystem": "node",
                "count": "0",
                "vulnerabilities": json.dumps([]),
                "error": err,
            }
        return {
            "file": str(path),
            "ecosystem": "node",
            "count": str(len(vulns)),
            "vulnerabilities": json.dumps(vulns),
        }

    return {
        "file": str(path),
        "ecosystem": "",
        "count": "0",
        "vulnerabilities": json.dumps([]),
        "error": "file must be named requirements.txt or package.json",
    }



# (regex, unsafe_pattern label, recommendation)
_VALIDATE_INPUT_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(
            r"(?i)(eval|exec)\s*\([^)]*"
            r"(request\.(POST|GET|args|form|params|data|body)|request\[|input\s*\()",
        ),
        "eval/exec may process user-controlled input",
        "Avoid dynamic code execution; validate input and use explicit parsing or APIs.",
    ),
    (
        re.compile(r"\.execute\s*\(\s*f[\"'][^\"']*\{[^}]*request"),
        "SQL f-string may embed request parameters",
        "Use parameterized queries; bind values with placeholders.",
    ),
    (
        re.compile(r"(?i)subprocess\.[a-z]+\([^)]*shell\s*=\s*True"),
        "subprocess with shell=True invokes a shell",
        "Use shell=False with a list of arguments; avoid shell metacharacters in user data.",
    ),
    (
        re.compile(
            r"(?i)subprocess\.[a-z]+\([^)]*(\+request|request\.(POST|GET|args)|f[\"'][^\"']*request)",
        ),
        "subprocess arguments may include request data",
        "Validate and allowlist commands and arguments; never pass raw user strings to subprocess.",
    ),
    (
        re.compile(r"(?i)os\.system\s*\([^)]*(request\.|request\[|\+|f[\"'])"),
        "os.system may build a shell command from user-influenced strings",
        "Use subprocess with shell=False and fixed argument lists.",
    ),
    (
        re.compile(r"(?i)pickle\.loads?\s*\([^)]*(request\.|\.read\s*\(\)|body)"),
        "pickle deserialization of untrusted data can execute arbitrary code",
        "Do not unpickle untrusted input; use JSON, msgpack, or explicit schemas.",
    ),
    (
        re.compile(r"(?i)\byaml\.load\s*\("),
        "yaml.load can construct arbitrary Python objects",
        "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader).",
    ),
    (
        re.compile(r"(?i)mark_safe\s*\(\s*(request\.|f[\"'])"),
        "mark_safe disables HTML escaping for possibly dynamic content",
        "Escape output by default; use mark_safe only for fully trusted static strings.",
    ),
    (
        re.compile(r"\.innerHTML\s*="),
        "DOM innerHTML assignment can lead to XSS",
        "Prefer textContent, or sanitize HTML with a vetted library.",
    ),
    (
        re.compile(r"(?i)open\s*\(\s*(request\.|os\.path\.join\s*\([^)]*request)"),
        "File path may derive from user input",
        "Resolve paths under a trusted root, reject .. traversal, and validate filenames.",
    ),
    (
        re.compile(
            r"(?i)(request\.(POST|GET|args|form)\[[^\]]+\]|request\.args\.get)\s*[^;\n]*\+\s*[\"']",
        ),
        "String concatenation building queries or commands from request values",
        "Use parameterized APIs and validation libraries instead of string building.",
    ),
)


def _validate_input_line(line: str, line_no: int) -> list[dict[str, str | int]]:
    out: list[dict[str, str | int]] = []
    for pattern, unsafe, rec in _VALIDATE_INPUT_RULES:
        if pattern.search(line):
            out.append(
                {
                    "unsafe_pattern": unsafe,
                    "recommendation": rec,
                    "line": line_no,
                }
            )
    return out


def validate_input(file_path: str = "", code: str = "") -> dict[str, str]:
    """Analyze how user input may be handled unsafely in source code.

    Supply either a readable file path or a code string. If both are given, the
    file is used when it exists; otherwise the code snippet is analyzed.

    Args:
        file_path: Path to a source file (optional).
        code: Raw source code to analyze (optional).

    Returns:
        Dictionary with source label, count, and JSON list of findings. Each item
        has unsafe_pattern, recommendation, and line.
    """
    fp = (file_path or "").strip()
    raw = (code or "").strip()

    if fp:
        path = Path(fp).expanduser().resolve()
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            source = str(path)
        elif raw:
            content = raw
            source = "snippet"
        else:
            return {
                "source": fp,
                "count": "0",
                "findings": json.dumps([]),
                "error": "file not found or not a file",
            }
    elif raw:
        content = raw
        source = "snippet"
    else:
        return {
            "source": "",
            "count": "0",
            "findings": json.dumps([]),
            "error": "provide file_path or code",
        }

    findings: list[dict[str, str | int]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        findings.extend(_validate_input_line(line, line_no))

    return {
        "source": source,
        "count": str(len(findings)),
        "findings": json.dumps(findings),
    }



def _normalize_dep_severity(sev: str) -> str:
    s = sev.strip().lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    if s == "moderate":
        return "medium"
    if s in ("unknown", ""):
        return "unknown"
    return "unknown"


def _secret_type_to_severity(secret_type: str) -> str:
    t = secret_type.lower()
    if t in ("api key", "token"):
        return "high"
    return "medium"


def _accumulate_severity(counts: dict[str, int], severity: str) -> None:
    if severity not in counts:
        severity = "unknown"
    counts[severity] += 1


def _security_score_from_counts(counts: dict[str, int]) -> int:
    """Higher score is better (100 = no issues)."""
    score = 100
    score -= counts.get("critical", 0) * 15
    score -= counts.get("high", 0) * 10
    score -= counts.get("medium", 0) * 5
    score -= counts.get("low", 0) * 2
    score -= counts.get("unknown", 0) * 3
    score -= counts.get("info", 0) * 1
    return max(0, min(100, score))


def security_summary(
    scan_secrets_json: str = "",
    analyze_code_security_json: str = "",
    check_dependencies_json: str = "",
    validate_input_json: str = "",
) -> dict[str, str]:
    """Combine outputs from security tools into a report with score and breakdown.

    Pass each parameter as a JSON string of that tool's full return dict (same
    shape as returned by scan_secrets, analyze_code_security, check_dependencies,
    and validate_input). Omitted or empty strings are treated as no findings.

    Args:
        scan_secrets_json: JSON string from scan_secrets.
        analyze_code_security_json: JSON string from analyze_code_security.
        check_dependencies_json: JSON string from check_dependencies.
        validate_input_json: JSON string from validate_input.

    Returns:
        Dictionary with summary text, severity_breakdown (JSON), security_score
        (0-100), total_issues, and optional error if JSON is invalid.
    """
    empty = (
        not (scan_secrets_json or "").strip()
        and not (analyze_code_security_json or "").strip()
        and not (check_dependencies_json or "").strip()
        and not (validate_input_json or "").strip()
    )
    if empty:
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }
        return {
            "summary": "No tool results provided. Pass JSON strings from scan_secrets, "
            "analyze_code_security, check_dependencies, and/or validate_input.",
            "severity_breakdown": json.dumps(breakdown),
            "security_score": "100",
            "total_issues": "0",
        }

    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    lines: list[str] = []
    total = 0

    def load(name: str, raw: str) -> dict | None:
        raw = (raw or "").strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    if scan_secrets_json.strip():
        data = load("scan_secrets", scan_secrets_json)
        if data is None:
            return {
                "summary": "",
                "severity_breakdown": json.dumps(counts),
                "security_score": "0",
                "total_issues": "0",
                "error": "invalid JSON in scan_secrets_json",
            }
        findings = data.get("findings", "[]")
        if isinstance(findings, str):
            try:
                items = json.loads(findings)
            except json.JSONDecodeError:
                items = []
        else:
            items = findings if isinstance(findings, list) else []
        n = len(items)
        total += n
        if n:
            lines.append(f"scan_secrets: {n} potential secret pattern(s).")
        for it in items:
            st = str(it.get("type", "unknown"))
            _accumulate_severity(counts, _secret_type_to_severity(st))

    if analyze_code_security_json.strip():
        data = load("analyze_code_security", analyze_code_security_json)
        if data is None:
            return {
                "summary": "",
                "severity_breakdown": json.dumps(counts),
                "security_score": "0",
                "total_issues": "0",
                "error": "invalid JSON in analyze_code_security_json",
            }
        findings = data.get("findings", "[]")
        if isinstance(findings, str):
            try:
                items = json.loads(findings)
            except json.JSONDecodeError:
                items = []
        else:
            items = findings if isinstance(findings, list) else []
        n = len(items)
        total += n
        if n:
            lines.append(f"analyze_code_security: {n} insecure pattern(s).")
        valid_sev = {"critical", "high", "medium", "low", "info", "unknown"}
        for it in items:
            sev = str(it.get("severity", "medium")).lower()
            if sev not in valid_sev:
                sev = "medium"
            _accumulate_severity(counts, sev)

    if check_dependencies_json.strip():
        data = load("check_dependencies", check_dependencies_json)
        if data is None:
            return {
                "summary": "",
                "severity_breakdown": json.dumps(counts),
                "security_score": "0",
                "total_issues": "0",
                "error": "invalid JSON in check_dependencies_json",
            }
        vulns = data.get("vulnerabilities", "[]")
        if isinstance(vulns, str):
            try:
                items = json.loads(vulns)
            except json.JSONDecodeError:
                items = []
        else:
            items = vulns if isinstance(vulns, list) else []
        n = len(items)
        total += n
        if n:
            lines.append(f"check_dependencies: {n} known vulnerability record(s).")
        for it in items:
            sev = _normalize_dep_severity(str(it.get("severity", "unknown")))
            _accumulate_severity(counts, sev)

    if validate_input_json.strip():
        data = load("validate_input", validate_input_json)
        if data is None:
            return {
                "summary": "",
                "severity_breakdown": json.dumps(counts),
                "security_score": "0",
                "total_issues": "0",
                "error": "invalid JSON in validate_input_json",
            }
        findings = data.get("findings", "[]")
        if isinstance(findings, str):
            try:
                items = json.loads(findings)
            except json.JSONDecodeError:
                items = []
        else:
            items = findings if isinstance(findings, list) else []
        n = len(items)
        total += n
        if n:
            lines.append(f"validate_input: {n} unsafe input handling pattern(s).")
        for _ in items:
            _accumulate_severity(counts, "medium")

    score = _security_score_from_counts(counts)
    summary_body = " ".join(lines) if lines else "No issues reported across provided tool outputs."
    summary = (
        f"Total issues counted: {total}. {summary_body} "
        f"Severity distribution is included in severity_breakdown. "
        f"Security score (100 = best): {score}."
    )

    return {
        "summary": summary,
        "severity_breakdown": json.dumps(counts),
        "security_score": str(score),
        "total_issues": str(total),
    }
