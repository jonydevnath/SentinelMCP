"""Tests for MCP server tools."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from SentinelMCP.tools import (
    analyze_code_security,
    check_dependencies,
    scan_secrets,
    security_summary,
    validate_input,
)


class TestScanSecrets:
    """Tests for scan_secrets tool."""

    def test_invalid_path(self, tmp_path: Path):
        missing = tmp_path / "nope"
        result = scan_secrets(str(missing))
        assert result["count"] == "0"
        assert result["error"] == "path is not a directory"
        assert json.loads(result["findings"]) == []

    def test_finds_api_key_pattern(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n',
            encoding="utf-8",
        )
        result = scan_secrets(str(tmp_path))
        findings = json.loads(result["findings"])
        assert len(findings) >= 1
        assert findings[0]["file"] == "app.py"
        assert findings[0]["line"] == 1
        assert findings[0]["type"] == "API key"

    def test_finds_password_assignment(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'db_password = "SuperSecretValue123"\n',
            encoding="utf-8",
        )
        result = scan_secrets(str(tmp_path))
        findings = json.loads(result["findings"])
        assert any(f["type"] == "password" for f in findings)

    def test_skips_node_modules(self, tmp_path: Path):
        bad = tmp_path / "node_modules" / "pkg" / "x.py"
        bad.parent.mkdir(parents=True)
        bad.write_text('api_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n', encoding="utf-8")
        result = scan_secrets(str(tmp_path))
        assert json.loads(result["findings"]) == []

    def test_returns_project_path_on_success(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        result = scan_secrets(str(tmp_path))
        assert "project" in result
        assert str(tmp_path.resolve()) in result["project"]
        assert "error" not in result


class TestAnalyzeCodeSecurity:
    """Tests for analyze_code_security tool."""

    def test_requires_input(self):
        result = analyze_code_security()
        assert result["error"] == "provide file_path or code"
        assert json.loads(result["findings"]) == []

    def test_missing_file(self):
        result = analyze_code_security(file_path="/nonexistent/nope.py")
        assert result["error"] == "file not found or not a file"

    def test_detects_eval(self):
        result = analyze_code_security(code="x = eval(user_input)\n")
        findings = json.loads(result["findings"])
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Unsafe eval"
        assert findings[0]["severity"] == "high"
        assert "line" in findings[0]

    def test_detects_sql_fstring(self):
        result = analyze_code_security(code='cur.execute(f"SELECT * FROM u WHERE id={x}")\n')
        findings = json.loads(result["findings"])
        assert any(f["issue_type"] == "SQL injection risk" for f in findings)

    def test_detects_hardcoded_credential(self):
        result = analyze_code_security(code='KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n')
        findings = json.loads(result["findings"])
        assert any(f["issue_type"] == "Hardcoded credential" for f in findings)

    def test_analyzes_file(self, tmp_path: Path):
        p = tmp_path / "bad.py"
        p.write_text("exec(code)\n", encoding="utf-8")
        result = analyze_code_security(file_path=str(p))
        assert result["source"] == str(p.resolve())
        findings = json.loads(result["findings"])
        assert findings[0]["issue_type"] == "Unsafe exec"


class TestCheckDependencies:
    """Tests for check_dependencies tool."""

    def test_requires_path(self):
        result = check_dependencies("")
        assert result.get("error") == "provide dep_file_path to requirements.txt or package.json"

    def test_wrong_filename(self, tmp_path: Path):
        p = tmp_path / "deps.txt"
        p.write_text("x", encoding="utf-8")
        result = check_dependencies(str(p))
        assert "requirements.txt or package.json" in result.get("error", "")

    def test_missing_file(self):
        result = check_dependencies("/nonexistent/requirements.txt")
        assert result["error"] == "file not found or not a file"

    @patch("SentinelMCP.tools.subprocess.run")
    def test_pip_audit_parses_vulnerabilities(self, mock_run, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.0.0\n", encoding="utf-8")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=json.dumps(
                {
                    "dependencies": [
                        {
                            "name": "requests",
                            "version": "2.0.0",
                            "vulns": [{"id": "GHSA-test", "fix_versions": ["2.31.0"]}],
                        }
                    ],
                    "fixes": [],
                }
            ),
            stderr="",
        )
        result = check_dependencies(str(req))
        assert result["ecosystem"] == "python"
        vulns = json.loads(result["vulnerabilities"])
        assert len(vulns) == 1
        assert vulns[0]["package"] == "requests"
        assert vulns[0]["severity"] == "unknown"
        assert vulns[0]["source"] == "pip-audit"

    @patch("SentinelMCP.tools.subprocess.run")
    def test_pip_audit_no_vulnerabilities(self, mock_run, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.31.0\n", encoding="utf-8")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"dependencies": [], "fixes": []}),
            stderr="",
        )
        result = check_dependencies(str(req))
        assert result["ecosystem"] == "python"
        assert result["count"] == "0"
        assert json.loads(result["vulnerabilities"]) == []

    @patch("SentinelMCP.tools.subprocess.run")
    def test_npm_audit_parses_vulnerabilities(self, mock_run, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"name":"x"}\n', encoding="utf-8")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=json.dumps(
                {
                    "vulnerabilities": {
                        "lodash": {
                            "name": "lodash",
                            "severity": "high",
                            "via": [
                                {
                                    "title": "Prototype Pollution",
                                    "severity": "high",
                                }
                            ],
                        }
                    }
                }
            ),
            stderr="",
        )
        result = check_dependencies(str(pkg))
        assert result["ecosystem"] == "node"
        vulns = json.loads(result["vulnerabilities"])
        assert vulns[0]["package"] == "lodash"
        assert vulns[0]["severity"] == "high"


class TestValidateInput:
    """Tests for validate_input tool."""

    def test_requires_input(self):
        result = validate_input()
        assert result["error"] == "provide file_path or code"
        assert json.loads(result["findings"]) == []

    def test_detects_eval_with_request(self):
        result = validate_input(code="y = eval(request.POST['q'])\n")
        findings = json.loads(result["findings"])
        assert len(findings) >= 1
        assert "eval" in findings[0]["unsafe_pattern"].lower()
        assert "recommendation" in findings[0]

    def test_detects_subprocess_shell_true(self):
        result = validate_input(code="subprocess.call(cmd, shell=True)\n")
        findings = json.loads(result["findings"])
        assert any("shell=True" in f["unsafe_pattern"] for f in findings)

    def test_detects_yaml_load(self):
        result = validate_input(code="data = yaml.load(stream)\n")
        findings = json.loads(result["findings"])
        assert any("yaml.load" in f["unsafe_pattern"] for f in findings)

    def test_analyzes_file(self, tmp_path: Path):
        p = tmp_path / "views.py"
        p.write_text("x = request.POST['id'] + ' AND 1=1'\n", encoding="utf-8")
        result = validate_input(file_path=str(p))
        assert result["source"] == str(p.resolve())
        findings = json.loads(result["findings"])
        assert len(findings) >= 1


class TestSecuritySummary:
    """Tests for security_summary tool."""

    def test_empty_inputs(self):
        result = security_summary()
        assert result["security_score"] == "100"
        assert result["total_issues"] == "0"
        assert json.loads(result["severity_breakdown"])["high"] == 0

    def test_combines_findings_and_score(self):
        scan = json.dumps(
            {
                "project": "/x",
                "count": "1",
                "findings": json.dumps(
                    [{"file": "a.py", "line": 1, "type": "API key"}]
                ),
            }
        )
        acs = json.dumps(
            {
                "source": "snippet",
                "count": "1",
                "findings": json.dumps(
                    [
                        {
                            "issue_type": "Unsafe eval",
                            "severity": "high",
                            "explanation": "x",
                            "suggested_fix": "y",
                            "line": 1,
                        }
                    ]
                ),
            }
        )
        result = security_summary(
            scan_secrets_json=scan,
            analyze_code_security_json=acs,
        )
        assert int(result["total_issues"]) == 2
        bd = json.loads(result["severity_breakdown"])
        assert bd["high"] >= 2
        assert int(result["security_score"]) < 100

    def test_invalid_json(self):
        result = security_summary(scan_secrets_json="not json")
        assert "error" in result

    def test_includes_all_four_tools(self):
        scan = json.dumps({
            "project": "/x",
            "count": "1",
            "findings": json.dumps([{"file": "a.py", "line": 1, "type": "password"}]),
        })
        acs = json.dumps({
            "source": "x",
            "count": "1",
            "findings": json.dumps([
                {"issue_type": "SQL injection risk", "severity": "medium", "line": 1},
            ]),
        })
        cd = json.dumps({
            "file": "/x/requirements.txt",
            "ecosystem": "python",
            "count": "1",
            "vulnerabilities": json.dumps([
                {"package": "foo", "severity": "high", "source": "pip-audit"},
            ]),
        })
        vi = json.dumps({
            "source": "x",
            "count": "1",
            "findings": json.dumps([
                {"unsafe_pattern": "subprocess shell", "recommendation": "x", "line": 1},
            ]),
        })
        result = security_summary(
            scan_secrets_json=scan,
            analyze_code_security_json=acs,
            check_dependencies_json=cd,
            validate_input_json=vi,
        )
        assert int(result["total_issues"]) == 4
        bd = json.loads(result["severity_breakdown"])
        assert bd["high"] >= 1
        assert bd["medium"] >= 2
        assert int(result["security_score"]) < 100
