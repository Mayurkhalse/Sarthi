from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from sarthi.core.models import Finding, RunContext, Severity
from sarthi.core.sandbox.exceptions import SandboxError
from sarthi.core.sandbox.manager import SandboxManager
from sarthi.core.verify.runners.base import Runner
from sarthi.core.verify.trust import (
    CommandTrustError,
    CommandTrustManager,
    build_sanitized_subprocess_env,
    parse_and_validate_command,
)


class TestRunner(Runner):
    """Executes test suites (pytest, npm test, etc.) and reports test failures."""

    __test__ = False

    def __init__(
        self,
        trust_mgr: CommandTrustManager | None = None,
        sandbox_mgr: SandboxManager | None = None,
    ) -> None:
        self.trust_mgr = trust_mgr or CommandTrustManager()
        self.sandbox_mgr = sandbox_mgr

    @property
    def name(self) -> str:
        return "tests"

    @property
    def required(self) -> bool:
        return True

    def has_test_suite(self, ctx: RunContext) -> bool:
        """Checks if the project has configured or detected tests."""
        if ctx.config.verify.commands.get("test"):
            return True
        if sys.platform == "win32":
            venv_pytest = ctx.project_root / ".venv" / "Scripts" / "pytest.exe"
        else:
            venv_pytest = ctx.project_root / ".venv" / "bin" / "pytest"
        if venv_pytest.is_file():
            return True
        if any(ctx.project_root.glob("test_*.py")) or any(ctx.project_root.glob("*_test.py")):
            return True
        if (ctx.project_root / "tests").is_dir():
            return True
        if (ctx.project_root / "pytest.ini").is_file() or (ctx.project_root / "conftest.py").is_file():
            return True
        pkg_json = ctx.project_root / "package.json"
        if pkg_json.is_file():
            return True
        return False

    def _detect_default_command(self, ctx: RunContext) -> list[str] | None:
        """Detects standard framework test runners from project layout."""
        # 1. Python pytest
        if sys.platform == "win32":
            venv_pytest = ctx.project_root / ".venv" / "Scripts" / "pytest.exe"
        else:
            venv_pytest = ctx.project_root / ".venv" / "bin" / "pytest"

        if venv_pytest.is_file():
            return [str(venv_pytest), "-q"]
        if shutil.which("pytest") and (
            any(ctx.project_root.glob("test_*.py"))
            or any(ctx.project_root.glob("*_test.py"))
            or (ctx.project_root / "tests").is_dir()
            or (ctx.project_root / "pytest.ini").is_file()
            or (ctx.project_root / "conftest.py").is_file()
        ):
            return ["pytest", "-q"]

        # 2. Node npm test
        pkg_json = ctx.project_root / "package.json"
        if pkg_json.is_file() and shutil.which("npm"):
            return ["npm", "test", "--", "--watchAll=false"]

        return None

    def check_trust(self, ctx: RunContext) -> tuple[bool, str | None]:
        """Validates that ANY test command execution (custom or auto-detected default)

        is allowlisted and explicitly approved by the user.

        Allowlisted tools (npm, mvn, gradle, pytest) run repo code by design;
        user approval is the real security boundary.
        """
        custom_cmd = ctx.config.verify.commands.get("test")
        if custom_cmd:
            try:
                parse_and_validate_command(custom_cmd, project_root=ctx.project_root)
            except CommandTrustError as e:
                return False, f"Custom command rejected: {e}"

            if not self.trust_mgr.is_approved(ctx.project_root, ctx.config.verify.commands):
                return False, (
                    f"Custom test command '{custom_cmd}' from .sarthi/project.yaml is untrusted/unapproved. "
                    f"Run 'sarthi approve \"{ctx.project_root}\"' to review and approve execution."
                )
            return True, None

        # Auto-detected default test command
        default_cmd = self._detect_default_command(ctx)
        if not default_cmd:
            return True, None

        cmd_str = " ".join(default_cmd)
        if not self.trust_mgr.is_approved(ctx.project_root, {"test": cmd_str}):
            return False, (
                f"Project test execution ('{cmd_str}') is unapproved. "
                f"Allowlisted test tools execute repository code by design. "
                f"Run 'sarthi approve \"{ctx.project_root}\"' to review and approve execution."
            )

        return True, None

    def _resolve_command(self, ctx: RunContext) -> list[str] | None:
        trusted, _ = self.check_trust(ctx)
        if not trusted:
            return None

        custom_cmd = ctx.config.verify.commands.get("test")
        if custom_cmd:
            try:
                return parse_and_validate_command(custom_cmd, project_root=ctx.project_root)
            except CommandTrustError:
                return None

        return self._detect_default_command(ctx)

    def available(self, ctx: RunContext) -> bool:
        return self._resolve_command(ctx) is not None

    def run(self, ctx: RunContext, files: list[Path]) -> list[Finding]:
        cmd = self._resolve_command(ctx)
        if not cmd:
            return []

        findings: list[Finding] = []
        safe_env = build_sanitized_subprocess_env(ctx.project_root)
        try:
            if self.sandbox_mgr is not None:
                sandbox_res = self.sandbox_mgr.run(cmd, ctx.project_root, custom_env=safe_env)
                returncode = sandbox_res.exit_code
                summary = (sandbox_res.stderr.strip() or sandbox_res.stdout.strip())
                timed_out = sandbox_res.timed_out
            else:
                res = subprocess.run(
                    cmd,
                    cwd=str(ctx.project_root),
                    env=safe_env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    shell=False,
                )
                returncode = res.returncode
                summary = (res.stderr.strip() or res.stdout.strip())
                timed_out = False

            if timed_out:
                raise subprocess.TimeoutExpired(cmd, 60)

            if returncode != 0:
                last_lines = "\n".join(summary.splitlines()[-6:]) if summary else "Tests exited with error"
                findings.append(
                    Finding(
                        rule_id="UNI-TEST-001",
                        severity=Severity.HIGH,
                        file="tests",
                        line=0,
                        message=f"Test suite failed:\n{last_lines}",
                        recommendation="Fix failing unit or integration tests before declaring task complete.",
                        verifier=self.name,
                        fix_hint=f"Execute '{' '.join(cmd)}' locally to inspect test output.",
                    )
                )
        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    rule_id="UNI-TEST-001",
                    severity=Severity.HIGH,
                    file="tests",
                    line=0,
                    message="Test suite execution timed out after 60 seconds.",
                    recommendation="Ensure tests terminate promptly and do not hang waiting on external I/O.",
                    verifier=self.name,
                    fix_hint="Check for infinite loops or blocked network calls in test code.",
                )
            )
        except SandboxError as e:
            findings.append(
                Finding(
                    rule_id="UNI-TEST-001",
                    severity=Severity.HIGH,
                    file="tests",
                    line=0,
                    message=f"Sandbox isolation error: {e}",
                    recommendation="Ensure sandbox environment and required OS capabilities are available.",
                    verifier=self.name,
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="UNI-TEST-001",
                    severity=Severity.HIGH,
                    file="tests",
                    line=0,
                    message=f"Error running test suite: {e}",
                    recommendation="Ensure test framework and dependencies are installed.",
                    verifier=self.name,
                )
            )

        return findings
