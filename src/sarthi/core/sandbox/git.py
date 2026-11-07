"""Sterile Git execution manager and policy boundary.

Enforces strict separation between Tier 1 (sterile read-only metadata queries)
and Tier 2 (repository modification operations requiring full OS sandboxing).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from sarthi.core.sandbox.exceptions import GitSecurityPolicyError

# Denied Git-specific and network proxy environment variables
DENIED_GIT_ENV_PREFIXES = ("GIT_",)
DENIED_PROXY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
)

# Standard Tier 1 configuration overrides
STERILE_CONFIG_OVERRIDES = [
    "-c", "core.hooksPath=",
    "-c", "core.fsmonitor=false",
    "-c", "diff.external=",
    "-c", "credential.helper=",
    "-c", "protocol.allow=never",
    "-c", "core.sshCommand=/bin/false",
]


class SterileGitExecutor:
    """Executes deterministic, read-only Git metadata queries under a sterile environment."""

    ALLOWED_SUBCOMMANDS = {
        "rev-parse",
        "status",
        "diff",
    }

    @staticmethod
    def is_tier1_allowed(subcommand: str, args: list[str]) -> bool:
        """Validates whether a Git command strictly adheres to the Tier 1 read-only allowlist."""
        if subcommand not in SterileGitExecutor.ALLOWED_SUBCOMMANDS:
            return False

        if subcommand == "rev-parse":
            # Only allow specific safe rev-parse queries
            allowed_rev_parse_args = {"--is-inside-work-tree", "HEAD"}
            return any(arg in allowed_rev_parse_args for arg in args) and not any(
                arg.startswith("--git-dir") for arg in args
            )

        if subcommand == "status":
            # Status must be porcelain
            return any("--porcelain" in arg for arg in args)

        if subcommand == "diff":
            # Diff must be name-only
            return "--name-only" in args

        return False

    @staticmethod
    def build_sterile_env(custom_home: Path | str | None = None) -> dict[str, str]:
        """Builds a sterile environment dictionary for Tier 1 Git execution."""
        env: dict[str, str] = {}
        for k, v in os.environ.items():
            k_upper = k.upper()
            if any(k_upper.startswith(prefix) for prefix in DENIED_GIT_ENV_PREFIXES):
                continue
            if k_upper in DENIED_PROXY_ENV:
                continue
            env[k] = v

        dev_null = "NUL" if os.name == "nt" else "/dev/null"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_SYSTEM"] = dev_null
        env["GIT_CONFIG_GLOBAL"] = dev_null

        if custom_home:
            env["HOME"] = str(Path(custom_home).resolve())
            env["USERPROFILE"] = str(Path(custom_home).resolve())

        return env

    @classmethod
    def run_tier1_query(
        cls,
        subcommand: str,
        query_args: list[str],
        cwd: Path | str,
        timeout: float = 5.0,
    ) -> subprocess.CompletedProcess[str]:
        """Executes an allowlisted Tier 1 metadata query with sterile configuration overrides.

        Raises:
            GitSecurityPolicyError: If the subcommand or arguments violate Tier 1 policy.
        """
        if not cls.is_tier1_allowed(subcommand, query_args):
            raise GitSecurityPolicyError(
                f"Disallowed Git invocation for Tier 1 metadata execution: git {subcommand} {' '.join(query_args)}"
            )

        cmd = ["git"]
        cmd.extend(STERILE_CONFIG_OVERRIDES)
        cmd.append("--no-pager")
        cmd.append(subcommand)

        # Normalize diff arguments with mandatory safety flags
        if subcommand == "diff":
            if "--no-ext-diff" not in query_args:
                cmd.append("--no-ext-diff")
            if "--no-textconv" not in query_args:
                cmd.append("--no-textconv")

        # Normalize status arguments
        if subcommand == "status":
            if "--no-renames" not in query_args:
                cmd.append("--no-renames")

        cmd.extend(query_args)

        with tempfile.TemporaryDirectory(prefix="sarthi_git_home_") as tmp_home:
            sterile_env = cls.build_sterile_env(custom_home=tmp_home)
            try:
                return subprocess.run(
                    cmd,
                    cwd=str(cwd),
                    env=sterile_env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=False,
                    check=False,
                )
            except subprocess.TimeoutExpired as e:
                raise GitSecurityPolicyError(f"Git Tier 1 metadata query timed out after {timeout}s: {cmd}") from e
            except Exception as e:
                raise GitSecurityPolicyError(f"Git Tier 1 execution failed: {e}") from e

