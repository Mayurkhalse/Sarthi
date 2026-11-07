"""Unit test suite for Sarthi OS-level sandbox core and fail-closed policy engine.

Validates policy contracts, capability reporting, fail-closed dispatching,
isolated workspace staging (hardlink decoupling, symlink traversal prevention,
special-file rejection), sterile Git Tier 1 execution, and cross-platform backends.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sarthi.core.models import ProjectConfig, RunContext
from sarthi.core.sandbox import (
    CapabilityStatus,
    FilesystemPolicy,
    GitSecurityPolicyError,
    MechanismMaturity,
    NetworkPolicy,
    ResourceLimits,
    SandboxCapabilityReport,
    SandboxCapabilityUnavailableError,
    SandboxError,
    SandboxExecutionError,
    SandboxInitializationError,
    SandboxManager,
    SandboxPolicy,
    SandboxResult,
    SandboxStagingError,
    StagedWorkspaceSecurityError,
    SterileGitExecutor,
    WorkspaceStagingManager,
)
from sarthi.core.sandbox.backends.linux import LinuxBubblewrapBackend
from sarthi.core.sandbox.backends.macos import MacOSSeatbeltBackend
from sarthi.core.sandbox.backends.null import NullSandboxBackend
from sarthi.core.sandbox.backends.windows import WindowsAppContainerBackend
from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.verify.runners.tests import TestRunner
from sarthi.core.verify.trust import CommandTrustManager


# ==============================================================================
# 1. Policy & Multi-Dimensional Capability Reporting Tests
# ==============================================================================


def test_sandbox_policy_defaults() -> None:
    """Verifies default_strict() policy enforces maximum security defaults."""
    policy = SandboxPolicy.default_strict()
    assert policy.network == NetworkPolicy.BLOCKED
    assert policy.filesystem == FilesystemPolicy.STAGED_ISOLATED
    assert not policy.allow_deprecated_mechanisms
    assert policy.limits.max_memory_bytes == 1024 * 1024 * 1024
    assert policy.limits.max_processes == 64
    assert policy.limits.timeout_seconds == 60.0


def test_capability_report_production_certified_pass() -> None:
    """Verifies is_production_certified is True ONLY when all required capabilities PASS under PRODUCTION maturity."""
    report = SandboxCapabilityReport(
        backend_name="test_backend",
        mechanism_maturity=MechanismMaturity.PRODUCTION,
        filesystem_isolation=CapabilityStatus.PASS,
        network_isolation=CapabilityStatus.PASS,
        process_isolation=CapabilityStatus.PASS,
        environment_isolation=CapabilityStatus.PASS,
        resource_enforcement=CapabilityStatus.PASS,
        workspace_confinement=CapabilityStatus.PASS,
        child_process_inheritance=CapabilityStatus.PASS,
    )
    assert report.is_production_certified is True
    assert report.is_capable_of("filesystem_isolation") is True


def test_capability_report_deprecated_mechanism_cannot_certify() -> None:
    """Verifies a DEPRECATED mechanism can NEVER receive production certification even if all capabilities PASS."""
    report = SandboxCapabilityReport(
        backend_name="macos_seatbelt",
        mechanism_maturity=MechanismMaturity.DEPRECATED,
        filesystem_isolation=CapabilityStatus.PASS,
        network_isolation=CapabilityStatus.PASS,
        process_isolation=CapabilityStatus.PASS,
        environment_isolation=CapabilityStatus.PASS,
        resource_enforcement=CapabilityStatus.PASS,
        workspace_confinement=CapabilityStatus.PASS,
        child_process_inheritance=CapabilityStatus.PASS,
    )
    assert report.is_production_certified is False


def test_capability_report_missing_capability_cannot_certify() -> None:
    """Verifies is_production_certified is False if any required capability is UNSUPPORTED."""
    report = SandboxCapabilityReport(
        backend_name="linux_bubblewrap",
        mechanism_maturity=MechanismMaturity.PRODUCTION,
        filesystem_isolation=CapabilityStatus.PASS,
        network_isolation=CapabilityStatus.UNSUPPORTED,  # Network isolation missing
        process_isolation=CapabilityStatus.PASS,
        environment_isolation=CapabilityStatus.PASS,
        resource_enforcement=CapabilityStatus.PASS,
        workspace_confinement=CapabilityStatus.PASS,
        child_process_inheritance=CapabilityStatus.PASS,
    )
    assert report.is_production_certified is False


# ==============================================================================
# 2. Null Backend & Fail-Closed Dispatching Tests
# ==============================================================================


def test_null_backend_fails_closed_on_initialize(tmp_path: Path) -> None:
    """Verifies NullSandboxBackend raises SandboxCapabilityUnavailableError on initialize()."""
    backend = NullSandboxBackend()
    report = backend.detect_capabilities(tmp_path)
    assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
    assert report.network_isolation == CapabilityStatus.UNSUPPORTED
    assert report.mechanism_maturity == MechanismMaturity.LEGACY_UNSUPPORTED

    with pytest.raises(SandboxCapabilityUnavailableError):
        backend.initialize(SandboxPolicy.default_strict(), tmp_path)


def test_null_backend_fails_closed_on_run(tmp_path: Path) -> None:
    """Verifies NullSandboxBackend raises SandboxCapabilityUnavailableError on run()."""
    backend = NullSandboxBackend()
    with pytest.raises(SandboxCapabilityUnavailableError):
        backend.run(["echo", "hello"], SandboxPolicy.default_strict(), tmp_path)


def test_sandbox_manager_fails_closed_with_null_backend(tmp_path: Path) -> None:
    """Verifies SandboxManager fails closed when backed by NullSandboxBackend."""
    mgr = SandboxManager(backend=NullSandboxBackend())
    with pytest.raises(SandboxCapabilityUnavailableError):
        mgr.run(["python", "-c", "print(1)"], tmp_path)


def test_sandbox_manager_rejects_deprecated_mechanism_by_default(tmp_path: Path) -> None:
    """Verifies SandboxManager rejects DEPRECATED backend unless explicitly permitted."""
    mock_backend = MagicMock(spec=BaseSandboxBackend)
    mock_backend.name = "mock_deprecated"
    mock_backend.maturity = MechanismMaturity.DEPRECATED
    mock_backend.detect_capabilities.return_value = SandboxCapabilityReport(
        backend_name="mock_deprecated",
        mechanism_maturity=MechanismMaturity.DEPRECATED,
        filesystem_isolation=CapabilityStatus.PASS,
        network_isolation=CapabilityStatus.PASS,
        process_isolation=CapabilityStatus.PASS,
        environment_isolation=CapabilityStatus.PASS,
        resource_enforcement=CapabilityStatus.PASS,
        workspace_confinement=CapabilityStatus.PASS,
        child_process_inheritance=CapabilityStatus.PASS,
    )

    mgr = SandboxManager(backend=mock_backend)
    # Default strict policy has allow_deprecated_mechanisms=False
    with pytest.raises(SandboxCapabilityUnavailableError, match="vendor-deprecated"):
        mgr.run(["echo", "test"], tmp_path, policy=SandboxPolicy.default_strict())


def test_sandbox_manager_ensures_cleanup_called_on_failure(tmp_path: Path) -> None:
    """Verifies backend.cleanup() is always invoked even when backend.run() raises."""
    mock_backend = MagicMock(spec=BaseSandboxBackend)
    mock_backend.name = "mock_backend"
    mock_backend.maturity = MechanismMaturity.PRODUCTION
    mock_backend.detect_capabilities.return_value = SandboxCapabilityReport(
        backend_name="mock_backend",
        mechanism_maturity=MechanismMaturity.PRODUCTION,
        filesystem_isolation=CapabilityStatus.PASS,
        network_isolation=CapabilityStatus.PASS,
        process_isolation=CapabilityStatus.PASS,
        environment_isolation=CapabilityStatus.PASS,
        resource_enforcement=CapabilityStatus.PASS,
        workspace_confinement=CapabilityStatus.PASS,
        child_process_inheritance=CapabilityStatus.PASS,
    )
    mock_backend.run.side_effect = SandboxExecutionError("Execution crashed")

    mgr = SandboxManager(backend=mock_backend)
    policy = SandboxPolicy(filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE)

    with pytest.raises(SandboxExecutionError, match="Execution crashed"):
        mgr.run(["fail_cmd"], tmp_path, policy=policy)

    assert mock_backend.cleanup.called is True


# ==============================================================================
# 3. Workspace Staging & Inode Decoupling Tests
# ==============================================================================


def test_staging_copies_regular_files_and_allocates_fresh_inodes(tmp_path: Path) -> None:
    """Verifies staging copies files by value, ensuring fresh inodes (decoupling hardlinks)."""
    source_dir = tmp_path / "source_repo"
    source_dir.mkdir()
    file1 = source_dir / "app.py"
    file1.write_text("print('hello')", encoding="utf-8")
    sub_dir = source_dir / "pkg"
    sub_dir.mkdir()
    file2 = sub_dir / "mod.py"
    file2.write_text("X = 1", encoding="utf-8")

    mgr = WorkspaceStagingManager(source_dir)
    with mgr as staged_dir:
        assert staged_dir.is_dir()
        staged_file1 = staged_dir / "app.py"
        staged_file2 = staged_dir / "pkg" / "mod.py"

        assert staged_file1.is_file()
        assert staged_file2.is_file()
        assert staged_file1.read_text(encoding="utf-8") == "print('hello')"

        # Inode verification: On filesystems supporting inodes, regular file copy
        # creates a distinct inode number, severing external hardlink sharing
        src_stat = file1.stat()
        staged_stat = staged_file1.stat()
        if hasattr(src_stat, "st_ino") and hasattr(staged_stat, "st_ino"):
            assert src_stat.st_ino != staged_stat.st_ino, "Staged file must have independent inode"

    # Verify cleanup purged staged tree
    assert not staged_dir.exists()


def test_staging_preserves_internal_relative_symlinks(tmp_path: Path) -> None:
    """Verifies safe relative symlinks strictly within the workspace boundary are preserved."""
    source_dir = tmp_path / "sym_repo"
    source_dir.mkdir()
    target_file = source_dir / "target.txt"
    target_file.write_text("target data", encoding="utf-8")

    link_file = source_dir / "link_to_target.txt"
    try:
        os.symlink("target.txt", link_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege context.")

    with WorkspaceStagingManager(source_dir) as staged_dir:
        staged_link = staged_dir / "link_to_target.txt"
        assert staged_link.is_symlink()
        assert staged_link.read_text(encoding="utf-8") == "target data"


def test_staging_rejects_escaping_symlink(tmp_path: Path) -> None:
    """Verifies symlinks pointing outside the workspace boundary cause immediate failure."""
    outside_file = tmp_path / "secret.key"
    outside_file.write_text("super-secret", encoding="utf-8")

    source_dir = tmp_path / "malicious_repo"
    source_dir.mkdir()
    escaping_link = source_dir / "escape_link.txt"

    try:
        # Relative link pointing outside source_dir
        os.symlink("../secret.key", escaping_link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege context.")

    mgr = WorkspaceStagingManager(source_dir)
    with pytest.raises(StagedWorkspaceSecurityError, match="Symlink traversal detected"):
        mgr.stage()


def test_staging_rejects_absolute_symlink(tmp_path: Path) -> None:
    """Verifies absolute symlinks targeting host paths are rejected."""
    source_dir = tmp_path / "abs_repo"
    source_dir.mkdir()
    abs_link = source_dir / "abs_link.txt"

    try:
        abs_target = str(tmp_path.resolve())
        os.symlink(abs_target, abs_link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege context.")

    mgr = WorkspaceStagingManager(source_dir)
    with pytest.raises(StagedWorkspaceSecurityError, match="Absolute symlink forbidden"):
        mgr.stage()


def test_staging_rejects_special_file_fifo(tmp_path: Path) -> None:
    """Verifies FIFOs / named pipes in the repository are rejected fail-closed."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("Named pipes (mkfifo) not supported on this OS.")

    source_dir = tmp_path / "fifo_repo"
    source_dir.mkdir()
    fifo_path = source_dir / "test_fifo"

    try:
        os.mkfifo(fifo_path)
    except Exception:
        pytest.skip("mkfifo failed or permission denied.")

    mgr = WorkspaceStagingManager(source_dir)
    with pytest.raises(StagedWorkspaceSecurityError, match="FIFO/named pipe"):
        mgr.stage()


def test_staging_cleans_up_on_failure(tmp_path: Path) -> None:
    """Verifies partial staging directories are purged when staging aborts due to an error."""
    source_dir = tmp_path / "fail_repo"
    source_dir.mkdir()
    (source_dir / "file.txt").write_text("content", encoding="utf-8")
    abs_link = source_dir / "bad_link"

    try:
        os.symlink(str(tmp_path.resolve()), abs_link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform.")

    mgr = WorkspaceStagingManager(source_dir, base_staging_dir=tmp_path)
    with pytest.raises(StagedWorkspaceSecurityError):
        mgr.stage()

    # Verify no orphan staging directory remains in base_staging_dir
    staged_dirs = list(tmp_path.glob("sarthi_staged_*"))
    assert len(staged_dirs) == 0, f"Found orphan staging directories: {staged_dirs}"


# ==============================================================================
# 4. Sterile Git Tier 1 Execution Tests
# ==============================================================================


def test_sterile_git_allows_tier1_subcommands() -> None:
    """Verifies Tier 1 allowlist accepts valid read-only metadata queries."""
    assert SterileGitExecutor.is_tier1_allowed("rev-parse", ["--is-inside-work-tree"]) is True
    assert SterileGitExecutor.is_tier1_allowed("rev-parse", ["HEAD"]) is True
    assert SterileGitExecutor.is_tier1_allowed("status", ["--porcelain"]) is True
    assert SterileGitExecutor.is_tier1_allowed("diff", ["--name-only", "HEAD"]) is True


def test_sterile_git_rejects_tier2_and_arbitrary_subcommands() -> None:
    """Verifies Tier 1 rejects modification operations (Tier 2 operations)."""
    assert SterileGitExecutor.is_tier1_allowed("checkout", ["main"]) is False
    assert SterileGitExecutor.is_tier1_allowed("merge", ["feature"]) is False
    assert SterileGitExecutor.is_tier1_allowed("pull", []) is False
    assert SterileGitExecutor.is_tier1_allowed("clone", ["http://evil.com"]) is False
    assert SterileGitExecutor.is_tier1_allowed("commit", ["-m", "msg"]) is False
    assert SterileGitExecutor.is_tier1_allowed("config", ["--list"]) is False
    assert SterileGitExecutor.is_tier1_allowed("reset", ["--hard"]) is False


def test_sterile_git_rejects_disallowed_invocation(tmp_path: Path) -> None:
    """Verifies run_tier1_query raises GitSecurityPolicyError for un-allowlisted operations."""
    with pytest.raises(GitSecurityPolicyError, match="Disallowed Git invocation"):
        SterileGitExecutor.run_tier1_query("checkout", ["HEAD~1"], cwd=tmp_path)


def test_sterile_git_environment_sanitization() -> None:
    """Verifies build_sterile_env strips GIT_* variables, proxies, and sets sterile config overrides."""
    os.environ["GIT_DIR"] = "/tmp/fake_git"
    os.environ["GIT_EXEC_PATH"] = "/tmp/evil_bin"
    os.environ["HTTP_PROXY"] = "http://evil-proxy:8080"
    try:
        env = SterileGitExecutor.build_sterile_env(custom_home="/tmp/isolated_home")
        assert "GIT_DIR" not in env
        assert "GIT_EXEC_PATH" not in env
        assert "HTTP_PROXY" not in env
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_SYSTEM"] in ("/dev/null", "NUL")
        assert env["GIT_CONFIG_GLOBAL"] in ("/dev/null", "NUL")
    finally:
        os.environ.pop("GIT_DIR", None)
        os.environ.pop("GIT_EXEC_PATH", None)
        os.environ.pop("HTTP_PROXY", None)


# ==============================================================================
# 5. Cross-Platform Backend Adapter Behavior Tests
# ==============================================================================


def test_macos_backend_reports_deprecated(tmp_path: Path) -> None:
    """Verifies MacOSSeatbeltBackend always reports MechanismMaturity.DEPRECATED."""
    backend = MacOSSeatbeltBackend()
    assert backend.maturity == MechanismMaturity.DEPRECATED
    report = backend.detect_capabilities(tmp_path)
    assert report.mechanism_maturity == MechanismMaturity.DEPRECATED
    assert report.is_production_certified is False


def test_linux_backend_non_linux_host_reports_unsupported(tmp_path: Path) -> None:
    """Verifies LinuxBubblewrapBackend returns UNSUPPORTED on non-Linux platforms."""
    backend = LinuxBubblewrapBackend(bwrap_path="/nonexistent/bwrap")
    if not sys.platform.startswith("linux"):
        report = backend.detect_capabilities(tmp_path)
        assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
        assert report.network_isolation == CapabilityStatus.UNSUPPORTED


def test_windows_backend_non_windows_host_reports_unsupported(tmp_path: Path) -> None:
    """Verifies WindowsAppContainerBackend returns UNSUPPORTED on non-Windows platforms."""
    backend = WindowsAppContainerBackend()
    if sys.platform != "win32":
        report = backend.detect_capabilities(tmp_path)
        assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
        assert report.network_isolation == CapabilityStatus.UNSUPPORTED


# ==============================================================================
# 6. TestRunner Integration Tests
# ==============================================================================


def test_test_runner_with_sandbox_manager_error_handling(tmp_path: Path) -> None:
    """Verifies TestRunner gracefully converts SandboxError into structured High severity Finding."""
    mock_mgr = MagicMock(spec=SandboxManager)
    mock_mgr.run.side_effect = SandboxCapabilityUnavailableError("Linux namespaces not supported")

    trust_mgr = MagicMock(spec=CommandTrustManager)
    runner = TestRunner(trust_mgr=trust_mgr, sandbox_mgr=mock_mgr)

    ctx = RunContext(
        project_root=tmp_path,
        config=ProjectConfig(project_name="sandbox_test"),
    )

    findings = runner.run(ctx, [])
    assert len(findings) == 1
    assert "Sandbox isolation error" in findings[0].message
    assert "Linux namespaces not supported" in findings[0].message

