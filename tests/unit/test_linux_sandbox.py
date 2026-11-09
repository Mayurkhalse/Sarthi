"""Unit tests for Linux Bubblewrap and cgroup v2 sandbox backend.

Tests verify LinuxBubblewrapBackend configuration, runtime mount table generation,
capability probing, fail-closed isolation contracts, and CgroupV2Manager lifecycle.
All tests run cross-platform by mocking OS-specific kernel interfaces.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sarthi.core.sandbox.backends.cgroup import CgroupV2Manager
from sarthi.core.sandbox.backends.linux import LinuxBubblewrapBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxCleanupError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    FilesystemPolicy,
    MechanismMaturity,
    NetworkPolicy,
    ResourceLimits,
    SandboxPolicy,
)
from sarthi.core.sandbox.result import SandboxCapabilityReport


def test_linux_backend_is_available_on_current_host() -> None:
    """Verifies is_available() reflects whether host is Linux with bwrap installed."""
    backend = LinuxBubblewrapBackend()
    if not sys.platform.startswith("linux"):
        assert backend.is_available() is False
    else:
        # On Linux, reflects presence of bwrap
        assert isinstance(backend.is_available(), bool)


def test_linux_backend_reports_unsupported_on_non_linux(tmp_path: Path) -> None:
    """Verifies all capabilities report UNSUPPORTED when not running on Linux."""
    with patch("sys.platform", "win32"):
        backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
        report = backend.detect_capabilities(tmp_path)
        assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
        assert report.network_isolation == CapabilityStatus.UNSUPPORTED
        assert report.process_isolation == CapabilityStatus.UNSUPPORTED
        assert report.process_count_enforcement == CapabilityStatus.UNSUPPORTED
        assert report.resource_enforcement == CapabilityStatus.UNSUPPORTED
        assert report.environment_isolation == CapabilityStatus.UNSUPPORTED
        assert report.workspace_confinement == CapabilityStatus.UNSUPPORTED
        assert report.child_process_inheritance == CapabilityStatus.UNSUPPORTED
        assert report.is_production_certified is False
        assert "Not running on Linux." in report.evidence_trace[0]


def test_linux_backend_reports_unsupported_when_bwrap_missing(tmp_path: Path) -> None:
    """Verifies fail-closed reporting when bwrap executable does not exist."""
    with patch("sys.platform", "linux"):
        backend = LinuxBubblewrapBackend(bwrap_path="/nonexistent/path/to/bwrap")
        report = backend.detect_capabilities(tmp_path)
        assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
        assert report.network_isolation == CapabilityStatus.UNSUPPORTED
        assert report.mechanism_maturity == MechanismMaturity.IMPLEMENTATION_PENDING
        assert report.is_production_certified is False


def test_linux_backend_detect_capabilities_probe_failure(tmp_path: Path) -> None:
    """Verifies probe failure (e.g. unprivileged user namespaces disabled) marks capabilities UNSUPPORTED."""
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 1\n")

    with patch("sys.platform", "linux"), patch("os.path.isfile", return_value=True):
        backend = LinuxBubblewrapBackend(bwrap_path=str(fake_bwrap))
        with patch.object(
            backend,
            "probe_bwrap_capability",
            return_value=(False, "bwrap probe failed: unprivileged user namespaces disabled"),
        ):
            report = backend.detect_capabilities(tmp_path)
            assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
            assert report.network_isolation == CapabilityStatus.UNSUPPORTED
            assert report.process_isolation == CapabilityStatus.UNSUPPORTED
            assert report.process_count_enforcement == CapabilityStatus.UNSUPPORTED
            assert report.resource_enforcement == CapabilityStatus.UNSUPPORTED
            assert report.is_production_certified is False


def test_linux_backend_detect_capabilities_success_with_cgroup_v2(tmp_path: Path) -> None:
    """Verifies full capability pass when bwrap probe and cgroup v2 controllers succeed."""
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 0\n")

    with (
        patch("sys.platform", "linux"),
        patch("os.path.isfile", return_value=True),
        patch.object(LinuxBubblewrapBackend, "probe_bwrap_capability", return_value=(True, "Probe OK")),
        patch.object(CgroupV2Manager, "is_available", return_value=True),
        patch.object(CgroupV2Manager, "is_delegated", return_value=True),
        patch.object(CgroupV2Manager, "get_available_controllers", return_value={"pids", "memory", "cpu"}),
        patch.dict(os.environ, {"SARTHI_SANDBOX_CERTIFIED": "1"}),
    ):
        backend = LinuxBubblewrapBackend(bwrap_path=str(fake_bwrap))
        report = backend.detect_capabilities(tmp_path)

        assert report.filesystem_isolation == CapabilityStatus.PASS
        assert report.network_isolation == CapabilityStatus.PASS
        assert report.process_isolation == CapabilityStatus.PASS
        assert report.process_count_enforcement == CapabilityStatus.PASS
        assert report.resource_enforcement == CapabilityStatus.PASS
        assert report.environment_isolation == CapabilityStatus.PASS
        assert report.workspace_confinement == CapabilityStatus.PASS
        assert report.child_process_inheritance == CapabilityStatus.PASS
        assert report.certification_tier == CertificationTier.PRODUCTION_CERTIFIED
        assert report.mechanism_maturity == MechanismMaturity.PRODUCTION
        assert report.is_production_certified is True


def test_linux_backend_detect_capabilities_missing_cgroup_controllers(tmp_path: Path) -> None:
    """Verifies that missing cgroup v2 controllers report UNSUPPORTED for process/memory limits."""
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 0\n")

    with (
        patch("sys.platform", "linux"),
        patch("os.path.isfile", return_value=True),
        patch.object(LinuxBubblewrapBackend, "probe_bwrap_capability", return_value=(True, "Probe OK")),
        patch.object(CgroupV2Manager, "is_available", return_value=True),
        patch.object(CgroupV2Manager, "is_delegated", return_value=True),
        patch.object(CgroupV2Manager, "get_available_controllers", return_value={"cpu"}),  # No pids, no memory
    ):
        backend = LinuxBubblewrapBackend(bwrap_path=str(fake_bwrap))
        report = backend.detect_capabilities(tmp_path)

        assert report.filesystem_isolation == CapabilityStatus.PASS
        assert report.network_isolation == CapabilityStatus.PASS
        assert report.process_isolation == CapabilityStatus.PASS
        # Missing controllers:
        assert report.process_count_enforcement == CapabilityStatus.UNSUPPORTED
        assert report.resource_enforcement == CapabilityStatus.UNSUPPORTED
        # Cannot be certified when controllers are missing:
        assert report.is_production_certified is False


def test_linux_backend_initialize_fails_closed_when_unavailable() -> None:
    """Verifies initialize() raises SandboxCapabilityUnavailableError when backend cannot run."""
    with patch("sys.platform", "win32"):
        backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
        policy = SandboxPolicy()
        with pytest.raises(SandboxCapabilityUnavailableError, match="LinuxBubblewrapBackend is unavailable"):
            backend.initialize(policy, Path("/tmp/ws"))


def test_linux_backend_build_bwrap_args_isolation_flags(tmp_path: Path) -> None:
    """Verifies build_bwrap_args constructs required namespace and filesystem isolation arguments."""
    backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )

    args = backend.build_bwrap_args(
        policy=policy,
        workspace_root=tmp_path,
        block_fd=42,
        env={"CUSTOM_KEY": "CUSTOM_VAL"},
    )

    assert args[0] == "/usr/bin/bwrap"
    assert "--unshare-pid" in args
    assert "--unshare-user" in args
    assert "--cap-drop" in args and args[args.index("--cap-drop") + 1] == "ALL"
    assert "--die-with-parent" in args
    assert "--dev" in args and args[args.index("--dev") + 1] == "/dev"
    assert "--proc" in args and args[args.index("--proc") + 1] == "/proc"
    assert "--tmpfs" in args and args[args.index("--tmpfs") + 1] == "/tmp"
    assert "--unshare-net" in args
    assert "--clearenv" in args
    assert "--block-fd" in args and args[args.index("--block-fd") + 1] == "42"

    # Environment variables
    assert "--setenv" in args
    assert "CUSTOM_KEY" in args and args[args.index("CUSTOM_KEY") + 1] == "CUSTOM_VAL"
    assert "PATH" in args
    assert "LANG" in args

    # Workspace mount
    ws_str = str(tmp_path.resolve())
    assert "--bind" in args
    assert ws_str in args
    assert "--chdir" in args and args[args.index("--chdir") + 1] == ws_str


def test_linux_backend_build_bwrap_args_read_only_workspace(tmp_path: Path) -> None:
    """Verifies read-only workspace uses --ro-bind instead of --bind."""
    backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
    policy = SandboxPolicy(
        filesystem=FilesystemPolicy.READ_ONLY_WORKSPACE,
    )
    args = backend.build_bwrap_args(policy=policy, workspace_root=tmp_path)
    ws_str = str(tmp_path.resolve())
    assert "--ro-bind" in args
    # Workspace should appear after --ro-bind
    idx = args.index("--ro-bind")
    assert args[idx + 1] == ws_str or ws_str in args


def test_cgroup_v2_manager_directory_allocation_and_limits(tmp_path: Path) -> None:
    """Verifies cgroup directory creation, controller subtree enablement, and resource limits."""
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    (cgroup_root / "cgroup.controllers").write_text("pids memory cpu\n", encoding="utf-8")
    (cgroup_root / "cgroup.subtree_control").write_text("", encoding="utf-8")

    mgr = CgroupV2Manager(cgroup_root=cgroup_root)

    with patch.object(mgr, "is_available", return_value=True), patch.object(
        mgr, "get_current_process_cgroup_dir", return_value=cgroup_root
    ):
        child_dir = mgr.allocate_sandbox_cgroup("test-run-1")
        assert child_dir.is_dir()
        assert child_dir.name == "sarthi-sandbox-test-run-1"

        # Mock files in child cgroup
        (child_dir / "pids.max").write_text("max\n", encoding="utf-8")
        (child_dir / "memory.max").write_text("max\n", encoding="utf-8")
        (child_dir / "memory.swap.max").write_text("max\n", encoding="utf-8")
        (child_dir / "memory.oom.group").write_text("0\n", encoding="utf-8")

        mgr.configure_limits(
            max_processes=42,
            max_memory_bytes=512 * 1024 * 1024,
            swap_max_bytes=0,
            oom_group=True,
        )

        assert (child_dir / "pids.max").read_text(encoding="utf-8").strip() == "42"
        assert (child_dir / "memory.max").read_text(encoding="utf-8").strip() == str(512 * 1024 * 1024)
        assert (child_dir / "memory.swap.max").read_text(encoding="utf-8").strip() == "0"
        assert (child_dir / "memory.oom.group").read_text(encoding="utf-8").strip() == "1"


def test_cgroup_v2_manager_attach_and_verify_pid(tmp_path: Path) -> None:
    """Verifies attach_pid writes to cgroup.procs and verifies membership."""
    cgroup_dir = tmp_path / "sarthi-sandbox-test"
    cgroup_dir.mkdir()
    procs_file = cgroup_dir / "cgroup.procs"
    procs_file.write_text("", encoding="utf-8")

    mgr = CgroupV2Manager(cgroup_root=tmp_path)
    mgr.cgroup_path = cgroup_dir

    mgr.attach_pid(9999)
    assert "9999" in procs_file.read_text(encoding="utf-8").split()
    assert mgr.verify_pid_attached(9999) is True
    assert mgr.verify_pid_attached(1111) is False


def test_cgroup_v2_manager_kill_all_using_cgroup_kill(tmp_path: Path) -> None:
    """Verifies kill_all writes '1' to cgroup.kill for atomic kernel 5.14+ termination."""
    cgroup_dir = tmp_path / "sarthi-sandbox-test"
    cgroup_dir.mkdir()
    kill_file = cgroup_dir / "cgroup.kill"
    kill_file.write_text("0\n", encoding="utf-8")

    mgr = CgroupV2Manager(cgroup_root=tmp_path)
    mgr.cgroup_path = cgroup_dir

    mgr.kill_all()
    assert kill_file.read_text(encoding="utf-8").strip() == "1"


def test_cgroup_v2_manager_cleanup_emptiness_verification(tmp_path: Path) -> None:
    """Verifies cleanup polls cgroup.events for populated 0 and removes directory."""
    cgroup_dir = tmp_path / "sarthi-sandbox-test"
    cgroup_dir.mkdir()
    (cgroup_dir / "cgroup.events").write_text("populated 0\n", encoding="utf-8")
    (cgroup_dir / "cgroup.procs").write_text("", encoding="utf-8")

    mgr = CgroupV2Manager(cgroup_root=tmp_path)
    mgr.cgroup_path = cgroup_dir

    with patch("os.rmdir") as mock_rmdir:
        mgr.cleanup()
        mock_rmdir.assert_called_once_with(cgroup_dir)
    assert mgr.cgroup_path is None


def test_cgroup_v2_manager_cleanup_failure_raises_sandbox_cleanup_error(tmp_path: Path) -> None:
    """Verifies cleanup raises SandboxCleanupError if residual processes remain."""
    cgroup_dir = tmp_path / "sarthi-sandbox-test"
    cgroup_dir.mkdir()
    (cgroup_dir / "cgroup.events").write_text("populated 1\n", encoding="utf-8")
    (cgroup_dir / "cgroup.procs").write_text("12345\n", encoding="utf-8")

    mgr = CgroupV2Manager(cgroup_root=tmp_path)
    mgr.cgroup_path = cgroup_dir

    # Mock rmdir to fail because directory is not empty
    with patch("os.rmdir", side_effect=OSError("Directory not empty")):
        with pytest.raises(SandboxCleanupError, match="Failed to remove cgroup directory"):
            mgr.cleanup(drain_timeout=0.1)


def test_linux_backend_run_with_mocked_popen(tmp_path: Path) -> None:
    """Verifies LinuxBubblewrapBackend.run executes command and collects results."""
    backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
    policy = SandboxPolicy(
        limits=ResourceLimits(timeout_seconds=5),
    )

    mock_proc = MagicMock()
    mock_proc.pid = 12345
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = ("hello sandboxed world\n", "")

    with (
        patch.object(backend, "is_available", return_value=True),
        patch.object(CgroupV2Manager, "is_available", return_value=False),
        patch.object(
            backend,
            "detect_capabilities",
            return_value=SandboxCapabilityReport(
                backend_name="linux_bubblewrap",
                mechanism_maturity=MechanismMaturity.PRODUCTION,
            ),
        ),
        patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
    ):
        result = backend.run(["echo", "hello"], policy, tmp_path)

        assert result.exit_code == 0
        assert result.stdout == "hello sandboxed world\n"
        assert result.timed_out is False
        assert result.cleanup_successful is True
        mock_popen.assert_called_once()


def test_linux_backend_run_timeout_terminates_process(tmp_path: Path) -> None:
    """Verifies timeout triggers process-tree termination and sets timed_out=True."""
    backend = LinuxBubblewrapBackend(bwrap_path="/usr/bin/bwrap")
    policy = SandboxPolicy(
        limits=ResourceLimits(timeout_seconds=1),
    )

    mock_proc = MagicMock()
    mock_proc.pid = 54321
    mock_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1),
        ("partial output", ""),
    ]

    with (
        patch.object(backend, "is_available", return_value=True),
        patch.object(CgroupV2Manager, "is_available", return_value=False),
        patch.object(
            backend,
            "detect_capabilities",
            return_value=SandboxCapabilityReport(
                backend_name="linux_bubblewrap",
                mechanism_maturity=MechanismMaturity.PRODUCTION,
            ),
        ),
        patch("subprocess.Popen", return_value=mock_proc),
    ):
        result = backend.run(["sleep", "10"], policy, tmp_path)

        assert result.timed_out is True
        assert result.exit_code == -1
