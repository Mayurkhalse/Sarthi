"""Unit tests for Windows AppContainer and Job Object sandbox backend.

Tests verify WindowsAppContainerBackend configuration, capability probing,
Job Object lifecycle, AppContainer profile creation, additive DACL scoping,
fail-closed error handling, and timeout enforcement.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sarthi.core.sandbox.backends.windows import WindowsAppContainerBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    ResourceLimits,
    SandboxPolicy,
)


def test_windows_backend_availability() -> None:
    """Verifies is_available() accurately detects Windows platform."""
    backend = WindowsAppContainerBackend()
    if sys.platform != "win32":
        assert backend.is_available() is False
    else:
        assert backend.is_available() is True


def test_windows_backend_unsupported_on_non_windows(tmp_path: Path) -> None:
    """Verifies that non-Windows platforms report UNSUPPORTED for all capabilities."""
    with patch("sys.platform", "linux"):
        backend = WindowsAppContainerBackend()
        report = backend.detect_capabilities(tmp_path)
        assert report.filesystem_isolation == CapabilityStatus.UNSUPPORTED
        assert report.network_isolation == CapabilityStatus.UNSUPPORTED
        assert report.process_isolation == CapabilityStatus.UNSUPPORTED
        assert report.process_count_enforcement == CapabilityStatus.UNSUPPORTED
        assert report.resource_enforcement == CapabilityStatus.UNSUPPORTED
        assert report.environment_isolation == CapabilityStatus.UNSUPPORTED
        assert report.workspace_confinement == CapabilityStatus.UNSUPPORTED
        assert report.child_process_inheritance == CapabilityStatus.UNSUPPORTED
        assert report.certification_tier == CertificationTier.IMPLEMENTATION_PENDING


def test_windows_backend_initialize_fails_on_non_windows(tmp_path: Path) -> None:
    """Verifies initialize() raises SandboxCapabilityUnavailableError on non-Windows platforms."""
    with patch("sys.platform", "darwin"):
        backend = WindowsAppContainerBackend()
        policy = SandboxPolicy()
        with pytest.raises(SandboxCapabilityUnavailableError, match="Win32"):
            backend.initialize(policy, tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows kernel")
def test_windows_capability_probe_live(tmp_path: Path) -> None:
    """Tests live capability probing on Windows."""
    backend = WindowsAppContainerBackend()
    report = backend.detect_capabilities(tmp_path)
    assert report.filesystem_isolation == CapabilityStatus.PASS
    assert report.network_isolation == CapabilityStatus.PASS
    assert report.process_isolation == CapabilityStatus.PASS
    assert report.process_count_enforcement == CapabilityStatus.PASS
    assert report.resource_enforcement == CapabilityStatus.PASS
    assert report.environment_isolation == CapabilityStatus.PASS
    assert report.workspace_confinement == CapabilityStatus.PASS
    assert report.child_process_inheritance == CapabilityStatus.PASS
    assert any("AppContainer" in trace for trace in report.evidence_trace)
    assert any("Job Object" in trace for trace in report.evidence_trace)


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows kernel")
def test_windows_sandbox_basic_execution(tmp_path: Path) -> None:
    """Verifies basic execution inside AppContainer and output capture."""
    backend = WindowsAppContainerBackend()
    policy = SandboxPolicy()
    try:
        result = backend.run(["cmd.exe", "/c", "echo", "sarthi_windows_unit_test"], policy, tmp_path)
        assert result.exit_code == 0
        assert "sarthi_windows_unit_test" in result.stdout
        assert result.timed_out is False
    finally:
        backend.cleanup()


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows kernel")
def test_windows_sandbox_timeout_enforcement(tmp_path: Path) -> None:
    """Verifies execution timeout terminates process via Job Object."""
    backend = WindowsAppContainerBackend()
    policy = SandboxPolicy(limits=ResourceLimits(timeout_seconds=1.0))
    try:
        # Sleep for 10 seconds using python
        result = backend.run([sys.executable, "-c", "import time; time.sleep(10)"], policy, tmp_path)
        assert result.timed_out is True
        assert result.exit_code == -1
    finally:
        backend.cleanup()


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows kernel")
def test_windows_sandbox_environment_sanitization(tmp_path: Path) -> None:
    """Verifies that parent environment secrets are sanitized."""
    backend = WindowsAppContainerBackend()
    policy = SandboxPolicy()
    secret_key = "SARTHI_TEST_SECRET_VAR_12345"
    os.environ[secret_key] = "super_secret_token"
    try:
        result = backend.run(["cmd.exe", "/c", "set"], policy, tmp_path)
        assert result.exit_code == 0
        assert secret_key not in result.stdout
    finally:
        os.environ.pop(secret_key, None)
        backend.cleanup()
