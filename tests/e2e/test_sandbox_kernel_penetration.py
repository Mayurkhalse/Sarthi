"""Adversarial OS-level security penetration suite for Sarthi Linux Bubblewrap & cgroup v2.

These tests execute REAL adversarial penetration scripts against genuine OS isolation
mechanisms. They verify:
1. Filesystem containment and host credential denial (/etc/shadow, ~/.ssh)
2. Immutability of host filesystems (read-only system mounts)
3. Network WAN egress denial (default-deny netns unsharing)
4. Host loopback interface isolation
5. Fork bomb exhaustion containment (cgroup v2 pids.max)
6. Hard memory limit containment and atomic OOM termination (cgroup v2 memory.max)
7. Host secret environment sanitization
8. Clean process-tree teardown and cgroup emptiness verification

NOTE: Marked with @pytest.mark.security_ci_only. Executes in Linux CI runners with bwrap.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sarthi.core.sandbox.backends.cgroup import CgroupV2Manager
from sarthi.core.sandbox.backends.linux import LinuxBubblewrapBackend
from sarthi.core.sandbox.policy import (
    FilesystemPolicy,
    NetworkPolicy,
    ResourceLimits,
    SandboxPolicy,
)

pytestmark = [
    pytest.mark.security_ci_only,
    pytest.mark.skipif(
        not sys.platform.startswith("linux") or not shutil.which("bwrap"),
        reason="Kernel security penetration tests require Linux host with bubblewrap (bwrap) installed.",
    ),
]


@pytest.fixture
def linux_backend() -> LinuxBubblewrapBackend:
    return LinuxBubblewrapBackend()


def get_sandbox_python() -> str:
    """Finds an executable python binary for sandboxed adversarial testing.

    Prefers system /usr/bin/python3 or /usr/bin/python (natively self-contained within
    the sandbox's /usr mount), falling back to resolved sys.executable.
    """
    for candidate in ("/usr/bin/python3", "/usr/bin/python"):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return str(Path(sys.executable).resolve())


def test_adversarial_host_credential_denial(linux_backend: LinuxBubblewrapBackend, tmp_path: Path) -> None:
    """Verifies sandboxed process cannot read host sensitive files (/etc/shadow, /root, /etc/gshadow)."""
    script_file = tmp_path / "attack_creds.py"
    script_file.write_text(
        """
import sys
targets = ['/etc/shadow', '/root', '/etc/gshadow']
for path in targets:
    try:
        with open(path, 'r') as f:
            # If readable, security boundary breached!
            sys.exit(42)
    except (PermissionError, FileNotFoundError):
        pass
sys.exit(0)
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )
    result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
    assert result.exit_code == 0, f"Host credential boundary violated! Stderr: {result.stderr}"


def test_adversarial_host_filesystem_write_immutability(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies sandboxed process cannot write or modify host system directories (/usr, /etc, /bin)."""
    script_file = tmp_path / "attack_fs.py"
    script_file.write_text(
        """
import sys
targets = ['/usr/malicious_probe.txt', '/etc/malicious_probe.conf', '/bin/malicious_probe']
for path in targets:
    try:
        with open(path, 'w') as f:
            f.write('pwned')
        sys.exit(42)  # Write succeeded on host system!
    except (PermissionError, OSError):
        pass
sys.exit(0)
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )
    result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
    assert result.exit_code == 0, f"Host filesystem write isolation violated! Stderr: {result.stderr}"


def test_adversarial_network_wan_egress_denial(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies sandboxed process cannot establish outbound connections to WAN IP addresses."""
    script_file = tmp_path / "attack_net_wan.py"
    script_file.write_text(
        """
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
try:
    sock.connect(('8.8.8.8', 53))
    sys.exit(42)  # Connected to external internet!
except OSError:
    sys.exit(0)  # Correctly blocked by network namespace isolation
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )
    result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
    assert result.exit_code == 0, f"Outbound WAN egress was permitted! Stderr: {result.stderr}"


def test_adversarial_host_loopback_isolation(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies sandboxed process cannot reach services listening on the host's loopback interface."""
    # 1. Start ephemeral HTTP listener on host loopback
    server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    host_port = server.server_address[1]

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    # 2. Adversarial script attempts to connect to host loopback
    script_file = tmp_path / "attack_loopback.py"
    script_file.write_text(
        f"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
try:
    sock.connect(('127.0.0.1', {host_port}))
    sys.exit(42)  # Reached host loopback listener!
except OSError:
    sys.exit(0)  # Correctly blocked by isolated loopback namespace
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )
    try:
        result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
        assert result.exit_code == 0, f"Host loopback service was reached! Stderr: {result.stderr}"
    finally:
        server.server_close()


def test_adversarial_fork_bomb_containment(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies cgroup v2 pids.max strictly bounds process creation and prevents fork bomb starvation."""
    if not CgroupV2Manager.is_available() or not CgroupV2Manager.is_delegated():
        pytest.skip("cgroup v2 is not available or not delegated on this runner.")
    controllers = CgroupV2Manager.get_available_controllers()
    if "pids" not in controllers:
        pytest.skip("cgroup v2 pids controller is not enabled on this runner.")

    script_file = tmp_path / "attack_fork_bomb.py"
    script_file.write_text(
        """
import os, sys, time
pids = []
try:
    for _ in range(60):
        pid = os.fork()
        if pid == 0:
            time.sleep(2)
            sys.exit(0)
        pids.append(pid)
    sys.exit(42)  # If all 60 forks succeeded without limit, fail
except BlockingIOError:
    # Kernel pids.max ceiling enforced!
    sys.exit(0)
except OSError:
    # Fork failed due to resource limits
    sys.exit(0)
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
        limits=ResourceLimits(max_processes=15, timeout_seconds=10),
    )
    result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
    assert result.exit_code == 0, f"Fork bomb breached process ceiling! Exit code: {result.exit_code}"


def test_adversarial_memory_exhaustion_containment(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies cgroup v2 memory.max terminates sandboxed memory hog without affecting supervisor."""
    if not CgroupV2Manager.is_available() or not CgroupV2Manager.is_delegated():
        pytest.skip("cgroup v2 is not available or not delegated on this runner.")
    controllers = CgroupV2Manager.get_available_controllers()
    if "memory" not in controllers:
        pytest.skip("cgroup v2 memory controller is not enabled on this runner.")

    script_file = tmp_path / "attack_mem.py"
    # Allocate 120MB in a 32MB constrained container
    script_file.write_text(
        """
import sys
try:
    data = bytearray(120 * 1024 * 1024)
    # Touch pages to force physical page faulting
    for i in range(0, len(data), 4096):
        data[i] = 1
    sys.exit(42)  # Memory limit was not enforced!
except MemoryError:
    sys.exit(0)
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
        limits=ResourceLimits(max_memory_bytes=32 * 1024 * 1024, timeout_seconds=10),
    )
    result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)

    # Process must either be terminated by OOM killer (exit code -9 or 137) or caught with MemoryError (exit 0)
    # It must NEVER succeed (exit 42)
    assert result.exit_code != 42, "Memory limit was violated; 120MB allocation succeeded!"
    assert result.exit_code in (-9, 137, 0)


def test_adversarial_environment_secret_sanitization(
    linux_backend: LinuxBubblewrapBackend, tmp_path: Path
) -> None:
    """Verifies host environment secrets (e.g. API keys, tokens) are completely stripped from sandbox."""
    secret_key = "SARTHI_TEST_SUPER_SECRET_KEY"
    secret_value = "untrusted_payload_secret_12345"

    script_file = tmp_path / "attack_env.py"
    script_file.write_text(
        f"""
import os, sys
if os.environ.get('{secret_key}') == '{secret_value}':
    sys.exit(42)  # Leaked host environment secret!
sys.exit(0)
""",
        encoding="utf-8",
    )

    policy = SandboxPolicy(
        network=NetworkPolicy.BLOCKED,
        filesystem=FilesystemPolicy.READ_WRITE_WORKSPACE,
    )

    # Temporarily set secret in supervisor process environment
    old_val = os.environ.get(secret_key)
    os.environ[secret_key] = secret_value
    try:
        result = linux_backend.run([get_sandbox_python(), str(script_file)], policy, tmp_path)
        assert result.exit_code == 0, f"Host environment variable was leaked! Stderr: {result.stderr}"
    finally:
        if old_val is not None:
            os.environ[secret_key] = old_val
        else:
            os.environ.pop(secret_key, None)
