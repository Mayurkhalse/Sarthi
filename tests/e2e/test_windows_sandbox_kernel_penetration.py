"""Adversarial OS-level security penetration suite for Sarthi Windows AppContainer & Job Objects.

These tests execute REAL adversarial penetration scripts against genuine Windows kernel
isolation mechanisms. They verify:
1. Filesystem containment and host credential denial (%USERPROFILE%/.ssh, %APPDATA%)
2. Unauthorized filesystem read denial (C:\\Windows\\System32\\config\\SAM)
3. Immutability of host filesystems (write attempts to host root / Windows)
4. Network WAN egress denial (zero network capabilities, WFP drop)
5. Host loopback interface isolation (127.0.0.1 drop)
6. Fork bomb process exhaustion containment (ActiveProcessLimit cap)
7. Hard commit memory exhaustion containment (JobMemoryLimit cap)
8. Child and grandchild process containment inheritance
9. Job Object escape resistance (CREATE_BREAKAWAY_FROM_JOB access denial)
10. Host environment secret sanitization
11. Inherited privileged handle denial (HANDLE_LIST isolation)
12. Clean process-tree teardown and orphan process prevention (KILL_ON_JOB_CLOSE)
13. DNS resolution denial
14. IPv6 egress denial
15. Directory junction traversal denial (kernel SRM destination check)

NOTE: Marked with @pytest.mark.security_ci_only. Executes in Windows CI runners without mocking.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sarthi.core.sandbox.backends.windows import WindowsAppContainerBackend
from sarthi.core.sandbox.policy import ResourceLimits, SandboxPolicy

pytestmark = [
    pytest.mark.security_ci_only,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="Kernel security penetration tests require native Windows platform.",
    ),
]


@pytest.fixture
def windows_backend() -> WindowsAppContainerBackend:
    backend = WindowsAppContainerBackend()
    yield backend
    backend.cleanup()


# -----------------------------------------------------------------------------
# 1. Host Credential Denial
# -----------------------------------------------------------------------------
def test_adversarial_host_credential_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary tries to steal host SSH keys or user credentials from %USERPROFILE%."""
    user_profile = os.environ.get("USERPROFILE", r"C:\Users\Default")
    test_cred_path = os.path.join(user_profile, ".ssh", "id_rsa")

    # Script attempting to exfiltrate or read host credential
    script = f"""
import os, sys
target = r"{test_cred_path}"
try:
    if os.path.exists(target):
        with open(target, 'rb') as f:
            data = f.read(16)
        print("EXFILTRATED_HOST_CREDENTIAL")
        sys.exit(0)
    else:
        # Attempt to list directory
        parent = os.path.dirname(target)
        entries = os.listdir(parent)
        print("LISTED_PARENT_DIR:", len(entries))
        sys.exit(0)
except Exception as e:
    print("ACCESS_DENIED:", type(e).__name__, str(e))
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "ACCESS_DENIED" in result.stdout
    assert "EXFILTRATED_HOST_CREDENTIAL" not in result.stdout


# -----------------------------------------------------------------------------
# 2. Unauthorized Filesystem Read Denial
# -----------------------------------------------------------------------------
def test_adversarial_unauthorized_filesystem_access_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to read sensitive Windows registry hives (SAM / SYSTEM)."""
    sam_path = r"C:\Windows\System32\config\SAM"
    script = f"""
import sys
try:
    with open(r"{sam_path}", 'rb') as f:
        data = f.read(32)
    print("READ_SAM_SUCCESS")
    sys.exit(0)
except Exception as e:
    print("SAM_DENIED:", type(e).__name__)
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "SAM_DENIED" in result.stdout
    assert "READ_SAM_SUCCESS" not in result.stdout


# -----------------------------------------------------------------------------
# 3. Host Filesystem Write Immutability
# -----------------------------------------------------------------------------
def test_adversarial_host_filesystem_write_immutability(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to write outside the staged directory onto host drives."""
    escape_target = r"C:\sarthi_test_write_escape.txt"
    script = f"""
import sys
try:
    with open(r"{escape_target}", 'w') as f:
        f.write("malicious_tamper")
    print("ESCAPE_WRITE_SUCCESS")
    sys.exit(0)
except Exception as e:
    print("WRITE_DENIED:", type(e).__name__)
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "WRITE_DENIED" in result.stdout
    assert "ESCAPE_WRITE_SUCCESS" not in result.stdout
    assert not os.path.exists(escape_target)


# -----------------------------------------------------------------------------
# 4. Network WAN Egress Denial
# -----------------------------------------------------------------------------
def test_adversarial_network_wan_egress_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts outbound WAN socket communication to external IP."""
    script = """
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(('8.8.8.8', 53))
    print("WAN_CONNECTED")
    sys.exit(0)
except Exception as e:
    print("WAN_DENIED:", type(e).__name__, str(e))
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "WAN_DENIED" in result.stdout
    assert "WAN_CONNECTED" not in result.stdout


# -----------------------------------------------------------------------------
# 5. Host Loopback Isolation
# -----------------------------------------------------------------------------
def test_adversarial_host_loopback_isolation(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to connect to a service listening on host 127.0.0.1."""
    # Start a dummy server on host
    server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = server.server_port
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()

    script = f"""
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(('127.0.0.1', {port}))
    print("LOOPBACK_CONNECTED")
    sys.exit(0)
except Exception as e:
    print("LOOPBACK_DENIED:", type(e).__name__, str(e))
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    server.server_close()
    assert result.exit_code == 42
    assert "LOOPBACK_DENIED" in result.stdout
    assert "LOOPBACK_CONNECTED" not in result.stdout


# -----------------------------------------------------------------------------
# 6. Fork Bomb Process Exhaustion Containment
# -----------------------------------------------------------------------------
def test_adversarial_process_exhaustion_containment(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary executes recursive process fork-bomb to exhaust OS PID table."""
    script = """
import subprocess, sys
# Try to spawn 25 background processes
procs = []
try:
    for i in range(25):
        p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        procs.append(p)
    print("SPAWNED_ALL:", len(procs))
    sys.exit(0)
except Exception as e:
    print("FORK_LIMITED:", type(e).__name__, len(procs))
    sys.exit(42)
"""
    # ActiveProcessLimit capped at 5 processes
    policy = SandboxPolicy(limits=ResourceLimits(max_processes=5, timeout_seconds=10.0))
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "FORK_LIMITED" in result.stdout
    assert "SPAWNED_ALL" not in result.stdout


# -----------------------------------------------------------------------------
# 7. Memory Exhaustion Containment
# -----------------------------------------------------------------------------
def test_adversarial_memory_exhaustion_containment(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary allocates memory past Job Object commit memory ceiling."""
    script = """
import sys
try:
    # Attempt to allocate 512 MB in chunks
    chunks = []
    for _ in range(512):
        chunks.append(bytearray(1024 * 1024))
    print("ALLOCATED_ALL_512MB")
    sys.exit(0)
except Exception as e:
    print("MEMORY_EXHAUSTION_HALTED:", type(e).__name__)
    sys.exit(42)
"""
    # Cap Job commit limit to 128 MB
    policy = SandboxPolicy(
        limits=ResourceLimits(max_memory_bytes=128 * 1024 * 1024, timeout_seconds=10.0)
    )
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    # Either the script catches MemoryError (42) or process is terminated by Job Object (-1 / crash)
    assert "ALLOCATED_ALL_512MB" not in result.stdout
    assert result.exit_code != 0


# -----------------------------------------------------------------------------
# 8. Child Process Containment
# -----------------------------------------------------------------------------
def test_adversarial_child_process_containment(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to spawn child and grandchild to escape containment."""
    user_profile = os.environ.get("USERPROFILE", r"C:\Users\Default")
    test_cred = os.path.join(user_profile, ".ssh", "id_rsa")

    child_code = f"""
import os, sys
try:
    with open(r"{test_cred}", "rb") as f:
        pass
    print("GRANDCHILD_ESCAPE_SUCCESS")
    sys.exit(0)
except Exception:
    print("GRANDCHILD_CONTAINED")
    sys.exit(42)
"""
    parent_code = f"""
import subprocess, sys
res = subprocess.run([sys.executable, "-c", {child_code!r}], capture_output=True, text=True)
print(res.stdout)
sys.exit(res.returncode)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", parent_code], policy, tmp_path)
    assert result.exit_code == 42
    assert "GRANDCHILD_CONTAINED" in result.stdout
    assert "GRANDCHILD_ESCAPE_SUCCESS" not in result.stdout


# -----------------------------------------------------------------------------
# 9. Job Object Escape Resistance
# -----------------------------------------------------------------------------
def test_adversarial_job_object_escape_resistance(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to spawn process using CREATE_BREAKAWAY_FROM_JOB to escape Job Object."""
    script = """
import ctypes, subprocess, sys
from ctypes import wintypes

k = ctypes.windll.kernel32
k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k.IsProcessInJob.restype = wintypes.BOOL

child_code = '''
import ctypes, sys
from ctypes import wintypes
k = ctypes.windll.kernel32
k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k.IsProcessInJob.restype = wintypes.BOOL
in_job = wintypes.BOOL()
k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(in_job))
if in_job.value:
    print("CHILD_STILL_CONTAINED_IN_JOB")
    sys.exit(0)
else:
    print("CHILD_ESCAPED_JOB")
    sys.exit(1)
'''

CREATE_BREAKAWAY_FROM_JOB = 0x01000000
try:
    p = subprocess.Popen(
        [sys.executable, "-c", child_code],
        creationflags=CREATE_BREAKAWAY_FROM_JOB,
        stdout=subprocess.PIPE,
        text=True,
    )
    out, _ = p.communicate()
    print("RESULT:", out.strip())
    if "CHILD_ESCAPED_JOB" in out:
        sys.exit(10)
    elif "CHILD_STILL_CONTAINED_IN_JOB" in out:
        print("BREAKAWAY_CONTAINED")
        sys.exit(0)
except Exception as e:
    print("BREAKAWAY_DENIED_BY_EXCEPTION:", type(e).__name__)
    sys.exit(0)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 0
    assert "CHILD_ESCAPED_JOB" not in result.stdout
    assert "BREAKAWAY_CONTAINED" in result.stdout or "BREAKAWAY_DENIED_BY_EXCEPTION" in result.stdout


# -----------------------------------------------------------------------------
# 10. Environment Secret Sanitization
# -----------------------------------------------------------------------------
def test_adversarial_environment_secret_sanitization(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts to read sensitive parent host environment variables."""
    secret_key = "SARTHI_PENETRATION_API_SECRET_TOKEN"
    os.environ[secret_key] = "super_classified_key_val"

    script = f"""
import os, sys
if "{secret_key}" in os.environ:
    print("SECRET_LEAKED:", os.environ["{secret_key}"])
    sys.exit(0)
else:
    print("SECRET_SANITIZED")
    sys.exit(42)
"""
    try:
        policy = SandboxPolicy()
        result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
        assert result.exit_code == 42
        assert "SECRET_SANITIZED" in result.stdout
        assert "SECRET_LEAKED" not in result.stdout
    finally:
        os.environ.pop(secret_key, None)


# -----------------------------------------------------------------------------
# 11. Inherited Privileged Handle Denial
# -----------------------------------------------------------------------------
def test_adversarial_inherited_privileged_handle_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Verifies that non-whitelisted parent file handles are not inherited."""
    # Host creates a private file and opens it
    private_file = tmp_path.parent / "host_private_handle_file.txt"
    private_file.write_text("classified_host_data", encoding="utf-8")

    with open(private_file, "r") as host_handle:
        raw_fileno = host_handle.fileno()

        script = f"""
import os, sys
# Attempt to read from inherited descriptor
try:
    os.read({raw_fileno}, 16)
    print("HANDLE_INHERITED_SUCCESS")
    sys.exit(0)
except Exception:
    print("HANDLE_ISOLATED")
    sys.exit(42)
"""
        policy = SandboxPolicy()
        result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
        assert result.exit_code == 42
        assert "HANDLE_ISOLATED" in result.stdout
        assert "HANDLE_INHERITED_SUCCESS" not in result.stdout

    if private_file.exists():
        private_file.unlink()


# -----------------------------------------------------------------------------
# 12. Teardown and Orphan Process Prevention
# -----------------------------------------------------------------------------
def test_adversarial_teardown_and_orphan_process_prevention(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary spawns lingering daemon; verify cleanup kills all processes via Job Object."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259

    # Spawns a daemon that sleeps for 60 seconds
    script = """
import subprocess, sys
p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
print("DAEMON_PID:", p.pid)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 0
    daemon_pid_str = [line for line in result.stdout.splitlines() if "DAEMON_PID:" in line][0]
    daemon_pid = int(daemon_pid_str.split(":")[1].strip())

    # Verify daemon process is running via native Win32 handle
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, daemon_pid)
    assert h_proc, f"Daemon process {daemon_pid} was not found."
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(h_proc, ctypes.byref(exit_code))
    assert exit_code.value == STILL_ACTIVE, "Daemon process should be running before cleanup."

    # Execute backend cleanup (terminates Job Object process tree)
    windows_backend.cleanup()

    # Verify daemon process is killed by kernel
    time.sleep(0.5)
    kernel32.GetExitCodeProcess(h_proc, ctypes.byref(exit_code))
    kernel32.CloseHandle(h_proc)
    assert exit_code.value != STILL_ACTIVE, "Daemon process must be terminated after Job Object closure."


# -----------------------------------------------------------------------------
# Subtests: Protocol & Reparse Point Checks
# -----------------------------------------------------------------------------
def test_adversarial_dns_resolution_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts DNS resolution inside zero-capability AppContainer."""
    script = """
import socket, sys
try:
    socket.getaddrinfo('google.com', 80)
    print("DNS_RESOLVED")
    sys.exit(0)
except Exception as e:
    print("DNS_DENIED:", type(e).__name__)
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "DNS_DENIED" in result.stdout
    assert "DNS_RESOLVED" not in result.stdout


def test_adversarial_network_ipv6_egress_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary attempts IPv6 socket connection to Google DNS."""
    script = """
import socket, sys
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(('2001:4860:4860::8888', 53))
    print("IPV6_CONNECTED")
    sys.exit(0)
except Exception as e:
    print("IPV6_DENIED:", type(e).__name__)
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "IPV6_DENIED" in result.stdout
    assert "IPV6_CONNECTED" not in result.stdout


def test_adversarial_reparse_point_traversal_denial(
    windows_backend: WindowsAppContainerBackend, tmp_path: Path
) -> None:
    """Adversary creates a directory junction inside workspace to escape to host files."""
    user_profile = os.environ.get("USERPROFILE", r"C:\Users\Default")
    junction_target = os.path.join(user_profile, ".ssh")
    junction_link = tmp_path / "ssh_junction"

    # Host creates junction inside the workspace
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction_link), junction_target], capture_output=True)

    script = f"""
import os, sys
target_link = r"{junction_link}"
try:
    entries = os.listdir(target_link)
    print("JUNCTION_TRAVERSED:", len(entries))
    sys.exit(0)
except Exception as e:
    print("JUNCTION_DENIED:", type(e).__name__)
    sys.exit(42)
"""
    policy = SandboxPolicy()
    result = windows_backend.run([sys.executable, "-c", script], policy, tmp_path)
    assert result.exit_code == 42
    assert "JUNCTION_DENIED" in result.stdout
    assert "JUNCTION_TRAVERSED" not in result.stdout
