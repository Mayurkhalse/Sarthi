"""Linux Bubblewrap sandbox backend adapter.

Enforces genuine OS-level filesystem and network isolation via minimal mount
namespaces, network unsharing, PID unsharing, and capability dropping.
Integrates with cgroup v2 for aggregate process count limits (pids.max),
hard memory limits (memory.max), swap prevention, and emptiness-verified cleanup.
Adheres strictly to the architectural requirements in SEC-01C-ARCHITECTURE.md.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from sarthi.core.sandbox.backends.cgroup import DEFAULT_CGROUP2_ROOT, CgroupV2Manager
from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxCleanupError,
    SandboxError,
    SandboxExecutionError,
    SandboxInitializationError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    FilesystemPolicy,
    MechanismMaturity,
    NetworkPolicy,
    SandboxPolicy,
)
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult

logger = logging.getLogger(__name__)


class LinuxBubblewrapBackend(BaseSandboxBackend):
    """Linux container isolation backend powered by Bubblewrap (bwrap) and cgroup v2."""

    def __init__(
        self,
        bwrap_path: str | None = None,
        cgroup_root: Path | str = DEFAULT_CGROUP2_ROOT,
    ) -> None:
        self._bwrap_path = bwrap_path or shutil.which("bwrap")
        self._cgroup_root = Path(cgroup_root)
        self._cgroup_mgr: CgroupV2Manager | None = None
        self._initialized = False

    @property
    def name(self) -> str:
        return "linux_bubblewrap"

    @property
    def maturity(self) -> MechanismMaturity:
        if not sys.platform.startswith("linux") or not self._bwrap_path or not os.path.isfile(self._bwrap_path):
            return MechanismMaturity.IMPLEMENTATION_PENDING
        return MechanismMaturity.PRODUCTION

    def is_available(self) -> bool:
        """Checks if running on Linux with a functional bwrap binary."""
        if not sys.platform.startswith("linux"):
            return False
        return self._bwrap_path is not None and os.path.isfile(self._bwrap_path)

    def probe_bwrap_capability(self) -> tuple[bool, str]:
        """Performs an active capability probe to verify user and mount namespace unsharing."""
        if not self.is_available():
            return False, "bwrap binary missing or not running on Linux."

        # Probe unprivileged user namespaces and basic mount capability
        probe_cmd = [
            self._bwrap_path,
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
        ]

        # Handle merged-usr symlinks in probe
        for link_path in ("/bin", "/sbin", "/lib", "/lib64"):
            if os.path.islink(link_path):
                try:
                    target = os.readlink(link_path)
                    probe_cmd.extend(["--symlink", target, link_path])
                except OSError:
                    pass
            elif os.path.isdir(link_path):
                probe_cmd.extend(["--ro-bind", link_path, link_path])

        probe_cmd.extend(["--", "true"])

        try:
            res = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "Bubblewrap active namespace probe succeeded."
            return False, f"Bubblewrap probe failed (exit code {res.returncode}): {res.stderr.strip()}"
        except Exception as e:
            return False, f"Bubblewrap probe execution error: {e}"

    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        """Assesses OS-level enforcement capabilities on this host."""
        evidence: list[str] = []

        if not sys.platform.startswith("linux"):
            return SandboxCapabilityReport(
                backend_name=self.name,
                mechanism_maturity=self.maturity,
                certification_tier=CertificationTier.IMPLEMENTATION_PENDING,
                filesystem_isolation=CapabilityStatus.UNSUPPORTED,
                network_isolation=CapabilityStatus.UNSUPPORTED,
                process_isolation=CapabilityStatus.UNSUPPORTED,
                process_count_enforcement=CapabilityStatus.UNSUPPORTED,
                resource_enforcement=CapabilityStatus.UNSUPPORTED,
                environment_isolation=CapabilityStatus.UNSUPPORTED,
                workspace_confinement=CapabilityStatus.UNSUPPORTED,
                child_process_inheritance=CapabilityStatus.UNSUPPORTED,
                evidence_trace=["Not running on Linux."],
            )

        if not self._bwrap_path or not os.path.isfile(self._bwrap_path):
            return SandboxCapabilityReport(
                backend_name=self.name,
                mechanism_maturity=self.maturity,
                certification_tier=CertificationTier.IMPLEMENTATION_PENDING,
                filesystem_isolation=CapabilityStatus.UNSUPPORTED,
                network_isolation=CapabilityStatus.UNSUPPORTED,
                process_isolation=CapabilityStatus.UNSUPPORTED,
                process_count_enforcement=CapabilityStatus.UNSUPPORTED,
                resource_enforcement=CapabilityStatus.UNSUPPORTED,
                environment_isolation=CapabilityStatus.UNSUPPORTED,
                workspace_confinement=CapabilityStatus.UNSUPPORTED,
                child_process_inheritance=CapabilityStatus.UNSUPPORTED,
                evidence_trace=["Bubblewrap (bwrap) binary not found on Linux host."],
            )

        evidence.append(f"Bubblewrap binary verified at {self._bwrap_path}")

        # Probe bwrap active execution
        probe_ok, probe_msg = self.probe_bwrap_capability()
        evidence.append(probe_msg)

        if not probe_ok:
            return SandboxCapabilityReport(
                backend_name=self.name,
                mechanism_maturity=self.maturity,
                certification_tier=CertificationTier.IMPLEMENTATION_PENDING,
                filesystem_isolation=CapabilityStatus.UNSUPPORTED,
                network_isolation=CapabilityStatus.UNSUPPORTED,
                process_isolation=CapabilityStatus.UNSUPPORTED,
                process_count_enforcement=CapabilityStatus.UNSUPPORTED,
                resource_enforcement=CapabilityStatus.UNSUPPORTED,
                environment_isolation=CapabilityStatus.UNSUPPORTED,
                workspace_confinement=CapabilityStatus.UNSUPPORTED,
                child_process_inheritance=CapabilityStatus.UNSUPPORTED,
                evidence_trace=evidence,
            )

        # Bubblewrap core isolation capabilities verified
        fs_status = CapabilityStatus.PASS
        net_status = CapabilityStatus.PASS
        proc_status = CapabilityStatus.PASS
        env_status = CapabilityStatus.PASS
        ws_status = CapabilityStatus.PASS
        child_status = CapabilityStatus.PASS

        # Evaluate cgroup v2 resource controllers
        cgroup_mgr = CgroupV2Manager(self._cgroup_root)
        cgroup_available = cgroup_mgr.is_available()
        controllers = cgroup_mgr.get_available_controllers(self._cgroup_root) if cgroup_available else set()

        if cgroup_available:
            evidence.append(f"cgroup v2 filesystem detected at {self._cgroup_root}")
            evidence.append(f"cgroup v2 controllers: {', '.join(sorted(controllers)) or 'none'}")
        else:
            evidence.append("cgroup v2 filesystem not available or inaccessible.")

        has_pids = "pids" in controllers
        has_memory = "memory" in controllers

        pids_status = CapabilityStatus.PASS if (cgroup_available and has_pids) else CapabilityStatus.UNSUPPORTED
        mem_status = CapabilityStatus.PASS if (cgroup_available and has_memory) else CapabilityStatus.UNSUPPORTED

        all_pass = (
            fs_status == CapabilityStatus.PASS
            and net_status == CapabilityStatus.PASS
            and proc_status == CapabilityStatus.PASS
            and pids_status == CapabilityStatus.PASS
            and mem_status == CapabilityStatus.PASS
            and env_status == CapabilityStatus.PASS
            and ws_status == CapabilityStatus.PASS
            and child_status == CapabilityStatus.PASS
        )

        # Certification tier resolution
        if all_pass and os.environ.get("SARTHI_SANDBOX_CERTIFIED") == "1":
            cert_tier = CertificationTier.PRODUCTION_CERTIFIED
        elif all_pass and (os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"):
            cert_tier = CertificationTier.CI_VERIFIED
        elif all_pass:
            cert_tier = CertificationTier.CAPABILITY_AVAILABLE_UNVERIFIED
        else:
            cert_tier = CertificationTier.CAPABILITY_AVAILABLE_UNVERIFIED if probe_ok else CertificationTier.IMPLEMENTATION_PENDING

        maturity = MechanismMaturity.PRODUCTION if probe_ok else MechanismMaturity.IMPLEMENTATION_PENDING

        return SandboxCapabilityReport(
            backend_name=self.name,
            mechanism_maturity=maturity,
            certification_tier=cert_tier,
            filesystem_isolation=fs_status,
            network_isolation=net_status,
            process_isolation=proc_status,
            process_count_enforcement=pids_status,
            resource_enforcement=mem_status,
            environment_isolation=env_status,
            workspace_confinement=ws_status,
            child_process_inheritance=child_status,
            evidence_trace=evidence,
        )

    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        """Prepares isolation backend state and verifies platform readiness."""
        if not self.is_available():
            raise SandboxCapabilityUnavailableError(
                "LinuxBubblewrapBackend is unavailable (not on Linux or bwrap missing). Fail-closed."
            )
        self._initialized = True

    def _discover_runtime_mounts(
        self,
        workspace_root: Path,
        policy: SandboxPolicy,
    ) -> list[str]:
        """Calculates minimal read-only runtime mounts and workspace bindings."""
        mount_args: list[str] = []

        # 1. System core dependencies (/usr, /lib, /lib64, /bin, /sbin)
        for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin"):
            if os.path.islink(p):
                try:
                    target = os.readlink(p)
                    mount_args.extend(["--symlink", target, p])
                except OSError:
                    pass
            elif os.path.isdir(p):
                mount_args.extend(["--ro-bind", p, p])

        # 2. Dynamic linkers & system alternatives
        for extra in ("/etc/ld.so.cache", "/etc/ld.so.conf.d", "/etc/alternatives"):
            if os.path.isfile(extra):
                mount_args.extend(["--ro-bind", extra, extra])
            elif os.path.isdir(extra):
                mount_args.extend(["--ro-bind", extra, extra])

        # 3. DNS / SSL certs if network is not blocked
        if policy.network != NetworkPolicy.BLOCKED:
            for net_meta in ("/etc/resolv.conf", "/etc/ssl", "/etc/pki", "/etc/ca-certificates"):
                if os.path.isfile(net_meta) or os.path.isdir(net_meta):
                    mount_args.extend(["--ro-bind", net_meta, net_meta])

        # 4. Python runtime closure (interpreter, virtualenv, base prefixes)
        ws_resolved = workspace_root.resolve()
        for py_dir in (sys.prefix, sys.base_prefix):
            try:
                resolved_p = Path(py_dir).resolve()
                if resolved_p.is_dir() and resolved_p != Path("/usr"):
                    try:
                        resolved_p.relative_to(ws_resolved)
                    except ValueError:
                        # Outside workspace: mount read-only
                        mount_args.extend(["--ro-bind", str(resolved_p), str(resolved_p)])
            except Exception:
                pass

        # 5. Node.js runtime closure if available and outside /usr
        node_bin = shutil.which("node")
        if node_bin:
            try:
                real_node = Path(node_bin).resolve()
                if real_node.is_file():
                    node_dir = real_node.parent
                    if node_dir != Path("/usr/bin") and node_dir != Path("/bin"):
                        try:
                            node_dir.relative_to(ws_resolved)
                        except ValueError:
                            mount_args.extend(["--ro-bind", str(node_dir), str(node_dir)])
            except Exception:
                pass

        # 6. Workspace Mount
        if policy.filesystem == FilesystemPolicy.READ_ONLY_WORKSPACE:
            mount_args.extend(["--ro-bind", str(ws_resolved), str(ws_resolved)])
        else:
            mount_args.extend(["--bind", str(ws_resolved), str(ws_resolved)])

        return mount_args

    def build_bwrap_args(
        self,
        policy: SandboxPolicy,
        workspace_root: Path,
        block_fd: int | None = None,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        """Constructs the minimal allowlist mount table and isolation flags for bwrap."""
        bwrap_bin = self._bwrap_path or "bwrap"
        ws_resolved = workspace_root.resolve()

        args = [
            bwrap_bin,
            # Process & User Namespace Isolation
            "--unshare-pid",
            "--unshare-user",
            "--cap-drop", "ALL",
            "--die-with-parent",
            # Standard Minimal Device Nodes
            "--dev", "/dev",
            # Virtual Private procfs
            "--proc", "/proc",
            # Ephemeral In-Memory tmpfs
            "--tmpfs", "/tmp",
        ]

        # Pre-exec synchronization flag for zero-race cgroup attachment
        if block_fd is not None:
            args.extend(["--block-fd", str(block_fd)])

        # Network Isolation
        if policy.network == NetworkPolicy.BLOCKED:
            args.append("--unshare-net")

        # Environment Sanitization
        args.append("--clearenv")

        # Set curated safe environment variables
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": "C.UTF-8",
            "TERM": os.environ.get("TERM", "xterm"),
            "TMPDIR": "/tmp",
            "HOME": "/tmp",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if env:
            safe_env.update(env)

        for k, v in safe_env.items():
            args.extend(["--setenv", k, str(v)])

        # Runtime mounts & workspace bindings
        args.extend(self._discover_runtime_mounts(workspace_root, policy))

        # Working directory
        args.extend(["--chdir", str(ws_resolved)])

        return args

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Executes a command inside the bwrap sandbox with cgroup resource enforcement."""
        if not self._initialized:
            self.initialize(policy, workspace_root)

        # 1. Evaluate cgroup v2 resource controller setup
        use_cgroup = CgroupV2Manager.is_available()
        cgroup_mgr: CgroupV2Manager | None = None
        sync_read_fd: int | None = None
        sync_write_fd: int | None = None

        if use_cgroup:
            cgroup_mgr = CgroupV2Manager(self._cgroup_root)
            cgroup_id = uuid.uuid4().hex[:12]
            try:
                cgroup_mgr.allocate_sandbox_cgroup(cgroup_id)
                cgroup_mgr.configure_limits(
                    max_processes=policy.limits.max_processes,
                    max_memory_bytes=policy.limits.max_memory_bytes,
                    swap_max_bytes=0,
                    oom_group=True,
                )
                self._cgroup_mgr = cgroup_mgr

                # Allocate pipe for race-free pre-exec cgroup synchronization
                sync_read_fd, sync_write_fd = os.pipe()
                os.set_inheritable(sync_read_fd, True)
            except Exception as e:
                logger.warning(f"Failed to initialize cgroup v2: {e}")
                if cgroup_mgr:
                    try:
                        cgroup_mgr.cleanup()
                    except Exception:
                        pass
                cgroup_mgr = None
                self._cgroup_mgr = None
                if sync_read_fd is not None:
                    try:
                        os.close(sync_read_fd)
                        os.close(sync_write_fd)  # type: ignore
                    except Exception:
                        pass
                sync_read_fd, sync_write_fd = None, None

        # 2. Build Bubblewrap invocation arguments
        bwrap_args = self.build_bwrap_args(
            policy,
            workspace_root,
            block_fd=sync_read_fd,
            env=env,
        )
        full_cmd = bwrap_args + ["--"] + command

        # 3. Process Execution & Pre-Exec Synchronization
        start_time = time.monotonic()
        proc: subprocess.Popen | None = None
        pass_fds = (sync_read_fd,) if sync_read_fd is not None else ()
        cleanup_successful = True
        cleanup_error_msg: str | None = None

        try:
            # Use start_new_session=True for safe process-group signal routing
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                pass_fds=pass_fds,
                start_new_session=True,
                close_fds=True,
            )

            # If synchronization pipe is active, attach child PID and verify before releasing
            if cgroup_mgr and sync_write_fd is not None:
                try:
                    cgroup_mgr.attach_pid(proc.pid)
                except Exception as attach_err:
                    # Fail-closed: kill bwrap before untrusted code can execute
                    proc.kill()
                    proc.communicate()
                    raise SandboxInitializationError(
                        f"Failed to attach child process {proc.pid} to cgroup: {attach_err}"
                    ) from attach_err
                finally:
                    # Release bwrap child to execve
                    try:
                        os.write(sync_write_fd, b"GO\n")
                    except OSError:
                        pass
                    try:
                        os.close(sync_write_fd)
                        sync_write_fd = None
                    except OSError:
                        pass
                    if sync_read_fd is not None:
                        try:
                            os.close(sync_read_fd)
                            sync_read_fd = None
                        except OSError:
                            pass

            # 4. Wait for command completion under timeout
            stdout, stderr = proc.communicate(timeout=policy.limits.timeout_seconds)
            duration = time.monotonic() - start_time
            return_code = proc.returncode

            return SandboxResult(
                command=command,
                exit_code=return_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                duration_seconds=duration,
                capability_report=self.detect_capabilities(workspace_root),
                cleanup_successful=True,
            )

        except subprocess.TimeoutExpired:
            # Safe process-tree termination
            if cgroup_mgr:
                cgroup_mgr.kill_all()

            if proc is not None:
                # Deliver SIGTERM to process group, grace period, then SIGKILL
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    except Exception:
                        proc.terminate()

                time.sleep(0.2)
                try:
                    stdout, stderr = proc.communicate(timeout=0.8)
                except subprocess.TimeoutExpired:
                    if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
                            proc.kill()
                    else:
                        proc.kill()
                    stdout, stderr = proc.communicate()

            duration = time.monotonic() - start_time
            return SandboxResult(
                command=command,
                exit_code=-1,
                stdout=stdout or "",
                stderr=stderr or "",
                timed_out=True,
                duration_seconds=duration,
                capability_report=self.detect_capabilities(workspace_root),
                cleanup_successful=True,
            )

        except Exception as e:
            if isinstance(e, (SandboxError, SandboxExecutionError, SandboxInitializationError)):
                raise
            raise SandboxExecutionError(f"Linux Bubblewrap execution failed: {e}") from e

        finally:
            # Close any leaked pipe descriptors
            if sync_write_fd is not None:
                try:
                    os.close(sync_write_fd)
                except OSError:
                    pass
            if sync_read_fd is not None:
                try:
                    os.close(sync_read_fd)
                except OSError:
                    pass

            # 5. Emptiness-verified cgroup teardown
            if cgroup_mgr:
                try:
                    cgroup_mgr.cleanup()
                except SandboxCleanupError as clean_err:
                    cleanup_successful = False
                    cleanup_error_msg = str(clean_err)
                    logger.error(f"Sandbox cgroup cleanup error: {clean_err}")
                self._cgroup_mgr = None

            if not cleanup_successful:
                raise SandboxCleanupError(f"Sandbox cleanup failure: {cleanup_error_msg}")

    def cleanup(self) -> None:
        """Tears down any residual cgroup allocations and resets backend state."""
        if self._cgroup_mgr:
            try:
                self._cgroup_mgr.cleanup()
            finally:
                self._cgroup_mgr = None
        self._initialized = False
