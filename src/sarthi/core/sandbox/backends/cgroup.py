"""cgroup v2 resource controller management for Sarthi Linux sandboxing.

Enforces aggregate process count limits (pids.max), hard memory allocations
(memory.max), disk swap prevention (memory.swap.max = 0), atomic cgroup-wide
OOM termination (memory.oom.group = 1), and emptiness-verified teardown.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path

from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxCleanupError,
    SandboxInitializationError,
)

logger = logging.getLogger(__name__)

DEFAULT_CGROUP2_ROOT = Path("/sys/fs/cgroup")


class CgroupV2Manager:
    """Manages ephemeral cgroup v2 subtrees for sandboxed process trees."""

    def __init__(
        self,
        cgroup_root: Path | str = DEFAULT_CGROUP2_ROOT,
        cgroup_id: str | None = None,
    ) -> None:
        self.cgroup_root = Path(cgroup_root)
        self.cgroup_id = cgroup_id
        self.cgroup_path: Path | None = None
        self._created = False

    @staticmethod
    def is_available() -> bool:
        """Checks if cgroup v2 filesystem is mounted and accessible on this Linux host."""
        if not sys.platform.startswith("linux"):
            return False
        controllers_file = DEFAULT_CGROUP2_ROOT / "cgroup.controllers"
        return controllers_file.is_file()

    @classmethod
    def get_available_controllers(cls, root: Path | str = DEFAULT_CGROUP2_ROOT) -> set[str]:
        """Returns the set of available resource controllers enabled at root."""
        controllers_file = Path(root) / "cgroup.controllers"
        if not controllers_file.is_file():
            return set()
        try:
            content = controllers_file.read_text(encoding="utf-8").strip()
            return set(content.split())
        except Exception:
            return set()

    @classmethod
    def get_current_process_cgroup_dir(cls, root: Path | str = DEFAULT_CGROUP2_ROOT) -> Path | None:
        """Resolves the current process's cgroup v2 directory from /proc/self/cgroup."""
        proc_cgroup = Path("/proc/self/cgroup")
        if not proc_cgroup.is_file():
            return None
        try:
            # cgroup v2 entry format: 0::<relative_path>
            for line in proc_cgroup.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split("::", 1)
                if len(parts) == 2 and parts[0] == "0":
                    rel_path = parts[1].lstrip("/")
                    target = Path(root) / rel_path
                    if target.is_dir():
                        return target
            return None
        except Exception:
            return None

    @classmethod
    def is_delegated(cls, root: Path | str = DEFAULT_CGROUP2_ROOT) -> bool:
        """Checks if current process has write permissions to create sub-cgroups in its delegated slice."""
        if not cls.is_available():
            return False
        parent_dir = cls.get_current_process_cgroup_dir(root) or Path(root)
        try:
            return os.access(parent_dir, os.W_OK)
        except Exception:
            return False

    def allocate_sandbox_cgroup(self, cgroup_id: str) -> Path:
        """Provisions a dedicated child cgroup under the current process's slice or delegated root."""
        if not self.is_available():
            raise SandboxCapabilityUnavailableError("cgroup v2 is not available on this host. Fail-closed.")

        self.cgroup_id = cgroup_id
        parent_dir = self.get_current_process_cgroup_dir(self.cgroup_root) or self.cgroup_root

        # Verify parent directory is writable before attempting allocation
        if not os.access(parent_dir, os.W_OK):
            raise SandboxCapabilityUnavailableError(
                f"cgroup v2 parent directory '{parent_dir}' is not writable by current user (delegation missing). Fail-closed."
            )

        target_cgroup = parent_dir / f"sarthi-sandbox-{cgroup_id}"
        try:
            # Enable controllers in parent if needed
            subtree_control = parent_dir / "cgroup.subtree_control"
            if subtree_control.is_file():
                try:
                    # Request pids and memory in child subtrees
                    available = self.get_available_controllers(self.cgroup_root)
                    controllers_to_enable = []
                    if "pids" in available:
                        controllers_to_enable.append("+pids")
                    if "memory" in available:
                        controllers_to_enable.append("+memory")
                    if controllers_to_enable:
                        subtree_control.write_text(" ".join(controllers_to_enable), encoding="utf-8")
                except Exception as e:
                    logger.debug(f"Could not write to cgroup.subtree_control: {e}")

            target_cgroup.mkdir(parents=True, exist_ok=True)
            self.cgroup_path = target_cgroup
            self._created = True
            return target_cgroup
        except OSError as e:
            raise SandboxInitializationError(
                f"Failed to create cgroup v2 directory '{target_cgroup}': {e}"
            ) from e

    def configure_limits(
        self,
        max_processes: int | None = 64,
        max_memory_bytes: int | None = 1024 * 1024 * 1024,
        swap_max_bytes: int = 0,
        oom_group: bool = True,
    ) -> None:
        """Applies resource caps to the configured cgroup."""
        if not self.cgroup_path or not self.cgroup_path.is_dir():
            raise SandboxInitializationError("Cannot configure limits: cgroup directory is not initialized.")

        # 1. Process ceiling: pids.max
        if max_processes is not None:
            pids_max_file = self.cgroup_path / "pids.max"
            if pids_max_file.is_file():
                try:
                    pids_max_file.write_text(str(max_processes), encoding="utf-8")
                except OSError as e:
                    raise SandboxInitializationError(f"Failed to set cgroup v2 pids.max={max_processes}: {e}") from e

        # 2. Hard memory cap: memory.max
        if max_memory_bytes is not None:
            mem_max_file = self.cgroup_path / "memory.max"
            if mem_max_file.is_file():
                try:
                    mem_max_file.write_text(str(max_memory_bytes), encoding="utf-8")
                except OSError as e:
                    raise SandboxInitializationError(
                        f"Failed to set cgroup v2 memory.max={max_memory_bytes}: {e}"
                    ) from e

        # 3. Swap prevention: memory.swap.max = 0 (optional if swap controller enabled)
        swap_max_file = self.cgroup_path / "memory.swap.max"
        if swap_max_file.is_file():
            try:
                swap_max_file.write_text(str(swap_max_bytes), encoding="utf-8")
            except Exception as e:
                logger.debug(f"Could not set memory.swap.max: {e}")

        # 4. Atomic workload termination: memory.oom.group = 1
        if oom_group:
            oom_group_file = self.cgroup_path / "memory.oom.group"
            if oom_group_file.is_file():
                try:
                    oom_group_file.write_text("1", encoding="utf-8")
                except Exception as e:
                    logger.debug(f"Could not set memory.oom.group: {e}")

    def attach_pid(self, pid: int) -> None:
        """Assigns a process PID to the cgroup before untrusted code begins executing."""
        if not self.cgroup_path or not self.cgroup_path.is_dir():
            raise SandboxInitializationError("Cannot attach PID: cgroup directory not initialized.")

        procs_file = self.cgroup_path / "cgroup.procs"
        if not procs_file.is_file():
            raise SandboxInitializationError(f"cgroup.procs missing at {procs_file}")

        try:
            procs_file.write_text(str(pid), encoding="utf-8")
        except OSError as e:
            raise SandboxInitializationError(f"Failed to attach PID {pid} to cgroup: {e}") from e

        # Verify child is definitively attached
        if not self.verify_pid_attached(pid):
            raise SandboxInitializationError(
                f"PID {pid} was written to cgroup.procs but verification failed."
            )

    def verify_pid_attached(self, pid: int) -> bool:
        """Verifies that the target PID appears in cgroup.procs."""
        if not self.cgroup_path:
            return False
        procs_file = self.cgroup_path / "cgroup.procs"
        if not procs_file.is_file():
            return False
        try:
            pids = procs_file.read_text(encoding="utf-8").split()
            return str(pid) in pids
        except Exception:
            return False

    def kill_all(self) -> None:
        """Atomically terminates all processes assigned to this cgroup."""
        if not self.cgroup_path or not self.cgroup_path.is_dir():
            return

        # Kernel 5.14+ atomic termination interface
        kill_file = self.cgroup_path / "cgroup.kill"
        if kill_file.is_file():
            try:
                kill_file.write_text("1", encoding="utf-8")
                return
            except Exception as e:
                logger.debug(f"cgroup.kill failed, falling back to process enumeration: {e}")

        # Pre-5.14 fallback: enumerate cgroup.procs and issue SIGKILL
        procs_file = self.cgroup_path / "cgroup.procs"
        if procs_file.is_file():
            try:
                pids_str = procs_file.read_text(encoding="utf-8").split()
                for pid_s in pids_str:
                    try:
                        os.kill(int(pid_s), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except Exception:
                pass

    def cleanup(self, drain_timeout: float = 2.0) -> None:
        """Verifies all member processes have exited, then removes the ephemeral cgroup directory."""
        if not self.cgroup_path or not self.cgroup_path.is_dir():
            self.cgroup_path = None
            return

        target_path = self.cgroup_path

        # Supervisor isolation guard: NEVER kill or rmdir root cgroups
        if target_path == self.cgroup_root or target_path == Path("/"):
            logger.error("Refusing to clean root cgroup directory.")
            return

        # Verify supervisor's own PID is not in this sandbox cgroup
        supervisor_pid = os.getpid()
        if self.verify_pid_attached(supervisor_pid):
            logger.error("Supervisor PID found in sandbox cgroup. Refusing cleanup.")
            return

        # Step 1: Kill any remaining tasks
        self.kill_all()

        # Step 2: Poll cgroup.events for 'populated 0' within drain timeout
        start = time.monotonic()
        events_file = target_path / "cgroup.events"
        procs_file = target_path / "cgroup.procs"

        while time.monotonic() - start < drain_timeout:
            is_empty = False
            if events_file.is_file():
                try:
                    events_text = events_file.read_text(encoding="utf-8")
                    if "populated 0" in events_text:
                        is_empty = True
                except Exception:
                    pass
            elif procs_file.is_file():
                try:
                    pids = procs_file.read_text(encoding="utf-8").strip()
                    if not pids:
                        is_empty = True
                except Exception:
                    pass

            if is_empty:
                break
            time.sleep(0.05)

        # Step 3: Remove cgroup directory
        try:
            os.rmdir(target_path)
            self.cgroup_path = None
        except OSError as e:
            residual_pids = ""
            if procs_file.is_file():
                try:
                    residual_pids = procs_file.read_text(encoding="utf-8").replace("\n", " ").strip()
                except Exception:
                    pass
            raise SandboxCleanupError(
                f"Failed to remove cgroup directory '{target_path}' (residual PIDs: [{residual_pids}]): {e}"
            ) from e

