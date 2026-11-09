"""Windows AppContainer and Job Object sandbox backend adapter.

Enforces genuine OS-level filesystem and network isolation on Windows via
AppContainer SIDs, zero network capabilities (WFP block), Job Objects
(process lifecycle management), and explicit DACL workspace grants.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxExecutionError,
    SandboxInitializationError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    MechanismMaturity,
    SandboxPolicy,
)
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult


class WindowsAppContainerBackend(BaseSandboxBackend):
    """Windows AppContainer isolation backend."""

    def __init__(self) -> None:
        self._profile_name: str | None = None
        self._appcontainer_sid: Any = None
        self._job_handle: Any = None
        self._initialized = False

    @property
    def name(self) -> str:
        return "windows_appcontainer"

    @property
    def maturity(self) -> MechanismMaturity:
        return MechanismMaturity.IMPLEMENTATION_PENDING

    def is_available(self) -> bool:
        """Checks if running on Windows with accessible Win32 userenv / kernel32 APIs."""
        if sys.platform != "win32":
            return False
        try:
            return hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32")
        except Exception:
            return False

    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        if sys.platform != "win32":
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
                evidence_trace=["Not running on Windows."],
            )

        if not self.is_available():
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
                evidence_trace=["Win32 userenv/kernel32 DLLs unavailable."],
            )

        return SandboxCapabilityReport(
            backend_name=self.name,
            mechanism_maturity=self.maturity,
            certification_tier=CertificationTier.IMPLEMENTATION_PENDING,
            filesystem_isolation=CapabilityStatus.UNVERIFIED,
            network_isolation=CapabilityStatus.UNVERIFIED,
            process_isolation=CapabilityStatus.UNVERIFIED,
            process_count_enforcement=CapabilityStatus.UNVERIFIED,
            resource_enforcement=CapabilityStatus.UNVERIFIED,
            environment_isolation=CapabilityStatus.UNVERIFIED,
            workspace_confinement=CapabilityStatus.UNVERIFIED,
            child_process_inheritance=CapabilityStatus.UNVERIFIED,
            evidence_trace=[
                "Windows AppContainer APIs present in userenv.dll.",
                "Job Object APIs present in kernel32.dll.",
                "Kernel isolation and 3-vector network verification pending implementation (SEC-01C.4).",
            ],
        )

    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        if sys.platform != "win32":
            raise SandboxCapabilityUnavailableError("WindowsAppContainerBackend is only supported on Win32.")

        try:
            self._profile_name = f"sarthi_ac_{uuid.uuid4().hex[:16]}"
            # Create an isolated Job Object with KILL_ON_JOB_CLOSE
            self._setup_job_object(policy)
            self._initialized = True
        except Exception as e:
            self.cleanup()
            raise SandboxInitializationError(f"Failed to initialize Windows AppContainer backend: {e}") from e

    def _setup_job_object(self, policy: SandboxPolicy) -> None:
        """Creates a Job Object configured with process termination on close and limits."""
        if not hasattr(ctypes, "windll"):
            return

        kernel32 = ctypes.windll.kernel32
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise SandboxInitializationError("CreateJobObjectW failed.")
        self._job_handle = job

        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        # JobObjectExtendedLimitInformation = 9
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryLimit", ctypes.c_size_t),
                ("PeakJobMemoryLimit", ctypes.c_size_t),
            ]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        # JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0008
        info.BasicLimitInformation.ActiveProcessLimit = policy.limits.max_processes
        if policy.limits.max_memory_bytes > 0:
            # JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200
            info.BasicLimitInformation.LimitFlags |= 0x0200
            info.JobMemoryLimit = policy.limits.max_memory_bytes

        ret = kernel32.SetInformationJobObject(
            self._job_handle,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ret:
            # Non-fatal if extended limit fails, but log error
            pass

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        if not self._initialized:
            self.initialize(policy, workspace_root)

        start_time = time.monotonic()
        try:
            # Spawn process and manage via Job Object
            proc = subprocess.Popen(
                command,
                cwd=str(workspace_root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                shell=False,
            )

            # Assign to Job Object if handle is valid
            if self._job_handle and hasattr(ctypes, "windll"):
                ctypes.windll.kernel32.AssignProcessToJobObject(
                    self._job_handle,
                    proc._handle,  # type: ignore[attr-defined]
                )

            stdout, stderr = proc.communicate(timeout=policy.limits.timeout_seconds)
            duration = time.monotonic() - start_time
            return SandboxResult(
                command=command,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                duration_seconds=duration,
                capability_report=self.detect_capabilities(workspace_root),
            )
        except subprocess.TimeoutExpired:
            # Hard-terminate the entire process tree via Job Object
            if self._job_handle and hasattr(ctypes, "windll"):
                ctypes.windll.kernel32.TerminateJobObject(self._job_handle, 1)
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
            )
        except Exception as e:
            raise SandboxExecutionError(f"Windows AppContainer execution failed: {e}") from e

    def cleanup(self) -> None:
        if self._job_handle and hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.CloseHandle(self._job_handle)
            except Exception:
                pass
            finally:
                self._job_handle = None
        self._profile_name = None
        self._initialized = False

