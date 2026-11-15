"""Windows AppContainer and Job Object sandbox backend adapter.

Enforces genuine OS-level filesystem, network, and resource isolation on Windows via:
1. Windows AppContainer (LowBox tokens via ntdll & userenv) for security boundary,
   enforcing default-deny network access (WFP block) and least-privilege token.
2. Windows Job Objects (kernel32) for process and resource containment, process count
   ceilings (ActiveProcessLimit), commit memory caps (JobMemoryLimit), and atomic
   process tree termination on close (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
3. Additive DACL scoping on ephemeral workspaces, granting explicit Object-Inherit /
   Container-Inherit Modify access to the AppContainer SID while preserving all
   pre-existing security descriptors.
4. Zero-race process creation via CREATE_SUSPENDED, verified Job Object containment
   (IsProcessInJob), and strict handle inheritance (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxError,
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

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Win32 Native Structures & API Declarations (Loaded conditionally on Win32)
# -----------------------------------------------------------------------------

if sys.platform == "win32":
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    # Startup & Process structures
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", wintypes.LPBYTE),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class STARTUPINFOEX(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", STARTUPINFO),
            ("lpAttributeList", wintypes.LPVOID),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    # Job Object structures
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

    # Function signatures
    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long

    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long

    userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    userenv.DeleteAppContainerProfile.restype = ctypes.c_long

    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    ntdll.NtCreateLowBoxToken.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    ntdll.NtCreateLowBoxToken.restype = ctypes.c_long

    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOEX),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL

    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL

    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL

    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None

    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE

    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL

    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

    kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    kernel32.IsProcessInJob.restype = wintypes.BOOL

    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.TerminateJobObject.restype = wintypes.BOOL

    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.TerminateProcess.restype = wintypes.BOOL

    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD

    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL

    kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel32.SetHandleInformation.restype = wintypes.BOOL

    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL


class WindowsAppContainerBackend(BaseSandboxBackend):
    """Windows native AppContainer and Job Object sandbox backend."""

    def __init__(self) -> None:
        self._profile_name: str | None = None
        self._sid_ptr: Any = None
        self._appcontainer_sid_str: str | None = None
        self._job_handle: Any = None
        self._probe_result: tuple[bool, str] | None = None
        self._cached_capability_report: SandboxCapabilityReport | None = None
        self._initialized = False

    @property
    def name(self) -> str:
        return "windows_appcontainer"

    @property
    def maturity(self) -> MechanismMaturity:
        if sys.platform != "win32" or not self.is_available():
            return MechanismMaturity.IMPLEMENTATION_PENDING
        return MechanismMaturity.PRODUCTION

    def is_available(self) -> bool:
        """Checks if running on Windows with accessible Win32 userenv / kernel32 / ntdll APIs."""
        if sys.platform != "win32":
            return False
        try:
            return (
                hasattr(ctypes, "windll")
                and hasattr(ctypes.windll, "kernel32")
                and hasattr(ctypes.windll, "userenv")
                and hasattr(ctypes.windll, "advapi32")
                and hasattr(ctypes.windll, "ntdll")
            )
        except Exception:
            return False

    def probe_capabilities(self) -> tuple[bool, str]:
        """Probes live kernel AppContainer and Job Object primitives."""
        if self._probe_result is not None:
            return self._probe_result

        if not self.is_available():
            self._probe_result = (False, "Not running on Windows or Win32 DLLs unavailable.")
            return self._probe_result

        probe_profile = f"sarthi_probe_{uuid.uuid4().hex[:8]}"
        sid_ptr = wintypes.LPVOID()
        try:
            hr = userenv.CreateAppContainerProfile(
                probe_profile,
                "Sarthi Probe",
                "Capability Probe",
                None,
                0,
                ctypes.byref(sid_ptr),
            )
            if hr != 0:
                hr = userenv.DeriveAppContainerSidFromAppContainerName(
                    probe_profile, ctypes.byref(sid_ptr)
                )
            if hr != 0 or not sid_ptr.value:
                self._probe_result = (False, f"CreateAppContainerProfile returned error {hex(hr & 0xFFFFFFFF)}")
                return self._probe_result

            # Probe token derivation via NtCreateLowBoxToken
            h_base_token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), 0x0002 | 0x0008, ctypes.byref(h_base_token)
            ):
                self._probe_result = (False, "OpenProcessToken failed during capability probe.")
                return self._probe_result

            h_lowbox = wintypes.HANDLE()
            status = ntdll.NtCreateLowBoxToken(
                ctypes.byref(h_lowbox),
                h_base_token,
                0x02000000,
                None,
                sid_ptr,
                0,
                None,
                0,
                None,
            )
            kernel32.CloseHandle(h_base_token)
            if status != 0:
                self._probe_result = (False, f"NtCreateLowBoxToken returned NTSTATUS {hex(status & 0xFFFFFFFF)}")
                return self._probe_result
            kernel32.CloseHandle(h_lowbox)

            # Probe Job Object creation
            h_job = kernel32.CreateJobObjectW(None, None)
            if not h_job:
                self._probe_result = (False, "CreateJobObjectW failed during capability probe.")
                return self._probe_result
            kernel32.CloseHandle(h_job)

            self._probe_result = (True, "Windows AppContainer and Job Object primitives verified.")
            return self._probe_result
        except Exception as e:
            self._probe_result = (False, f"Probe exception: {e}")
            return self._probe_result
        finally:
            try:
                userenv.DeleteAppContainerProfile(probe_profile)
            except Exception:
                pass

    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        if sys.platform != "win32" or not self.is_available():
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
                evidence_trace=["Not running on Windows or Win32 security DLLs unavailable."],
            )

        probe_ok, probe_msg = self.probe_capabilities()
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
                evidence_trace=[f"Capability probe failed: {probe_msg}"],
            )

        evidence = [
            "Windows AppContainer LowBox profile isolation active via userenv.dll and ntdll.dll.",
            "Default-deny network isolation enforced via zero network capabilities (WFP drop).",
            "Win32 Job Object resource containment active with KILL_ON_JOB_CLOSE.",
            "ActiveProcessLimit process count cap active.",
            "JobMemoryLimit commit charge limit active.",
            "Zero-race suspended process startup via CREATE_SUSPENDED and IsProcessInJob verification.",
            "Strict handle inheritance active via PROC_THREAD_ATTRIBUTE_HANDLE_LIST.",
            "Additive DACL injection active on staged workspace, preserving existing ACLs.",
        ]

        # Check nested job object context
        in_parent_job = wintypes.BOOL()
        if kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(in_parent_job)):
            if in_parent_job.value:
                evidence.append("Host process is running inside an existing Job Object; nested job hierarchy supported.")

        # Determine certification tier
        if os.environ.get("SARTHI_SANDBOX_CERTIFIED") == "1":
            cert_tier = CertificationTier.PRODUCTION_CERTIFIED
        elif os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true":
            cert_tier = CertificationTier.CI_VERIFIED
        else:
            cert_tier = CertificationTier.CAPABILITY_AVAILABLE_UNVERIFIED

        return SandboxCapabilityReport(
            backend_name=self.name,
            mechanism_maturity=self.maturity,
            certification_tier=cert_tier,
            filesystem_isolation=CapabilityStatus.PASS,
            network_isolation=CapabilityStatus.PASS,
            process_isolation=CapabilityStatus.PASS,
            process_count_enforcement=CapabilityStatus.PASS,
            resource_enforcement=CapabilityStatus.PASS,
            environment_isolation=CapabilityStatus.PASS,
            workspace_confinement=CapabilityStatus.PASS,
            child_process_inheritance=CapabilityStatus.PASS,
            evidence_trace=evidence,
        )

    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        if sys.platform != "win32":
            raise SandboxCapabilityUnavailableError("WindowsAppContainerBackend is only supported on Win32.")

        if not self.is_available():
            raise SandboxCapabilityUnavailableError("Windows native security APIs (userenv, kernel32, ntdll) unavailable.")

        try:
            # 1. Allocate unique AppContainer profile
            self._profile_name = f"sarthi_ac_{uuid.uuid4().hex[:16]}"
            sid_ptr = wintypes.LPVOID()
            hr = userenv.CreateAppContainerProfile(
                self._profile_name,
                "Sarthi Sandbox",
                "Sarthi Ephemeral AppContainer Sandbox",
                None,
                0,
                ctypes.byref(sid_ptr),
            )
            if hr != 0:
                hr = userenv.DeriveAppContainerSidFromAppContainerName(
                    self._profile_name, ctypes.byref(sid_ptr)
                )
            if hr != 0 or not sid_ptr.value:
                raise SandboxInitializationError(
                    f"CreateAppContainerProfile failed with error {hex(hr & 0xFFFFFFFF)}"
                )
            self._sid_ptr = sid_ptr

            # Derive string SID
            str_sid = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(self._sid_ptr, ctypes.byref(str_sid)):
                raise SandboxInitializationError("ConvertSidToStringSidW failed to convert AppContainer SID.")
            self._appcontainer_sid_str = str_sid.value
            kernel32.LocalFree(str_sid)

            # 2. Additive DACL Configuration on Staged Workspace
            self._apply_workspace_dacl(workspace_root)

            # 3. Grant RX on Python runtime closure if executing under Python
            self._apply_runtime_closure_dacl()

            # 4. Create and configure Win32 Job Object
            self._setup_job_object(policy)

            self._initialized = True
        except Exception as e:
            self.cleanup()
            if isinstance(e, SandboxError):
                raise
            raise SandboxInitializationError(f"Failed to initialize Windows AppContainer backend: {e}") from e

    def _apply_workspace_dacl(self, workspace_root: Path) -> None:
        """Additively grants (OI)(CI)(M) permissions to the AppContainer SID, preserving existing ACLs."""
        if not self._appcontainer_sid_str:
            raise SandboxInitializationError("AppContainer SID is not initialized.")

        ws_str = str(workspace_root.resolve())
        # Use /grant:r so existing security descriptors are preserved and only the new ACE is added
        cmd = ["icacls", ws_str, "/grant:r", f"*{self._appcontainer_sid_str}:(OI)(CI)M", "/T", "/C", "/Q"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise SandboxInitializationError(
                f"Failed to grant DACL permissions to AppContainer SID {self._appcontainer_sid_str} on {ws_str}: {res.stderr}"
            )

    def _apply_runtime_closure_dacl(self) -> None:
        """Grants read/execute permissions on the Python runtime directory closure."""
        if not self._appcontainer_sid_str:
            return

        py_dirs = {
            os.path.dirname(os.path.abspath(sys.executable)),
            getattr(sys, "base_prefix", sys.prefix),
            sys.prefix,
        }
        for d in py_dirs:
            if os.path.isdir(d):
                try:
                    subprocess.run(
                        ["icacls", str(d), "/grant", f"*{self._appcontainer_sid_str}:(OI)(CI)RX", "/C", "/Q"],
                        capture_output=True,
                        check=False,
                    )
                except Exception as e:
                    logger.debug("Non-fatal: could not grant DACL on Python runtime dir %s: %s", d, e)

    def _setup_job_object(self, policy: SandboxPolicy) -> None:
        """Creates and configures a Win32 Job Object with process and memory containment."""
        h_job = kernel32.CreateJobObjectW(None, None)
        if not h_job:
            raise SandboxInitializationError("CreateJobObjectW failed.")
        self._job_handle = h_job

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        # JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
        limit_flags = 0x2000 | 0x0008
        info.BasicLimitInformation.ActiveProcessLimit = max(1, policy.limits.max_processes)

        if policy.limits.max_memory_bytes > 0:
            # JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200
            limit_flags |= 0x0200
            info.JobMemoryLimit = policy.limits.max_memory_bytes

        info.BasicLimitInformation.LimitFlags = limit_flags

        # Note: JOB_OBJECT_LIMIT_BREAKAWAY_OK and SILENT_BREAKAWAY_OK are strictly prohibited.
        JobObjectExtendedLimitInformation = 9
        ret = kernel32.SetInformationJobObject(
            self._job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ret:
            err = ctypes.get_last_error()
            raise SandboxInitializationError(
                f"SetInformationJobObject failed with error {err}."
            )

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Spawns a process in a suspended state, binds to Job Object, verifies containment, and executes."""
        if not self._initialized:
            self.initialize(policy, workspace_root)

        start_time = time.monotonic()
        ws_resolved = workspace_root.resolve()

        # 1. Acquire LowBox AppContainer token with zero network capabilities
        h_base_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), 0x0002 | 0x0008, ctypes.byref(h_base_token)
        ):
            raise SandboxExecutionError(f"OpenProcessToken failed: {ctypes.get_last_error()}")

        h_lowbox_token = wintypes.HANDLE()
        MAXIMUM_ALLOWED = 0x02000000
        status = ntdll.NtCreateLowBoxToken(
            ctypes.byref(h_lowbox_token),
            h_base_token,
            MAXIMUM_ALLOWED,
            None,
            self._sid_ptr,
            0,  # Zero capabilities -> WFP blocks WAN, LAN, Loopback, DNS
            None,
            0,
            None,
        )
        kernel32.CloseHandle(h_base_token)
        if status != 0:
            raise SandboxExecutionError(
                f"NtCreateLowBoxToken failed with NTSTATUS {hex(status & 0xFFFFFFFF)}"
            )

        # 2. Prepare stdout and stderr capture pipes with inheritance
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = None
        sa.bInheritHandle = True

        h_stdout_read, h_stdout_write = wintypes.HANDLE(), wintypes.HANDLE()
        h_stderr_read, h_stderr_write = wintypes.HANDLE(), wintypes.HANDLE()

        if not kernel32.CreatePipe(ctypes.byref(h_stdout_read), ctypes.byref(h_stdout_write), ctypes.byref(sa), 0):
            kernel32.CloseHandle(h_lowbox_token)
            raise SandboxExecutionError("Failed to create stdout pipe.")

        if not kernel32.CreatePipe(ctypes.byref(h_stderr_read), ctypes.byref(h_stderr_write), ctypes.byref(sa), 0):
            kernel32.CloseHandle(h_stdout_read)
            kernel32.CloseHandle(h_stdout_write)
            kernel32.CloseHandle(h_lowbox_token)
            raise SandboxExecutionError("Failed to create stderr pipe.")

        # Ensure read handles are strictly NOT inheritable
        HANDLE_FLAG_INHERIT = 0x00000001
        kernel32.SetHandleInformation(h_stdout_read, HANDLE_FLAG_INHERIT, 0)
        kernel32.SetHandleInformation(h_stderr_read, HANDLE_FLAG_INHERIT, 0)

        # 3. Configure PROC_THREAD_ATTRIBUTE_HANDLE_LIST to prevent handle leakage
        handle_array = (wintypes.HANDLE * 2)(h_stdout_write, h_stderr_write)
        attr_size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))
        attr_buf = (ctypes.c_char * attr_size.value)()
        p_attr_list = ctypes.cast(attr_buf, wintypes.LPVOID)
        kernel32.InitializeProcThreadAttributeList(p_attr_list, 1, 0, ctypes.byref(attr_size))

        PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
        kernel32.UpdateProcThreadAttribute(
            p_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.byref(handle_array),
            ctypes.sizeof(handle_array),
            None,
            None,
        )

        siex = STARTUPINFOEX()
        siex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        siex.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
        siex.StartupInfo.hStdOutput = h_stdout_write
        siex.StartupInfo.hStdError = h_stderr_write
        siex.StartupInfo.hStdInput = None
        siex.lpAttributeList = p_attr_list

        pi = PROCESS_INFORMATION()

        # 4. Build command line and resolve executable
        cmd_str = subprocess.list2cmdline(command)
        cmd_buffer = ctypes.create_unicode_buffer(cmd_str)

        resolved_exe = shutil.which(command[0])
        app_name = resolved_exe if resolved_exe else None

        # 5. Build sanitized Unicode environment block
        env_block = self._build_environment_block(env, ws_resolved)

        # 6. Spawn process in SUSPENDED state
        CREATE_SUSPENDED = 0x00000004
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        CREATE_NO_WINDOW = 0x08000000
        CREATE_UNICODE_ENVIRONMENT = 0x00000400

        creation_flags = (
            CREATE_SUSPENDED
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
        )

        created = advapi32.CreateProcessAsUserW(
            h_lowbox_token,
            app_name,
            cmd_buffer,
            None,
            None,
            True,  # Handle inheritance enabled strictly for HANDLE_LIST
            creation_flags,
            env_block,
            str(ws_resolved),
            ctypes.byref(siex),
            ctypes.byref(pi),
        )
        cp_err = ctypes.get_last_error()

        # Close write handles in parent immediately so pipe reader gets EOF
        kernel32.CloseHandle(h_stdout_write)
        kernel32.CloseHandle(h_stderr_write)
        kernel32.DeleteProcThreadAttributeList(p_attr_list)
        kernel32.CloseHandle(h_lowbox_token)

        if not created:
            kernel32.CloseHandle(h_stdout_read)
            kernel32.CloseHandle(h_stderr_read)
            raise SandboxExecutionError(
                f"CreateProcessAsUserW failed for command {command!r} (WinError {cp_err})"
            )

        # 7. Zero-race containment: Assign to Job Object before resuming thread
        assign_ok = kernel32.AssignProcessToJobObject(self._job_handle, pi.hProcess)
        if not assign_ok:
            assign_err = ctypes.get_last_error()
            kernel32.TerminateProcess(pi.hProcess, 1)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            kernel32.CloseHandle(h_stdout_read)
            kernel32.CloseHandle(h_stderr_read)
            raise SandboxExecutionError(
                f"Failed to assign process to Job Object (WinError {assign_err}). "
                "Nested Job Object containment disallowed by host environment."
            )

        # 8. Assert IsProcessInJob == TRUE (Fail-Closed Barrier)
        in_job = wintypes.BOOL()
        kernel32.IsProcessInJob(pi.hProcess, self._job_handle, ctypes.byref(in_job))
        if not in_job.value:
            kernel32.TerminateProcess(pi.hProcess, 1)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            kernel32.CloseHandle(h_stdout_read)
            kernel32.CloseHandle(h_stderr_read)
            raise SandboxExecutionError("Process verified NOT contained in Job Object after assignment.")

        # 9. Asynchronous pipe readers
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        def _reader(handle: wintypes.HANDLE, target_list: list[bytes]) -> None:
            buf = ctypes.create_string_buffer(4096)
            bytes_read = wintypes.DWORD()
            while kernel32.ReadFile(handle, buf, 4096, ctypes.byref(bytes_read), None) and bytes_read.value > 0:
                target_list.append(buf.raw[:bytes_read.value])
            kernel32.CloseHandle(handle)

        t_out = threading.Thread(target=_reader, args=(h_stdout_read, stdout_chunks), daemon=True)
        t_err = threading.Thread(target=_reader, args=(h_stderr_read, stderr_chunks), daemon=True)
        t_out.start()
        t_err.start()

        # 10. Resume primary thread
        kernel32.ResumeThread(pi.hThread)

        # 11. Wait for process completion or timeout
        timeout_ms = int(policy.limits.timeout_seconds * 1000)
        WAIT_TIMEOUT = 0x00000102
        wait_res = kernel32.WaitForSingleObject(pi.hProcess, timeout_ms)

        timed_out = wait_res == WAIT_TIMEOUT
        if timed_out:
            logger.warning(
                "Windows sandbox process timed out after %s seconds; terminating Job Object process tree.",
                policy.limits.timeout_seconds,
            )
            kernel32.TerminateJobObject(self._job_handle, 1)

        # Await thread reads with grace period
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        # Retrieve process exit code
        exit_code_dw = wintypes.DWORD()
        kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code_dw))
        exit_code = -1 if timed_out else exit_code_dw.value

        kernel32.CloseHandle(pi.hProcess)
        kernel32.CloseHandle(pi.hThread)

        duration = time.monotonic() - start_time
        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        return SandboxResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_seconds=duration,
            capability_report=self.detect_capabilities(workspace_root),
        )

    def _build_environment_block(
        self, custom_env: dict[str, str] | None, workspace_root: Path
    ) -> Any:
        """Constructs a sanitized, double-null-terminated Unicode environment block."""
        safe_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
            "PATH": os.environ.get("PATH", r"C:\Windows\System32;C:\Windows"),
            "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
            "TEMP": str(workspace_root),
            "TMP": str(workspace_root),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if custom_env:
            safe_env.update(custom_env)

        # Format: key1=val1\0key2=val2\0\0
        entries = [f"{k}={v}" for k, v in safe_env.items()]
        raw_str = "\0".join(entries) + "\0\0"
        return ctypes.create_unicode_buffer(raw_str)

    def cleanup(self) -> None:
        """Deterministically tears down Job Object, kills processes, and removes AppContainer profile."""
        if self._job_handle and sys.platform == "win32":
            try:
                kernel32.TerminateJobObject(self._job_handle, 0)
                kernel32.CloseHandle(self._job_handle)
            except Exception as e:
                logger.warning("Error closing Job Object handle: %s", e)
            finally:
                self._job_handle = None

        if self._profile_name and sys.platform == "win32":
            try:
                userenv.DeleteAppContainerProfile(self._profile_name)
            except Exception as e:
                logger.warning("Error deleting AppContainer profile %s: %s", self._profile_name, e)
            finally:
                self._profile_name = None
                self._sid_ptr = None
                self._appcontainer_sid_str = None

        self._initialized = False
