"""Central Sandbox Manager for Sarthi OS-level subprocess isolation.

Acts as the primary orchestrator, policy validator, and platform dispatcher.
Enforces strict fail-closed security invariants across all execution paths.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sarthi.core.sandbox.backends.linux import LinuxBubblewrapBackend
from sarthi.core.sandbox.backends.macos import MacOSSeatbeltBackend
from sarthi.core.sandbox.backends.null import NullSandboxBackend
from sarthi.core.sandbox.backends.windows import WindowsAppContainerBackend
from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxCleanupError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    FilesystemPolicy,
    MechanismMaturity,
    NetworkPolicy,
    SandboxPolicy,
)
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult
from sarthi.core.sandbox.staging import WorkspaceStagingManager
from sarthi.core.verify.trust import build_sanitized_subprocess_env


class SandboxManager:
    """Central manager responsible for platform backend selection and policy enforcement."""

    def __init__(self, backend: BaseSandboxBackend | None = None) -> None:
        self.backend = backend or self._detect_default_backend()

    @staticmethod
    def _detect_default_backend() -> BaseSandboxBackend:
        """Selects the native backend for the host operating system."""
        if sys.platform == "win32":
            return WindowsAppContainerBackend()
        elif sys.platform.startswith("linux"):
            return LinuxBubblewrapBackend()
        elif sys.platform == "darwin":
            return MacOSSeatbeltBackend()
        return NullSandboxBackend()

    def get_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        """Returns the isolation capabilities of the active backend on this host."""
        return self.backend.detect_capabilities(project_root)

    def validate_policy(self, policy: SandboxPolicy, project_root: Path) -> SandboxCapabilityReport:
        """Evaluates whether the backend supports the requested isolation policy.

        Raises:
            SandboxCapabilityUnavailableError: If a required capability is unsupported or deprecated.
        """
        report = self.get_capabilities(project_root)

        # Fail-closed check: Implementation pending mechanisms
        if report.mechanism_maturity == MechanismMaturity.IMPLEMENTATION_PENDING:
            raise SandboxCapabilityUnavailableError(
                f"Active sandbox backend '{report.backend_name}' implementation is pending (SEC-01C). "
                "Execution refused (fail-closed)."
            )

        # Fail-closed check: Deprecated mechanisms
        if report.mechanism_maturity == MechanismMaturity.DEPRECATED and not policy.allow_deprecated_mechanisms:
            raise SandboxCapabilityUnavailableError(
                f"Active sandbox backend '{report.backend_name}' uses vendor-deprecated primitives. "
                "Execution refused (fail-closed). Set allow_deprecated_mechanisms=True to override."
            )

        if report.mechanism_maturity == MechanismMaturity.LEGACY_UNSUPPORTED:
            raise SandboxCapabilityUnavailableError(
                f"Active sandbox backend '{report.backend_name}' is unsupported. Execution refused (fail-closed)."
            )

        # Fail-closed check: Filesystem isolation requirement (mandatory)
        if policy.filesystem in (FilesystemPolicy.STAGED_ISOLATED, FilesystemPolicy.READ_ONLY_WORKSPACE):
            if report.filesystem_isolation != CapabilityStatus.PASS:
                raise SandboxCapabilityUnavailableError(
                    f"Backend '{report.backend_name}' filesystem isolation is {report.filesystem_isolation.value} "
                    "(requires PASS). Fail-closed."
                )

        # Fail-closed check: Network isolation requirement (mandatory when blocked)
        if policy.network == NetworkPolicy.BLOCKED:
            if report.network_isolation != CapabilityStatus.PASS:
                raise SandboxCapabilityUnavailableError(
                    f"Backend '{report.backend_name}' network isolation is {report.network_isolation.value} "
                    "(requires PASS). Fail-closed."
                )

        # Fail-closed check: Process count limit requirement
        if policy.limits.max_processes and report.process_count_enforcement != CapabilityStatus.PASS:
            raise SandboxCapabilityUnavailableError(
                f"Backend '{report.backend_name}' process count enforcement is {report.process_count_enforcement.value} "
                "(requires PASS). Fail-closed."
            )

        # Fail-closed check: Resource enforcement requirement
        if policy.limits.max_memory_bytes and report.resource_enforcement != CapabilityStatus.PASS:
            raise SandboxCapabilityUnavailableError(
                f"Backend '{report.backend_name}' memory resource enforcement is {report.resource_enforcement.value} "
                "(requires PASS). Fail-closed."
            )

        return report

    def run(
        self,
        command: list[str],
        project_root: Path | str,
        policy: SandboxPolicy | None = None,
        custom_env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Executes a command inside the OS-enforced sandbox boundary.

        Enforces policy validation, workspace staging (if configured), environment
        sanitization, and guaranteed backend cleanup.

        Raises:
            SandboxCapabilityUnavailableError: If capabilities are missing.
            SandboxInitializationError: If backend initialization fails.
            SandboxError: On execution failure.
        """
        root = Path(project_root).resolve()
        active_policy = policy or SandboxPolicy.default_strict()

        # Step 1: Validate policy against backend capabilities
        capability_report = self.validate_policy(active_policy, root)

        # Step 2: Prepare sanitized environment
        safe_env = build_sanitized_subprocess_env(root, base_env=custom_env)
        if active_policy.extra_env:
            safe_env.update(active_policy.extra_env)

        # Step 3: Handle workspace staging if required
        if active_policy.filesystem == FilesystemPolicy.STAGED_ISOLATED:
            with WorkspaceStagingManager(root) as staged_path:
                return self._execute_sandboxed(command, active_policy, staged_path, safe_env, capability_report)
        else:
            return self._execute_sandboxed(command, active_policy, root, safe_env, capability_report)

    def _execute_sandboxed(
        self,
        command: list[str],
        policy: SandboxPolicy,
        target_dir: Path,
        env: dict[str, str],
        capability_report: SandboxCapabilityReport,
    ) -> SandboxResult:
        """Coordinates initialization, execution, and cleanup with guaranteed teardown."""
        result: SandboxResult | None = None
        exec_exc: Exception | None = None
        try:
            self.backend.initialize(policy, target_dir)
            result = self.backend.run(command, policy, target_dir, env=env)
            result.capability_report = capability_report
            return result
        except Exception as e:
            exec_exc = e
            raise
        finally:
            try:
                self.backend.cleanup()
            except Exception as cleanup_exc:
                if result is not None:
                    result.cleanup_successful = False
                    result.evidence_trace.append(f"Cleanup failure: {cleanup_exc}")
                if exec_exc is None and result is None:
                    raise SandboxCleanupError(f"Sandbox cleanup failed: {cleanup_exc}") from cleanup_exc

