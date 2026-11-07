"""Explicit fail-closed null sandbox backend.

Used when sandboxing is requested on an unsupported platform or when no
OS-enforced isolation primitives are available. Never falls back to unconfined host execution.
"""

from __future__ import annotations

from pathlib import Path

from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import SandboxCapabilityUnavailableError
from sarthi.core.sandbox.policy import CapabilityStatus, MechanismMaturity, SandboxPolicy
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult


class NullSandboxBackend(BaseSandboxBackend):
    """Null sandbox backend that fails closed upon any execution attempt."""

    @property
    def name(self) -> str:
        return "null"

    @property
    def maturity(self) -> MechanismMaturity:
        return MechanismMaturity.LEGACY_UNSUPPORTED

    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        """Returns all capabilities as UNSUPPORTED with no production certification."""
        return SandboxCapabilityReport(
            backend_name=self.name,
            mechanism_maturity=self.maturity,
            filesystem_isolation=CapabilityStatus.UNSUPPORTED,
            network_isolation=CapabilityStatus.UNSUPPORTED,
            process_isolation=CapabilityStatus.UNSUPPORTED,
            environment_isolation=CapabilityStatus.UNSUPPORTED,
            resource_enforcement=CapabilityStatus.UNSUPPORTED,
            workspace_confinement=CapabilityStatus.UNSUPPORTED,
            child_process_inheritance=CapabilityStatus.UNSUPPORTED,
            evidence_trace=["Null backend provides zero OS-level isolation primitives."],
        )

    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        raise SandboxCapabilityUnavailableError(
            "NullSandboxBackend cannot provide OS-level isolation. Execution refused (fail-closed)."
        )

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        raise SandboxCapabilityUnavailableError(
            "NullSandboxBackend cannot execute commands under OS-level isolation. Execution refused (fail-closed)."
        )

    def cleanup(self) -> None:
        pass

