"""macOS Seatbelt sandbox backend (Documented Vendor Deprecation).

Respects the architectural requirement that macOS sandbox-exec is officially
deprecated by Apple and proprietary SBPL is undocumented. Fails closed by
default unless allow_deprecated_mechanisms=True is explicitly set in policy.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from sarthi.core.sandbox.base import BaseSandboxBackend
from sarthi.core.sandbox.exceptions import (
    SandboxCapabilityUnavailableError,
    SandboxExecutionError,
)
from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    MechanismMaturity,
    SandboxPolicy,
)
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult


class MacOSSeatbeltBackend(BaseSandboxBackend):
    """macOS Seatbelt (sandbox-exec) backend flagged as vendor-deprecated."""

    @property
    def name(self) -> str:
        return "macos_seatbelt"

    @property
    def maturity(self) -> MechanismMaturity:
        return MechanismMaturity.DEPRECATED

    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        if sys.platform != "darwin":
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
                evidence_trace=["Not running on macOS Darwin."],
            )

        has_sandbox_exec = shutil.which("sandbox-exec") is not None
        status = CapabilityStatus.UNVERIFIED if has_sandbox_exec else CapabilityStatus.UNSUPPORTED

        return SandboxCapabilityReport(
            backend_name=self.name,
            mechanism_maturity=self.maturity,
            certification_tier=CertificationTier.IMPLEMENTATION_PENDING,
            filesystem_isolation=status,
            network_isolation=status,
            process_isolation=status,
            process_count_enforcement=CapabilityStatus.UNSUPPORTED,
            resource_enforcement=CapabilityStatus.UNSUPPORTED,
            environment_isolation=CapabilityStatus.PASS,
            workspace_confinement=status,
            child_process_inheritance=status,
            evidence_trace=[
                "sandbox-exec detected but officially deprecated by Apple (man sandbox-exec).",
                "App Sandbox requires signed .app bundles and cannot wrap arbitrary CLI commands.",
            ],
        )

    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        if sys.platform != "darwin":
            raise SandboxCapabilityUnavailableError("macOS Seatbelt backend is only supported on Darwin.")

        if not policy.allow_deprecated_mechanisms:
            raise SandboxCapabilityUnavailableError(
                "macOS sandbox-exec is vendor-deprecated and undocumented. Execution refused (fail-closed). "
                "Set policy.allow_deprecated_mechanisms=True to allow experimental execution on macOS."
            )

        if not shutil.which("sandbox-exec"):
            raise SandboxCapabilityUnavailableError("sandbox-exec binary not found on macOS host.")

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        if not policy.allow_deprecated_mechanisms:
            raise SandboxCapabilityUnavailableError(
                "Execution blocked: macOS Seatbelt is marked DEPRECATED. Fail-closed."
            )
        raise SandboxExecutionError(
            "macOS Seatbelt live execution scheduled for Milestone SEC-01C.5. Fail-closed."
        )

    def cleanup(self) -> None:
        pass

