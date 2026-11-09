"""Sandbox execution results and multi-dimensional capability reporting.

Provides structured results of sandboxed subprocess execution along with
granular reports on OS isolation capability enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sarthi.core.sandbox.policy import (
    CapabilityStatus,
    CertificationTier,
    MechanismMaturity,
)


@dataclass(frozen=True)
class SandboxCapabilityReport:
    """Multi-dimensional capability assessment report for a sandbox backend."""

    backend_name: str
    mechanism_maturity: MechanismMaturity
    certification_tier: CertificationTier = CertificationTier.IMPLEMENTATION_PENDING
    filesystem_isolation: CapabilityStatus = CapabilityStatus.UNVERIFIED
    network_isolation: CapabilityStatus = CapabilityStatus.UNVERIFIED
    process_isolation: CapabilityStatus = CapabilityStatus.UNVERIFIED
    process_count_enforcement: CapabilityStatus = CapabilityStatus.UNVERIFIED
    resource_enforcement: CapabilityStatus = CapabilityStatus.UNVERIFIED
    environment_isolation: CapabilityStatus = CapabilityStatus.UNVERIFIED
    workspace_confinement: CapabilityStatus = CapabilityStatus.UNVERIFIED
    child_process_inheritance: CapabilityStatus = CapabilityStatus.UNVERIFIED
    evidence_trace: list[str] = field(default_factory=list)

    @property
    def is_production_certified(self) -> bool:
        """Returns True ONLY if all required capabilities PASS under a PRODUCTION mechanism and certified tier."""
        if self.mechanism_maturity != MechanismMaturity.PRODUCTION:
            return False
        if self.certification_tier != CertificationTier.PRODUCTION_CERTIFIED:
            return False
        return (
            self.filesystem_isolation == CapabilityStatus.PASS
            and self.network_isolation == CapabilityStatus.PASS
            and self.process_isolation == CapabilityStatus.PASS
            and self.process_count_enforcement == CapabilityStatus.PASS
            and self.resource_enforcement == CapabilityStatus.PASS
            and self.environment_isolation == CapabilityStatus.PASS
            and self.workspace_confinement == CapabilityStatus.PASS
            and self.child_process_inheritance == CapabilityStatus.PASS
        )

    def is_capable_of(self, requirement: str) -> bool:
        """Checks if a specific capability attribute has status PASS."""
        status = getattr(self, requirement, None)
        return status == CapabilityStatus.PASS


@dataclass
class SandboxResult:
    """Output and telemetry from a sandboxed command execution."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0
    capability_report: SandboxCapabilityReport | None = None
    cleanup_successful: bool = True
    evidence_trace: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Returns True if the process completed with returncode 0 without timing out and cleanup succeeded."""
        return self.exit_code == 0 and not self.timed_out and self.cleanup_successful

