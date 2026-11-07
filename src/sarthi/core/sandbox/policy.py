"""Sandbox execution policy and capability status definitions.

Defines rigid, immutable data contracts for specifying sandbox isolation
requirements and tracking platform capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class CapabilityStatus(str, Enum):
    """Enforcement status of an OS isolation capability."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_VERIFIED = "NOT_VERIFIED"


class MechanismMaturity(str, Enum):
    """Maturity and support level of the underlying OS isolation primitive."""

    PRODUCTION = "PRODUCTION"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY_UNSUPPORTED = "LEGACY_UNSUPPORTED"


class NetworkPolicy(str, Enum):
    """Network containment policy."""

    BLOCKED = "BLOCKED"              # Default-deny: no outbound WAN, LAN, or loopback
    LOOPBACK_ONLY = "LOOPBACK_ONLY"  # Loopback allowed, WAN/LAN blocked
    ALLOW_ALL = "ALLOW_ALL"          # Outbound network permitted (requires explicit approval)


class FilesystemPolicy(str, Enum):
    """Filesystem containment policy."""

    STAGED_ISOLATED = "STAGED_ISOLATED"        # Fresh staged copy; host filesystem excluded
    READ_ONLY_WORKSPACE = "READ_ONLY_WORKSPACE"  # Host workspace mounted read-only
    READ_WRITE_WORKSPACE = "READ_WRITE_WORKSPACE"  # Workspace mounted read-write, host excluded


@dataclass(frozen=True)
class ResourceLimits:
    """OS resource limits enforced on the sandboxed process tree."""

    max_memory_bytes: int = 1024 * 1024 * 1024  # 1GB commit / address space default
    max_processes: int = 64                      # Limit child forks (fork bomb mitigation)
    timeout_seconds: float = 60.0                # Monotonic execution watchdog


@dataclass(frozen=True)
class SandboxPolicy:
    """Complete specification of isolation boundaries required for an execution."""

    network: NetworkPolicy = NetworkPolicy.BLOCKED
    filesystem: FilesystemPolicy = FilesystemPolicy.STAGED_ISOLATED
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    allow_deprecated_mechanisms: bool = False
    extra_env: dict[str, str] = field(default_factory=dict)
    writable_paths: list[Path] = field(default_factory=list)
    read_only_paths: list[Path] = field(default_factory=list)

    @classmethod
    def default_strict(cls) -> SandboxPolicy:
        """Returns the default, strictest isolation policy for verification commands."""
        return cls(
            network=NetworkPolicy.BLOCKED,
            filesystem=FilesystemPolicy.STAGED_ISOLATED,
            limits=ResourceLimits(),
            allow_deprecated_mechanisms=False,
        )

