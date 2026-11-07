"""Abstract base class interface for platform-specific sandbox backends.

All platform adapters (Windows AppContainer, Linux Bubblewrap, macOS Seatbelt,
and Null) must implement this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sarthi.core.sandbox.policy import MechanismMaturity, SandboxPolicy
from sarthi.core.sandbox.result import SandboxCapabilityReport, SandboxResult


class BaseSandboxBackend(ABC):
    """Abstract interface defining the contract for OS-level subprocess sandboxes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the backend (e.g. 'windows_appcontainer', 'linux_bubblewrap')."""

    @property
    @abstractmethod
    def maturity(self) -> MechanismMaturity:
        """Support maturity level of the underlying OS isolation mechanism."""

    @abstractmethod
    def detect_capabilities(self, project_root: Path) -> SandboxCapabilityReport:
        """Probes and returns the actual OS-enforced isolation capabilities available on this host."""

    @abstractmethod
    def initialize(self, policy: SandboxPolicy, workspace_root: Path) -> None:
        """Prepares any ephemeral OS container, security tokens, namespaces, or job objects.

        Must raise SandboxInitializationError on failure and roll back any partial state.
        """

    @abstractmethod
    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        workspace_root: Path,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Executes a command inside the isolated OS boundary.

        Must raise SandboxExecutionError or SandboxTimeoutError on failure.
        """

    @abstractmethod
    def cleanup(self) -> None:
        """Tears down all allocated OS objects, mount points, or temporary profiles.

        Must be safe to invoke multiple times and execute even if initialize or run failed.
        """

