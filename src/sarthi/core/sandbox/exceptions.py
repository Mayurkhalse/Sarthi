"""Fail-closed exception hierarchy for Sarthi OS-level sandbox execution.

All sandbox-related errors derive from SandboxError to enable unambiguous
fail-closed error handling across the platform.
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base exception for all OS-level sandbox operations."""


class SandboxCapabilityUnavailableError(SandboxError):
    """Raised when an OS or backend lacks a required isolation capability (fail-closed)."""


class SandboxInitializationError(SandboxError):
    """Raised when sandbox environment initialization fails (e.g. container, namespaces, or job object setup)."""


class SandboxExecutionError(SandboxError):
    """Raised when an unrecoverable error occurs during sandboxed process execution."""


class SandboxTimeoutError(SandboxExecutionError):
    """Raised when sandboxed execution exceeds timeout and is forcibly terminated."""


class SandboxCleanupError(SandboxError):
    """Raised when teardown of sandbox resources fails."""


class SandboxStagingError(SandboxError):
    """Raised when workspace staging fails (e.g. disk quota, permission denials, cycles)."""


class StagedWorkspaceSecurityError(SandboxStagingError):
    """Raised when an illegal file type (FIFO, socket, block/char device, escaping symlink) is encountered."""


class GitSecurityPolicyError(SandboxError):
    """Raised when an un-allowlisted or insecure Git command is attempted in Tier 1."""

