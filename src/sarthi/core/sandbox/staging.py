"""Isolated workspace staging manager for OS-level subprocess sandboxes.

Guarantees complete hardlink decoupling by copying regular files by value into
a fresh directory tree (allocating new independent inodes), strictly validates
symlink targets and chains, rejects special files (FIFOs, sockets, device nodes),
and enforces fail-closed cleanup.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from types import TracebackType

from sarthi.core.sandbox.exceptions import (
    SandboxStagingError,
    StagedWorkspaceSecurityError,
)


class WorkspaceStagingManager:
    """Manages the creation, population, and teardown of an isolated workspace replica."""

    def __init__(
        self,
        source_root: Path | str,
        base_staging_dir: Path | str | None = None,
        prefix: str = "sarthi_staged_",
    ) -> None:
        self.source_root = Path(source_root).resolve()
        self.base_staging_dir = Path(base_staging_dir).resolve() if base_staging_dir else None
        self.prefix = prefix
        self.staged_root: Path | None = None

    def __enter__(self) -> Path:
        return self.stage()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.cleanup()

    def stage(self) -> Path:
        """Stages the repository into a fresh directory tree with verified inode decoupling.

        Raises:
            StagedWorkspaceSecurityError: If illegal special files or escaping symlinks are found.
            SandboxStagingError: If staging fails due to permissions, quota, or I/O errors.
        """
        if not self.source_root.is_dir():
            raise SandboxStagingError(f"Source repository root does not exist or is not a directory: {self.source_root}")

        try:
            staging_parent = str(self.base_staging_dir) if self.base_staging_dir else None
            temp_dir = tempfile.mkdtemp(prefix=self.prefix, dir=staging_parent)
            self.staged_root = Path(temp_dir).resolve()

            self._copy_tree_secure(self.source_root, self.staged_root)
            return self.staged_root
        except (StagedWorkspaceSecurityError, SandboxStagingError):
            self.cleanup()
            raise
        except Exception as e:
            self.cleanup()
            raise SandboxStagingError(f"Workspace staging failed unexpectedly: {e}") from e

    def cleanup(self) -> None:
        """Safely removes the staged directory tree and all contained files."""
        if self.staged_root and self.staged_root.exists():
            try:
                shutil.rmtree(self.staged_root, ignore_errors=True)
            except Exception:
                pass
            finally:
                self.staged_root = None

    def _copy_tree_secure(self, src: Path, dst: Path) -> None:
        """Recursively copies files from src to dst with strict security validation.

        - Regular files are copied by value (fresh inodes, no hardlinks preserved).
        - Relative symlinks are validated against boundary traversal; chained symlinks are resolved.
        - Special files (FIFOs, sockets, character/block devices) cause immediate failure.
        """
        for root, dirs, files in os.walk(src, topdown=True, followlinks=False):
            rel_root = Path(root).relative_to(src)
            current_dst_dir = dst / rel_root
            current_dst_dir.mkdir(parents=True, exist_ok=True)

            # Process directories (check if any directory itself is a symlink or special inode)
            for d in list(dirs):
                src_dir = Path(root) / d
                dir_stat = src_dir.lstat()
                if stat.S_ISLNK(dir_stat.st_mode):
                    self._validate_and_copy_symlink(src_dir, current_dst_dir / d, src)
                    # Do not recurse into symlinked directories via os.walk
                    dirs.remove(d)

            # Process files
            for f in files:
                src_file = Path(root) / f
                dst_file = current_dst_dir / f

                file_stat = src_file.lstat()
                mode = file_stat.st_mode

                # Special file checks: Reject FIFOs, UNIX domain sockets, character & block devices
                if stat.S_ISFIFO(mode):
                    raise StagedWorkspaceSecurityError(
                        f"Illegal special file (FIFO/named pipe) detected in repository: {src_file}"
                    )
                if stat.S_ISSOCK(mode):
                    raise StagedWorkspaceSecurityError(
                        f"Illegal special file (UNIX domain socket) detected in repository: {src_file}"
                    )
                if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    raise StagedWorkspaceSecurityError(
                        f"Illegal device node detected in repository: {src_file}"
                    )

                # Symlink handling
                if stat.S_ISLNK(mode):
                    self._validate_and_copy_symlink(src_file, dst_file, src)
                elif stat.S_ISREG(mode):
                    # Copy regular file by value (creates fresh inode on destination, severing hardlinks)
                    try:
                        shutil.copy2(src_file, dst_file, follow_symlinks=False)
                    except PermissionError as e:
                        raise SandboxStagingError(f"Permission denied while copying regular file: {src_file}") from e
                    except OSError as e:
                        raise SandboxStagingError(f"OS error copying regular file {src_file} -> {dst_file}: {e}") from e
                else:
                    raise StagedWorkspaceSecurityError(
                        f"Unsupported inode type (mode {oct(mode)}) in repository: {src_file}"
                    )

    def _validate_and_copy_symlink(self, src_link: Path, dst_link: Path, source_boundary: Path) -> None:
        """Validates that a symlink does not escape the workspace boundary, then copies it."""
        try:
            link_target_str = os.readlink(src_link)
        except OSError as e:
            raise SandboxStagingError(f"Failed to read symlink {src_link}: {e}") from e

        link_target = Path(link_target_str)

        # Disallow absolute symlinks outright (they point to host absolute paths)
        if link_target.is_absolute():
            raise StagedWorkspaceSecurityError(
                f"Absolute symlink forbidden in staged workspace: {src_link} -> {link_target}"
            )

        # Resolve relative target against the source file's directory
        resolved_source_path = (src_link.parent / link_target).resolve()
        resolved_boundary = source_boundary.resolve()

        # Boundary check: ensure target stays within source_boundary
        try:
            resolved_source_path.relative_to(resolved_boundary)
        except ValueError:
            raise StagedWorkspaceSecurityError(
                f"Symlink traversal detected escaping workspace boundary: {src_link} -> {link_target}"
            )

        # Chained symlink check: if target is also a symlink, trace it
        current = src_link.parent / link_target
        visited = {str(src_link.resolve())}
        while current.is_symlink():
            current_resolved = current.resolve()
            if str(current_resolved) in visited:
                raise StagedWorkspaceSecurityError(f"Cyclic symlink detected: {src_link}")
            visited.add(str(current_resolved))
            try:
                current_resolved.relative_to(resolved_boundary)
            except ValueError:
                raise StagedWorkspaceSecurityError(
                    f"Chained symlink traversal detected escaping workspace boundary: {src_link}"
                )
            next_target = Path(os.readlink(current))
            current = (current.parent / next_target).resolve()

        # Re-create the verified relative symlink in the destination
        try:
            os.symlink(link_target_str, dst_link)
        except OSError as e:
            raise SandboxStagingError(f"Failed to recreate symlink {dst_link} -> {link_target_str}: {e}") from e

