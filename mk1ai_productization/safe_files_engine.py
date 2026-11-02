"""Safe Read-Only Files Engine for Aegis Files, Aegis Code, and File Inspector (Audit Items 3, 4, 5, 7, 8, 9).

Enforces:
- Read-only workspace boundary (blocks `..`, absolute path escapes, and symlinks).
- Rejects special files (FIFO, character/block devices, sockets) via `stat.S_ISREG` / `O_NOFOLLOW`.
- Caps directory scan count (`max_entries = 200`) to prevent directory scan DoS.
- Strict hierarchical `folder_filter` validation (`Path.is_relative_to`).
- Full-file SHA-256 computation (never partial/truncated hash).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any


class FileAccessSecurityError(PermissionError):
    """Raised when path traversal, symlink, or special file access is attempted."""


class SafeReadOnlyFilesEngine:
    """Provides safe read-only file listing, inspection, and full SHA-256 verification."""

    MAX_SCAN_ENTRIES = 200
    MAX_READ_BYTES = 256 * 1024  # 256 KiB cap for code viewer preview

    def __init__(self, root_dir: Path) -> None:
        self._root_dir = root_dir.resolve(strict=True)

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    def _resolve_safe_path(self, rel_path: str) -> Path:
        if not rel_path or "\x00" in rel_path:
            raise FileAccessSecurityError("Invalid or empty file path")
        norm = Path(rel_path)
        if norm.is_absolute() or ".." in norm.parts:
            raise FileAccessSecurityError(f"Path traversal blocked: '{rel_path}'")

        # Check every parent component for symlinks before resolving
        curr = self._root_dir
        for part in norm.parts:
            curr = curr / part
            try:
                st = os.lstat(curr)
            except FileNotFoundError as exc:
                raise FileNotFoundError(f"Path does not exist: '{rel_path}'") from exc
            if stat.S_ISLNK(st.st_mode):
                raise FileAccessSecurityError(f"Symlink access is prohibited: '{rel_path}'")

        resolved = curr.resolve(strict=True)
        if not resolved.is_relative_to(self._root_dir):
            raise FileAccessSecurityError(f"Path escapes workspace root: '{rel_path}'")
        return resolved

    def list_workspace_files(
        self,
        *,
        folder_filter: str | None = None,
        max_entries: int | None = None,
    ) -> list[dict[str, Any]]:
        """Safely list regular files within root_dir with hierarchical folder_filter and DoS cap."""
        cap = min(max_entries or self.MAX_SCAN_ENTRIES, self.MAX_SCAN_ENTRIES)
        if cap < 1:
            raise ValueError("max_entries must be >= 1")

        filter_path: Path | None = None
        if folder_filter and folder_filter.strip():
            filter_path = self._resolve_safe_path(folder_filter.strip())
            st_filter = os.lstat(filter_path)
            if not stat.S_ISDIR(st_filter.st_mode):
                raise FileAccessSecurityError(f"folder_filter is not a directory: '{folder_filter}'")

        scan_root = filter_path if filter_path is not None else self._root_dir
        results: list[dict[str, Any]] = []

        for dirpath, dirnames, filenames in os.walk(scan_root, topdown=True, followlinks=False):
            # Exclude hidden/cache dirs and prevent symlinked directory recursion
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in {".git", "node_modules", "__pycache__", "dist"}
                and not os.path.islink(os.path.join(dirpath, d))
            )
            for fname in sorted(filenames):
                if len(results) >= cap:
                    return results
                full = Path(dirpath) / fname
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                # Skip symlinks or special files (FIFO, sockets, device nodes)
                if not stat.S_ISREG(st.st_mode):
                    continue
                if filter_path is not None and not full.is_relative_to(filter_path):
                    continue
                rel = full.relative_to(self._root_dir).as_posix()
                results.append(
                    {
                        "path": rel,
                        "name": fname,
                        "size_bytes": st.st_size,
                        "mode_octal": oct(st.st_mode & 0o777)[2:],
                    }
                )
        return results

    def inspect_regular_file(self, rel_path: str) -> dict[str, Any]:
        """Inspect a regular file, rejecting FIFOs/devices/symlinks, and compute full-file SHA-256."""
        target = self._resolve_safe_path(rel_path)
        st = os.lstat(target)
        if not stat.S_ISREG(st.st_mode):
            raise FileAccessSecurityError(
                f"Special or non-regular file rejected (FIFO/device/socket/dir): '{rel_path}'"
            )

        # Compute full-file SHA-256 in 64KiB chunks
        hasher = hashlib.sha256()
        total_read = 0
        preview_chunks: list[bytes] = []
        preview_collected = 0

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target, flags)
        try:
            f_st = os.fstat(fd)
            if not stat.S_ISREG(f_st.st_mode):
                raise FileAccessSecurityError(f"TOCTOU check: descriptor is not a regular file: '{rel_path}'")
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                hasher.update(chunk)
                total_read += len(chunk)
                if preview_collected < self.MAX_READ_BYTES:
                    take = chunk[: self.MAX_READ_BYTES - preview_collected]
                    preview_chunks.append(take)
                    preview_collected += len(take)
        finally:
            os.close(fd)

        preview_text = b"".join(preview_chunks).decode("utf-8", errors="replace")
        return {
            "path": target.relative_to(self._root_dir).as_posix(),
            "name": target.name,
            "size_bytes": f_st.st_size,
            "hashed_bytes": total_read,
            "full_file_sha256": hasher.hexdigest(),
            "mode_octal": oct(f_st.st_mode & 0o777)[2:],
            "is_regular_file": True,
            "preview_truncated": f_st.st_size > self.MAX_READ_BYTES,
            "content_preview": preview_text,
        }
