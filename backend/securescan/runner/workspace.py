"""Per-job workspaces under ``<data root>/workspaces/<job id>/{src,out,config}``.

* ``src``: the source to scan (cloned or unpacked by the worker, mounted read-only into scanners).
* ``out``: the scanner writes its reports here. World-writable (0777) on purpose: scanner images run as
  their own uid (the catalogue says which) and, with all capabilities dropped, even root has no
  permission override, so a directory that only the worker's uid can write would break such images.
* ``config``: files for the scanner (for example ``gitleaks.toml``), mounted read-only.

The worker (uid 1000) creates the directories itself, so no ``chown`` is needed. Files placed in ``src``
and ``config`` are made world-readable. ``cleanup`` removes the whole tree; ``workspace_gc`` removes
orphans older than 24 hours.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from securescan.config import get_settings
from securescan.logging import get_logger

log = get_logger(__name__)

DIR_MODE = 0o775
OUT_MODE = 0o777


def workspaces_root() -> Path:
    return Path(get_settings().workspaces_root)


@dataclass
class Workspace:
    job_id: uuid.UUID
    root: Path
    src: Path
    out: Path
    config: Path

    @classmethod
    def path_for(cls, job_id: uuid.UUID) -> Path:
        return workspaces_root() / str(job_id)

    @classmethod
    def create(cls, job_id: uuid.UUID) -> Workspace:
        """Create the three directories (an existing workspace of a retried job is emptied first)."""
        root = cls.path_for(job_id)
        if root.exists():
            remove_tree(root)
        base = workspaces_root()
        base.mkdir(parents=True, exist_ok=True)
        _mkdir(root, DIR_MODE)
        workspace = cls(
            job_id=job_id, root=root, src=root / "src", out=root / "out", config=root / "config"
        )
        _mkdir(workspace.src, DIR_MODE)
        _mkdir(workspace.out, OUT_MODE)
        _mkdir(workspace.config, DIR_MODE)
        return workspace

    def cleanup(self) -> None:
        remove_tree(self.root)

    def host_relative(self, name: str) -> str:
        """Path of ``src``, ``out`` or ``config`` below the data root (for logging)."""
        return str(getattr(self, name))


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir(parents=False, exist_ok=True)
    os.chmod(path, mode)  # mkdir(mode=...) is subject to the umask


def make_world_readable(root: Path) -> None:
    """Add read (and directory search) permission for everyone below ``root``; no symlink is followed."""
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            _add_mode(Path(current) / name, 0o755)
        for name in files:
            _add_mode(Path(current) / name, 0o644)
    _add_mode(root, 0o755)


def _add_mode(path: Path, bits: int) -> None:
    try:
        if path.is_symlink():
            return
        mode = stat.S_IMODE(path.lstat().st_mode)
        extra = bits & ~0o200  # never touch the write bit
        if mode | extra != mode:
            os.chmod(path, mode | extra)
    except OSError:
        pass


def remove_tree(path: Path) -> bool:
    """Delete a directory tree; fix permissions of read-only entries and retry. True when gone."""

    def onerror(func: object, target: str, _exc: object) -> None:
        try:
            os.chmod(os.path.dirname(target) or ".", 0o777)
            os.chmod(target, 0o777)
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target, ignore_errors=True)
            else:
                os.unlink(target)
        except OSError:
            pass

    if not path.exists() and not path.is_symlink():
        return True
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=onerror)  # type: ignore[call-arg,unused-ignore]
    else:  # pragma: no cover - production runs Python 3.14
        shutil.rmtree(path, onerror=onerror)
    gone = not path.exists()
    if not gone:
        log.warning("workspace_not_fully_removed", path=str(path))
    return gone
