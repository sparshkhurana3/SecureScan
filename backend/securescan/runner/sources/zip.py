"""Safe unpacking of an uploaded zip archive into a workspace.

The archive is untrusted. ``inspect_zip`` checks the central directory without extracting anything (the
API calls it when a scan is created, so a bad upload is refused at once with a problem detail), and
``extract_zip`` checks again while extracting (defence in depth; it also counts the bytes it really
writes, because headers can lie). Rejected:

* absolute paths, drive letters, ``..`` segments, NUL bytes, control characters in names,
* duplicate entries, encrypted entries, device files, fifos and sockets,
* symbolic links whose target is absolute or resolves outside the extraction root,
* more than ``zip_max_entries`` entries, more than ``zip_max_uncompressed_bytes`` in total, a compression
  ratio above ``zip_max_ratio`` (only judged once the content exceeds 10 MiB).

Extracted files get mode 0644 (0755 when the archive marks them executable) and directories 0755, so
scanner containers running under any uid can read them.
"""

from __future__ import annotations

import asyncio
import os
import posixpath
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from securescan.config import Settings
from securescan.runner.sources.base import SourceError, SourceInfo, SourceRequest

CHUNK = 1024 * 1024
RATIO_FLOOR_BYTES = 10 * 1024 * 1024
MAX_SYMLINK_TARGET = 4096
MAX_NAME_LENGTH = 1024
_DRIVE = re.compile(r"^[A-Za-z]:")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ZipRejected(SourceError):
    """The archive is not acceptable (the message says why, in plain words)."""


@dataclass(frozen=True)
class ZipLimits:
    max_uncompressed_bytes: int = 2 * 1024**3
    max_ratio: int = 100
    max_entries: int = 200_000

    @classmethod
    def from_settings(cls, settings: Settings) -> ZipLimits:
        return cls(
            max_uncompressed_bytes=settings.zip_max_uncompressed_bytes,
            max_ratio=settings.zip_max_ratio,
            max_entries=settings.zip_max_entries,
        )


@dataclass
class ZipMember:
    info: zipfile.ZipInfo
    path: str  # normalised relative POSIX path
    kind: str  # file | dir | symlink
    link_target: str | None = None


@dataclass
class ZipReport:
    entries: int
    files: int
    directories: int
    symlinks: int
    uncompressed_bytes: int
    compressed_bytes: int


def normalise_member_name(name: str) -> str:
    """The safe relative POSIX path of an archive entry name, or ``ZipRejected``."""
    if "\x00" in name or _CONTROL.search(name):
        raise ZipRejected(
            "The archive contains a file name with control characters.", code="zip.bad_name"
        )
    if len(name) > MAX_NAME_LENGTH:
        raise ZipRejected("The archive contains a file name that is too long.", code="zip.bad_name")
    unified = name.replace("\\", "/")
    if unified.startswith("/") or _DRIVE.match(unified):
        raise ZipRejected(
            f"The archive contains an absolute path ({_shown(name)}).", code="zip.absolute_path"
        )
    parts = [part for part in unified.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ZipRejected(
            f"The archive contains a path that leaves the folder ({_shown(name)}).",
            code="zip.path_traversal",
        )
    return "/".join(parts)


def _shown(name: str) -> str:
    return repr(name[:80])


def _mode_of(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o177777


def _classify(info: zipfile.ZipInfo) -> str:
    mode = _mode_of(info)
    kind = stat.S_IFMT(mode)
    if kind == stat.S_IFLNK:
        return "symlink"
    if info.is_dir() or kind == stat.S_IFDIR:
        return "dir"
    if kind in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
        raise ZipRejected(
            f"The archive contains a special file ({_shown(info.filename)}).", code="zip.special_file"
        )
    return "file"


def _lexical_symlink_ok(path: str, target: str) -> bool:
    """True when ``target`` (relative to the link's directory) does not leave the root, lexically."""
    if not target or target.startswith("/") or "\\" in target or "\x00" in target or _DRIVE.match(target):
        return False
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return joined != ".." and not joined.startswith("../") and not joined.startswith("/")


def inspect_zip(archive: Path, limits: ZipLimits | None = None) -> tuple[list[ZipMember], ZipReport]:
    """Validate the central directory of ``archive``; nothing is extracted. Raises ``ZipRejected``."""
    lim = limits or ZipLimits()
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > lim.max_entries:
                raise ZipRejected(
                    f"The archive has more than {lim.max_entries} entries.", code="zip.too_many_entries"
                )
            members: list[ZipMember] = []
            seen: set[str] = set()
            total = 0
            compressed = 0
            counts = {"file": 0, "dir": 0, "symlink": 0}
            for info in infos:
                if info.flag_bits & 0x1:
                    raise ZipRejected(
                        "The archive is password protected and cannot be scanned.", code="zip.encrypted"
                    )
                path = normalise_member_name(info.filename)
                if not path:
                    continue  # an entry for the root directory itself
                kind = _classify(info)
                key = path.lower()
                if key in seen and kind != "dir":
                    raise ZipRejected(
                        f"The archive lists the same file twice ({_shown(path)}).",
                        code="zip.duplicate_entry",
                    )
                if kind != "dir":
                    seen.add(key)
                link_target: str | None = None
                if kind == "symlink":
                    if info.file_size > MAX_SYMLINK_TARGET:
                        raise ZipRejected(
                            f"The archive contains an invalid link ({_shown(path)}).",
                            code="zip.symlink_invalid",
                        )
                    link_target = zf.read(info).decode("utf-8", "replace")
                    if not _lexical_symlink_ok(path, link_target):
                        raise ZipRejected(
                            f"The archive contains a link that points outside the folder ({_shown(path)}).",
                            code="zip.symlink_escape",
                        )
                else:
                    total += info.file_size
                    compressed += info.compress_size
                    if total > lim.max_uncompressed_bytes:
                        raise ZipRejected(
                            "The archive is larger than the allowed "
                            f"{lim.max_uncompressed_bytes // 1024**3} GB when unpacked.",
                            code="zip.too_large",
                        )
                counts[kind] += 1
                members.append(ZipMember(info=info, path=path, kind=kind, link_target=link_target))
    except zipfile.BadZipFile as exc:
        raise ZipRejected("The file is not a valid zip archive.", code="zip.invalid") from exc
    except (OSError, EOFError, NotImplementedError, RuntimeError) as exc:
        raise ZipRejected("The zip archive could not be read.", code="zip.invalid") from exc

    archive_size = max(archive.stat().st_size, 1)
    if total > RATIO_FLOOR_BYTES and total / archive_size > lim.max_ratio:
        raise ZipRejected(
            f"The archive expands more than {lim.max_ratio} times its size (a possible zip bomb).",
            code="zip.ratio",
        )
    report = ZipReport(
        entries=len(members),
        files=counts["file"],
        directories=counts["dir"],
        symlinks=counts["symlink"],
        uncompressed_bytes=total,
        compressed_bytes=compressed,
    )
    return members, report


def _inside(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def extract_zip(archive: Path, dest: Path, limits: ZipLimits | None = None) -> ZipReport:
    """Unpack ``archive`` into the (empty) directory ``dest``. Blocking; call through a thread."""
    lim = limits or ZipLimits()
    members, report = inspect_zip(archive, lim)
    dest.mkdir(parents=True, exist_ok=True)
    root = os.path.realpath(dest)
    written_total = 0
    try:
        with zipfile.ZipFile(archive) as zf:
            for member in members:
                target = os.path.join(root, *member.path.split("/"))
                parent = os.path.dirname(target)
                if not _inside(root, os.path.realpath(parent)):
                    raise ZipRejected(
                        f"The archive writes outside the folder ({_shown(member.path)}).",
                        code="zip.path_traversal",
                    )
                os.makedirs(parent, mode=0o755, exist_ok=True)
                if member.kind == "dir":
                    os.makedirs(target, mode=0o755, exist_ok=True)
                    os.chmod(target, 0o755)
                elif member.kind == "symlink":
                    resolved = os.path.realpath(os.path.join(parent, str(member.link_target)))
                    if not _inside(root, resolved):
                        raise ZipRejected(
                            f"The archive contains a link that points outside the folder ({_shown(member.path)}).",
                            code="zip.symlink_escape",
                        )
                    os.symlink(str(member.link_target), target)
                else:
                    if os.path.lexists(target):
                        raise ZipRejected(
                            f"The archive lists the same file twice ({_shown(member.path)}).",
                            code="zip.duplicate_entry",
                        )
                    written = _copy_member(zf, member.info, target, lim.max_uncompressed_bytes - written_total)
                    written_total += written
                    executable = bool(_mode_of(member.info) & 0o111)
                    os.chmod(target, 0o755 if executable else 0o644)
        _verify_links(root)
        _open_directories(root)
    except ZipRejected:
        raise
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise ZipRejected(
            "The archive could not be unpacked (it may be damaged or use an unsupported feature).",
            code="zip.extract_failed",
        ) from exc
    return report


def _copy_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: str, budget: int) -> int:
    """Stream one member to ``target``; stops when it writes more than it declared or the budget."""
    written = 0
    with zf.open(info) as source, open(target, "xb") as out:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > info.file_size or written > budget:
                raise ZipRejected(
                    "The archive holds more data than its headers say (a possible zip bomb).",
                    code="zip.too_large",
                )
            out.write(chunk)
    return written


def _open_directories(root: str) -> None:
    """Every directory readable and searchable by everyone (implicit parents obey the process umask)."""
    for current, dirs, _files in os.walk(root, followlinks=False):
        for name in dirs:
            path = os.path.join(current, name)
            if not os.path.islink(path):
                os.chmod(path, 0o755)
    os.chmod(root, 0o755)


def _verify_links(root: str) -> None:
    """After extraction every symbolic link must still resolve inside the root."""
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            full = os.path.join(current, name)
            if os.path.islink(full) and not _inside(root, os.path.realpath(full)):
                raise ZipRejected(
                    "The archive contains a link that points outside the folder.",
                    code="zip.symlink_escape",
                )


async def acquire_zip(request: SourceRequest) -> SourceInfo:
    """Source handler for ``zip`` targets: unpack the uploaded artifact into ``workspace.src``."""
    from securescan.db.models.artifacts import Artifact
    from securescan.storage.artifacts import StorageError, artifact_path

    target = request.target
    artifact = await request.session.get(Artifact, target.upload_artifact_id) if target.upload_artifact_id else None
    if artifact is None or artifact.deleted_at is not None:
        raise SourceError("The uploaded archive of this target is missing.", code="zip.upload_missing")
    try:
        path = artifact_path(artifact)
    except StorageError as exc:
        raise SourceError("The uploaded archive of this target is missing.", code="zip.upload_missing") from exc
    if not path.is_file():
        raise SourceError("The uploaded archive of this target is missing.", code="zip.upload_missing")
    await request.session.commit()  # no transaction stays open while the archive is unpacked
    await request.log(f"unpacking {artifact.filename or artifact.id} into the workspace")
    report = await asyncio.to_thread(
        extract_zip, path, request.workspace.src, ZipLimits.from_settings(request.settings)
    )
    await request.log(
        f"unpacked {report.files} files ({report.uncompressed_bytes} bytes), "
        f"{report.directories} folders, {report.symlinks} links"
    )
    return SourceInfo(
        kind="zip",
        is_git=False,
        ref=artifact.filename,
        description=f"zip upload {artifact.filename or artifact.id}",
        details={"sha256": artifact.sha256, "files": report.files, "bytes": report.uncompressed_bytes},
    )
