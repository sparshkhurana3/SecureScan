"""Template zip handling: read an uploaded zip safely, write a directory, zip a directory.

An uploaded template is untrusted. ``read_zip`` accepts only plain files with the allowed
extensions, refuses encrypted entries, links, odd or escaping names, duplicate names (also by case),
too many files and zip bombs, and returns the files in memory as ``{relative path: bytes}``. It does
not decide whether the template *works*: that is ``renderer.check_template``.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from securescan.reports.renderer import ALLOWED_EXTENSIONS, ENTRY_FILE

MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_UNPACKED_BYTES = 60 * 1024 * 1024
MAX_FILES = 200

_NAME_OK = re.compile(r"^[A-Za-z0-9._ -]+$")


class PackageError(Exception):
    """The zip is not an acceptable template package (the text is for the uploader)."""


def _clean_name(raw: str) -> str:
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/") or ":" in raw:
        raise PackageError(f"unsafe file name {raw[:60]!r}")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PackageError(f"unsafe file name {raw[:60]!r}")
    if any(not _NAME_OK.match(part) or part.startswith(".") for part in parts):
        raise PackageError(f"file name {raw[:60]!r} has characters that are not allowed")
    return "/".join(parts)


def read_zip(data: bytes) -> dict[str, bytes]:
    """Validate a template zip and return its files. Raises ``PackageError``."""
    if len(data) > MAX_ZIP_BYTES:
        raise PackageError("the zip is larger than 20 MB")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise PackageError("the file is not a zip archive")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES * 2:
                raise PackageError("the zip holds too many entries")
            for info in infos:
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    raise PackageError(f"{info.filename[:60]!r} is encrypted")
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise PackageError(f"{info.filename[:60]!r} is a link")
                if info.filename.startswith("__MACOSX/") or info.filename.endswith(".DS_Store"):
                    continue  # archive litter from macOS, not part of the template
                name = _clean_name(info.filename)
                if name.lower() in seen:
                    raise PackageError(f"{name!r} appears twice")
                seen.add(name.lower())
                suffix = PurePosixPath(name).suffix.lower()
                if suffix not in ALLOWED_EXTENSIONS:
                    allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
                    raise PackageError(f"{name!r}: only {allowed} files are allowed")
                if info.file_size > MAX_FILE_BYTES:
                    raise PackageError(f"{name!r} is larger than 20 MB")
                with archive.open(info) as handle:
                    content = handle.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    raise PackageError(f"{name!r} is larger than 20 MB when unpacked")
                total += len(content)
                if total > MAX_UNPACKED_BYTES:
                    raise PackageError("the zip is larger than 60 MB when unpacked")
                files[name] = content
                if len(files) > MAX_FILES:
                    raise PackageError("the zip holds more than 200 files")
    except zipfile.BadZipFile as exc:
        raise PackageError("the zip archive is damaged") from exc
    except (RuntimeError, NotImplementedError) as exc:  # unsupported compression, bad password
        raise PackageError("the zip uses a feature that is not supported") from exc
    return _flatten(files)


def _flatten(files: dict[str, bytes]) -> dict[str, bytes]:
    """Accept a zip made by zipping the folder itself: drop one common top-level folder."""
    if not files:
        raise PackageError("the zip is empty")
    if ENTRY_FILE in files:
        return files
    tops = {name.split("/", 1)[0] for name in files}
    if len(tops) == 1 and all("/" in name for name in files):
        prefix = next(iter(tops)) + "/"
        flat = {name[len(prefix):]: content for name, content in files.items()}
        if ENTRY_FILE in flat:
            return flat
    raise PackageError(f"the zip has no {ENTRY_FILE} at its top level")


def write_files(files: dict[str, bytes], destination: Path) -> None:
    """Write validated files below ``destination`` (created; must not escape it)."""
    root = destination.resolve()
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = (root / name).resolve()
        if root not in target.parents:
            raise PackageError(f"unsafe file name {name[:60]!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def zip_directory(directory: Path) -> bytes:
    """A zip of every allowed file below ``directory`` (sorted, fixed timestamps: reproducible)."""
    root = directory.resolve()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path.suffix.lower() not in ALLOWED_EXTENSIONS:
                continue
            name = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return out.getvalue()


def files_sha256(files: dict[str, bytes]) -> str:
    """One digest over names and contents, independent of the zip container."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8") + b"\x00")
        digest.update(hashlib.sha256(files[name]).digest())
    return digest.hexdigest()


def directory_files(directory: Path) -> dict[str, bytes]:
    root = directory.resolve()
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS
    }


def directory_sha256(directory: Path) -> str:
    return files_sha256(directory_files(directory))
