"""Safe unpacking of uploaded archives: traversal, absolute paths, symlinks, bombs, caps."""

from __future__ import annotations

import io
import os
import stat
import types
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings
from securescan.runner.sources.zip import (
    ZipLimits,
    ZipRejected,
    _copy_member,
    extract_zip,
    inspect_zip,
    normalise_member_name,
)

LINK = 0o120777 << 16
EXEC_FILE = 0o100755 << 16


def build_zip(path: Path, entries: list[tuple[Any, bytes | str]]) -> Path:
    """Entries are ``(name or ZipInfo, content)``; duplicate names are allowed on purpose."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries:
                zf.writestr(name, data)
    return path


def link_info(name: str, mode: int = LINK) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.external_attr = mode
    return info


def need_symlinks() -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symbolic links are not available here")


# --------------------------------------------------------------------------- the happy path
def test_unpacks_files_directories_and_sets_modes(tmp_path: Path) -> None:
    archive = build_zip(
        tmp_path / "ok.zip",
        [
            ("app/", ""),
            ("app/main.py", "print('hi')\n"),
            ("app/sub/data.txt", "data"),
            (link_info("app/run.sh", EXEC_FILE), "#!/bin/sh\n"),
            ("./", ""),
        ],
    )
    dest = tmp_path / "src"
    report = extract_zip(archive, dest)
    assert (dest / "app" / "main.py").read_text() == "print('hi')\n"
    assert (dest / "app" / "sub" / "data.txt").read_text() == "data"
    assert report.files == 3 and report.directories >= 1 and report.symlinks == 0
    assert stat.S_IMODE((dest / "app" / "main.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((dest / "app" / "run.sh").stat().st_mode) == 0o755
    assert stat.S_IMODE((dest / "app").stat().st_mode) == 0o755


def test_inspect_does_not_extract(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "ok.zip", [("a.txt", "x"), ("d/b.txt", "yy")])
    members, report = inspect_zip(archive)
    assert [m.path for m in members] == ["a.txt", "d/b.txt"]
    assert report.uncompressed_bytes == 3 and report.entries == 2
    assert not (tmp_path / "a.txt").exists()


def test_symlink_inside_the_tree_is_kept(tmp_path: Path) -> None:
    need_symlinks()
    archive = build_zip(tmp_path / "l.zip", [("lib/real.txt", "x"), (link_info("lib/alias"), "real.txt")])
    dest = tmp_path / "src"
    report = extract_zip(archive, dest)
    assert os.path.islink(dest / "lib" / "alias") and report.symlinks == 1
    assert (dest / "lib" / "alias").read_text() == "x"


# --------------------------------------------------------------------------- names
@pytest.mark.parametrize(
    "name", ["../evil", "a/../../evil", "..\\evil", "a/../b", "a/b/../../../c", "dir\\..\\..\\x"]
)
def test_path_traversal_is_rejected(tmp_path: Path, name: str) -> None:
    archive = build_zip(tmp_path / "t.zip", [("fine.txt", "x"), (name, "evil")])
    with pytest.raises(ZipRejected) as caught:
        extract_zip(archive, tmp_path / "src")
    assert caught.value.code == "zip.path_traversal"
    assert not (tmp_path / "evil").exists()
    assert "leaves the folder" in str(caught.value)


@pytest.mark.parametrize("name", ["/etc/passwd", "C:/Windows/system.ini", "\\\\server\\share\\x", "c:\\x"])
def test_absolute_paths_are_rejected(tmp_path: Path, name: str) -> None:
    archive = build_zip(tmp_path / "a.zip", [(name, "x")])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.absolute_path"


def test_control_characters_in_names_are_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "c.zip", [("bad\nname", "x")])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.bad_name"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a//b/./c/", "a/b/c"), ("dir\\file", "dir/file"), ("", ""), ("./", ""), ("x", "x"), ("a/.hidden", "a/.hidden")],
)
def test_names_are_normalised(name: str, expected: str) -> None:
    assert normalise_member_name(name) == expected


def test_duplicate_entries_are_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "d.zip", [("a.txt", "1"), ("a.txt", "2")])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.duplicate_entry"
    archive2 = build_zip(tmp_path / "d2.zip", [("a.txt", "1"), ("A.TXT", "2")])
    with pytest.raises(ZipRejected):
        inspect_zip(archive2)


def test_special_files_are_rejected(tmp_path: Path) -> None:
    fifo = link_info("pipe", 0o010644 << 16)
    archive = build_zip(tmp_path / "s.zip", [(fifo, "")])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.special_file"


# --------------------------------------------------------------------------- symbolic links
@pytest.mark.parametrize("target", ["../../etc/passwd", "/etc/passwd", "../x", "a/../../..", "C:/x", "back\\slash"])
def test_symlinks_that_leave_the_tree_are_rejected(tmp_path: Path, target: str) -> None:
    archive = build_zip(tmp_path / "l.zip", [(link_info("escape"), target)])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.symlink_escape"


def test_symlink_chain_that_escapes_is_caught_at_extraction(tmp_path: Path) -> None:
    need_symlinks()
    # link1 -> "." is fine; link2 -> "link1/.." looks harmless as text but resolves to the parent directory
    archive = build_zip(tmp_path / "chain.zip", [(link_info("link1"), "."), (link_info("link2"), "link1/..")])
    inspect_zip(archive)  # lexically fine
    with pytest.raises(ZipRejected) as caught:
        extract_zip(archive, tmp_path / "src")
    assert caught.value.code == "zip.symlink_escape"


def test_symlink_target_size_is_limited(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "big.zip", [(link_info("l"), "a" * 5000)])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive)
    assert caught.value.code == "zip.symlink_invalid"


# --------------------------------------------------------------------------- size, ratio, count
def test_entry_count_cap(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "n.zip", [(f"f{i}.txt", "x") for i in range(5)])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive, ZipLimits(max_entries=4))
    assert caught.value.code == "zip.too_many_entries"
    inspect_zip(archive, ZipLimits(max_entries=5))


def test_uncompressed_size_cap(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "s.zip", [("a.bin", b"x" * 60), ("b.bin", b"y" * 60)])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive, ZipLimits(max_uncompressed_bytes=100))
    assert caught.value.code == "zip.too_large"
    inspect_zip(archive, ZipLimits(max_uncompressed_bytes=120))


def test_three_gigabytes_are_refused_by_the_default_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = build_zip(tmp_path / "h.zip", [("huge.bin", b"x")])
    original = zipfile.ZipFile.infolist

    def claims_three_gigabytes(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        infos = original(self)
        for info in infos:
            info.file_size = 3 * 1024**3  # what the central directory would say
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", claims_three_gigabytes)
    limits = ZipLimits.from_settings(Settings())
    assert limits.max_uncompressed_bytes == 2 * 1024**3
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive, limits)
    assert caught.value.code == "zip.too_large"


def test_compression_ratio_cap(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "bomb.zip", [("zeros.bin", b"\x00" * (12 * 1024 * 1024))])
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(archive, ZipLimits(max_ratio=100))
    assert caught.value.code == "zip.ratio"
    inspect_zip(archive, ZipLimits(max_ratio=100_000))


def test_small_highly_compressible_files_are_not_a_bomb(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "ok.zip", [("zeros.bin", b"\x00" * 100_000)])
    inspect_zip(archive, ZipLimits(max_ratio=10))  # the ratio only counts above 10 MiB


def test_data_beyond_the_declared_size_stops_the_copy(tmp_path: Path) -> None:
    info = types.SimpleNamespace(file_size=5)
    zf = types.SimpleNamespace(open=lambda _info: io.BytesIO(b"x" * 10))
    with pytest.raises(ZipRejected) as caught:
        _copy_member(zf, info, str(tmp_path / "out.bin"), budget=1000)  # type: ignore[arg-type]
    assert caught.value.code == "zip.too_large"
    info_ok = types.SimpleNamespace(file_size=10)
    with pytest.raises(ZipRejected):
        _copy_member(zf, info_ok, str(tmp_path / "out2.bin"), budget=4)  # type: ignore[arg-type]
    assert _copy_member(zf, info_ok, str(tmp_path / "out3.bin"), budget=10) == 10  # type: ignore[arg-type]


# --------------------------------------------------------------------------- not an archive
def test_not_a_zip_file(tmp_path: Path) -> None:
    bogus = tmp_path / "x.zip"
    bogus.write_bytes(b"this is not a zip")
    with pytest.raises(ZipRejected) as caught:
        inspect_zip(bogus)
    assert caught.value.code == "zip.invalid"
    empty = tmp_path / "e.zip"
    empty.write_bytes(b"")
    with pytest.raises(ZipRejected):
        inspect_zip(empty)


def test_zip_rejected_is_a_source_error() -> None:
    from securescan.runner.sources.base import SourceError

    assert issubclass(ZipRejected, SourceError)
    assert ZipRejected("x", code="zip.invalid").code == "zip.invalid"
