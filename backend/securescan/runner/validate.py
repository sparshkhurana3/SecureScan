"""Output validation: does the report a scanner left behind exist, parse and stay under its size cap?

SecureScan never reads findings out of a report (DefectDojo does that). This module only answers the
questions of design "Results handling": the file is there, it is a regular file (never a symbolic link
the container may have planted), it is under ``max_mb`` and it is well-formed JSON or XML (syntax only).

Small JSON files are fully parsed. Large ones (above ``FULL_PARSE_BYTES``) get a constant-memory
structural check: balanced brackets outside strings, an object or array at the top level.
"""

from __future__ import annotations

import json
import mmap
import os
import re
import stat
import xml.etree.ElementTree as ET  # noqa: S405 - syntax check only; expat is protected against entity bombs
from dataclasses import dataclass, field
from pathlib import Path

from securescan.runner.catalogue import CatalogueEntry, OutputSpec

FULL_PARSE_BYTES = 64 * 1024 * 1024
_TOKEN = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]')
_NON_SPACE = re.compile(rb"\S")
_PAIRS = {ord("]"): ord("["), ord("}"): ord("{")}


@dataclass
class OutputProblem:
    file: str
    code: str  # missing | not_regular | too_large | empty | malformed | unsupported
    message: str


@dataclass
class ValidatedOutput:
    spec: OutputSpec
    path: Path
    size: int


@dataclass
class ValidationResult:
    outputs: list[ValidatedOutput] = field(default_factory=list)
    problems: list[OutputProblem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def reason(self) -> str:
        return "; ".join(p.message for p in self.problems)


def validate_outputs(entry: CatalogueEntry, out_dir: Path) -> ValidationResult:
    """Check every output the catalogue entry lists against the files in ``out_dir``."""
    result = ValidationResult()
    for spec in entry.outputs:
        path = out_dir.joinpath(*spec.file.split("/"))
        problem, size = _check_file(spec, path)
        if problem is not None:
            if problem.code == "missing" and not spec.required:
                continue
            result.problems.append(problem)
        else:
            result.outputs.append(ValidatedOutput(spec=spec, path=path, size=size))
    return result


def _check_file(spec: OutputSpec, path: Path) -> tuple[OutputProblem | None, int]:
    name = spec.file
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return OutputProblem(name, "missing", f"The expected report {name} was not produced."), 0
    except OSError:
        return OutputProblem(name, "missing", f"The expected report {name} cannot be read."), 0
    if not stat.S_ISREG(info.st_mode):
        return OutputProblem(name, "not_regular", f"The report {name} is not a regular file."), 0
    if info.st_size > spec.max_bytes:
        return (
            OutputProblem(
                name, "too_large", f"The report {name} is larger than the allowed {spec.max_mb} MB."
            ),
            info.st_size,
        )
    if spec.format == "none":
        return None, info.st_size
    if info.st_size == 0:
        return OutputProblem(name, "empty", f"The report {name} is empty."), 0
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return OutputProblem(name, "not_regular", f"The report {name} cannot be opened safely."), 0
    try:
        if spec.format == "json":
            error = check_json(fd, info.st_size)
        else:
            error = check_xml(fd)
    finally:
        os.close(fd)
    if error is not None:
        return OutputProblem(name, "malformed", f"The report {name} is not valid {spec.format.upper()}: {error}"), 0
    return None, info.st_size


def check_json(fd: int, size: int) -> str | None:
    """None when the JSON is well-formed, else a short reason."""
    if size <= FULL_PARSE_BYTES:
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read()
        try:
            json.loads(data)
        except (ValueError, RecursionError) as exc:
            return str(exc)[:120]
        return None
    with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as mapped:
        return structural_json_check(mapped)


def structural_json_check(data: bytes | mmap.mmap) -> str | None:
    """Balanced brackets outside strings and a container at the top level (constant memory)."""
    first = _NON_SPACE.search(data)
    if first is None:
        return "empty"
    if data[first.start()] not in (ord("{"), ord("[")):
        return "the top level is not an object or array"
    stack: list[int] = []
    for match in _TOKEN.finditer(data):
        char = match.group()[0]
        if char in (ord("{"), ord("[")):
            stack.append(char)
        elif char in _PAIRS:
            if not stack or stack.pop() != _PAIRS[char]:
                return "brackets do not match"
    if stack:
        return "brackets are not closed"
    end = len(data)
    while end > 0 and data[end - 1] in b" \t\r\n":
        end -= 1
    if end == 0 or data[end - 1] not in (ord("}"), ord("]")):
        return "the document does not end with a closing bracket"
    return None


def check_xml(fd: int) -> str | None:
    """None when the XML is well-formed (streamed, so large files stay cheap)."""
    with os.fdopen(os.dup(fd), "rb") as handle:
        head = handle.read(8192)
        if re.search(rb"<!ENTITY", head, re.IGNORECASE):
            return "entity declarations are not accepted"
        handle.seek(0)
        try:
            for _event, element in ET.iterparse(handle, events=("end",)):
                element.clear()
        except ET.ParseError as exc:
            return str(exc)[:120]
    return None
