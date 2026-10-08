#!/usr/bin/env python3
"""Static consistency check for the backend, usable without installing any dependency.

For every ``securescan.*`` import in backend/securescan and backend/tests it verifies that
the module exists and that each imported name is defined at the top level of that module
(or is a submodule of the package). Also byte-compiles every .py file to catch syntax errors.
Runs on any Python 3.9+ (the code base avoids syntax newer than 3.9 so this works everywhere).
"""

from __future__ import annotations

import ast
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
PKG = BACKEND / "securescan"


def module_path(name: str) -> Path | None:
    parts = name.split(".")
    base = BACKEND.joinpath(*parts)
    if base.with_suffix(".py").exists():
        return base.with_suffix(".py")
    if (base / "__init__.py").exists():
        return base / "__init__.py"
    return None


def defined_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()

    def visit(nodes: list[ast.stmt]) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    for sub in ast.walk(target):
                        if isinstance(sub, ast.Name):
                            names.add(sub.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    names.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    names.add(alias.asname or alias.name)
            elif isinstance(node, (ast.If, ast.Try)):
                visit(node.body)
                visit(getattr(node, "orelse", []))
                for handler in getattr(node, "handlers", []):
                    visit(handler.body)
                visit(getattr(node, "finalbody", []))
            elif isinstance(node, ast.With):
                visit(node.body)

    visit(tree.body)
    return names


def main() -> int:
    errors: list[str] = []
    files = sorted(list(PKG.rglob("*.py")) + list((BACKEND / "tests").rglob("*.py")))
    cache: dict[Path, set[str]] = {}
    for file in files:
        try:
            py_compile.compile(str(file), doraise=True, cfile=str(Path(__file__).with_suffix(".pyc")))
        except py_compile.PyCompileError as exc:
            errors.append(f"SYNTAX {file.relative_to(ROOT)}: {exc.msg.strip()}")
            continue
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module != "securescan" and not node.module.startswith("securescan."):
                    continue
                target = module_path(node.module)
                if target is None:
                    errors.append(f"MODULE {file.relative_to(ROOT)}:{node.lineno}: no module {node.module}")
                    continue
                if target not in cache:
                    cache[target] = defined_names(target)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if alias.name in cache[target]:
                        continue
                    if module_path(f"{node.module}.{alias.name}") is not None:
                        continue
                    errors.append(
                        f"NAME   {file.relative_to(ROOT)}:{node.lineno}: "
                        f"{node.module} has no top-level name {alias.name}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("securescan") and module_path(alias.name) is None:
                        errors.append(f"MODULE {file.relative_to(ROOT)}:{node.lineno}: no module {alias.name}")
    Path(__file__).with_suffix(".pyc").unlink(missing_ok=True)
    for line in errors:
        print(line)
    print(f"checked {len(files)} files, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
