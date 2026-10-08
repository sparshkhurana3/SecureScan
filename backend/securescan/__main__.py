"""Entry point: ``python -m securescan <api|worker|migrate|dojo-init|sonar-init>``.

Each command except ``api`` is ``<module>:run`` returning an exit code. A command whose module does
not exist yet (later milestones) prints ``<command>: not implemented yet`` and returns 0.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

from securescan.config import get_settings
from securescan.logging import configure_logging

# command -> (module, function). ``api`` is handled in this file.
DISPATCH: dict[str, tuple[str, str]] = {
    "migrate": ("securescan.db.migrate", "run"),
    "worker": ("securescan.jobs.worker", "run"),
    "dojo-init": ("securescan.integrations.defectdojo.init", "run"),
    "sonar-init": ("securescan.integrations.sonarqube.init", "run"),
}
COMMANDS = ["api", *DISPATCH]


def run_api() -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "securescan.main:app",
        host="0.0.0.0",  # noqa: S104 - container-internal; only the gateway publishes a port
        port=8000,
        log_config=None,  # logging is configured by securescan.logging (JSON lines)
        reload=settings.is_dev and os.environ.get("SECURESCAN_RELOAD") == "1",
    )
    return 0


def not_implemented(name: str) -> int:
    print(f"{name}: not implemented yet")
    return 0


def dispatch(command: str) -> int:
    """Run ``command``; returns its exit code."""
    if command == "api":
        return run_api()
    module_name, function_name = DISPATCH[command]
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        # Only a missing target module (or one of its parent packages) means "not built yet";
        # a missing third-party dependency inside it is a real error.
        if exc.name and (module_name == exc.name or module_name.startswith(exc.name + ".")):
            return not_implemented(command)
        raise
    function = getattr(module, function_name, None)
    if function is None:
        return not_implemented(command)
    return int(function())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securescan")
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level)
    return dispatch(args.command)


if __name__ == "__main__":
    sys.exit(main())
