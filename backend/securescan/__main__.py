"""Entry point: ``python -m securescan <api|worker|migrate|dojo-init|sonar-init>``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from securescan.config import get_settings

log = logging.getLogger("securescan")


def run_api() -> int:
    import uvicorn

    uvicorn.run("securescan.main:app", host="0.0.0.0", port=8000, log_level="info")  # noqa: S104
    return 0


async def _heartbeat() -> None:
    # Replaced by the Procrastinate worker in M2.
    while True:
        log.info("worker heartbeat")
        await asyncio.sleep(30)


def run_worker() -> int:
    asyncio.run(_heartbeat())
    return 0


def not_implemented(name: str) -> int:
    print(f"{name}: not implemented yet")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securescan")
    parser.add_argument("command", choices=["api", "worker", "migrate", "dojo-init", "sonar-init"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=get_settings().log_level, format="%(message)s")
    if args.command == "api":
        return run_api()
    if args.command == "worker":
        return run_worker()
    return not_implemented(args.command)


if __name__ == "__main__":
    sys.exit(main())
