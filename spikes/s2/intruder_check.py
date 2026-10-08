#!/usr/bin/env python3
"""Spike S2: a container that is not in the proxy's -allowfrom list must be refused. Stdlib only.

Run from the `intruder` service (run.sh enforce does this): exit 0 when the proxy refuses (HTTP 403, a reset or no
answer), exit 1 when GET /_ping succeeds from here. Prints exactly what happened for the findings file.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("DOCKER_HOST", "tcp://socket-proxy:2375").replace("tcp://", "http://")


def main() -> int:
    url = BASE + "/_ping"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            print("INTRUDER REACHED THE PROXY: GET %s -> HTTP %d" % (url, response.status))
            return 1
    except urllib.error.HTTPError as exc:
        print("refused: GET %s -> HTTP %d" % (url, exc.code))
        return 0 if exc.code == 403 else 1
    except Exception as exc:  # reset, timeout: also a refusal
        print("refused (no HTTP answer): GET %s -> %s: %s" % (url, type(exc).__name__, exc))
        return 0


if __name__ == "__main__":
    sys.exit(main())
