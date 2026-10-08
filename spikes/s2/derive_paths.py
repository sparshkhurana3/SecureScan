#!/usr/bin/env python3
"""Spike S2, discovery pass: derive the request paths the Docker SDK uses and print candidate allow regexes.

Runs inside the `client` container (see run.sh) while the proxy allows everything and logs at DEBUG:

    python /spike/derive_paths.py

What it does
  1. Switches on SDK/urllib3 debug logging (the raw request lines appear in the output).
  2. Runs the worker's whole container lifecycle (scenario.run_lifecycle) twice: with the SDK's default API
     version and with version="auto" (which sends an unversioned GET /version first).
  3. Prints every recorded call as a table (step, method, path, query, status).
  4. Generalises the paths into regexes (API version, container id and the SonarQube container name become
     patterns) and prints them as SP_ALLOW_* lines.
  5. Writes spikes/s2/.data/enforce.env: the proxy's environment for the enforcing pass (those lines plus
     SP_ALLOWFROM and SP_ALLOWBINDMOUNTFROM = the Mountpoint of the securescan_data volume), in the same format as
     deploy/socket-proxy/args.env so it can be pasted there.

Environment (all optional): DOCKER_HOST, S2_IMAGE, S2_VOLUME, S2_SONAR_NAME, S2_NET_A, S2_NET_B, S2_WORKSPACE,
S2_ALLOWFROM (default "client", the compose service name of the caller; in the real stack "worker").
Exit code 1 when any SDK call failed (status >= 400): the discovery pass must succeed completely.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scenario  # noqa: E402

DATA = Path(__file__).resolve().parent / ".data"
VERSION_RE = re.compile(r"^(/v[0-9]+[.][0-9]+)(/.*)$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CID = "CID"  # placeholder replaced in the final regex
CID_REGEX = "([0-9a-f]{64}|%s)" % re.escape(scenario.SONAR_NAME)
VERSION_PREFIX = "/v1[.][0-9]+"


def generalise(path: str) -> Tuple[str, bool]:
    """Return (pattern with CID placeholder, was_versioned)."""
    match = VERSION_RE.match(path)
    versioned = match is not None
    rest = match.group(2) if match else path
    parts = rest.split("/")  # ['', 'containers', '<id>', 'start']
    if len(parts) >= 3 and parts[1] == "containers" and parts[2] not in ("create", "json", "prune"):
        ident = parts[2]
        if HEX64.match(ident) or ident == scenario.SONAR_NAME or ident.startswith("s2-"):
            parts[2] = CID
    return "/".join(parts), versioned


def build_regexes(calls: List[Dict[str, object]]) -> Dict[str, List[str]]:
    """Group successful calls per method into the smallest list of regexes that permits exactly them."""
    seen = {}  # type: Dict[Tuple[str, str], Set[bool]]
    for call in calls:
        if int(call["status"]) >= 400:  # type: ignore[arg-type]
            continue
        pattern, versioned = generalise(str(call["path"]))
        seen.setdefault((str(call["method"]), pattern), set()).add(versioned)

    out = {}  # type: Dict[str, List[str]]
    verbs = {}  # type: Dict[Tuple[str, str], Set[str]]  # (method, versioned-prefix-kind) -> container verbs
    for (method, pattern), kinds in sorted(seen.items()):
        prefix = VERSION_PREFIX if kinds == {True} else ("(%s)?" % VERSION_PREFIX)
        # one alternation for /containers/CID/<verb>
        m = re.match(r"^/containers/%s/([a-z]+)$" % CID, pattern)
        if m:
            verbs.setdefault((method, prefix), set()).add(m.group(1))
            continue
        body = pattern.replace(CID, CID_REGEX)
        out.setdefault(method, []).append(prefix + body)
    for (method, prefix), names in sorted(verbs.items()):
        out.setdefault(method, []).append("%s/containers/%s/(%s)" % (prefix, CID_REGEX, "|".join(sorted(names))))
    # DELETE /containers/CID has no verb: it was kept as a plain pattern above
    return out


def print_table(title: str, calls: List[Dict[str, object]]) -> None:
    print("\n### %s\n" % title)
    print("| step | method | path | query | status |")
    print("| --- | --- | --- | --- | --- |")
    for c in calls:
        print("| %s | %s | `%s` | `%s` | %s |" % (c["step"], c["method"], c["path"], c["query"], c["status"]))


def quoted(name: str, value: str) -> str:
    # Compose env_file: single quotes keep the value literal (no interpolation, no comment stripping).
    return "%s='%s'" % (name, value)


def main() -> int:
    scenario.enable_sdk_debug_logging()
    all_calls = []  # type: List[Dict[str, object]]
    host_root = ""
    for label, version in (("SDK default API version", None), ('version="auto"', "auto")):
        print("\n==== lifecycle pass: %s ====" % label)
        client = scenario.make_client(version)
        rec = scenario.Recorder()
        rec.attach(client)
        info = scenario.run_lifecycle(client, rec)
        host_root = str(info["host_root"])
        print("API version reported by the daemon: %s; volume mountpoint: %s; job exit: %s; job logs: %r" % (
            info.get("api_version"), host_root, info.get("exit"), str(info.get("logs", "")).strip()))
        print_table("Requests made (%s)" % label, rec.calls)
        all_calls.extend(rec.calls)

    failed = [c for c in all_calls if int(c["status"]) >= 400]  # type: ignore[arg-type]
    if failed:
        print("\nFAILED: %d SDK call(s) returned >= 400 during discovery:" % len(failed))
        for c in failed:
            print("  %s %s -> %s (%s)" % (c["method"], c["path"], c["status"], c["step"]))
        return 1

    regexes = build_regexes(all_calls)
    allowfrom = os.environ.get("S2_ALLOWFROM", "client")
    lines = [
        "# Candidate allowlist derived by spikes/s2/derive_paths.py. Anchors ^ and $ are added by the proxy.",
        "# Paste into deploy/socket-proxy/args.env at M3 after spikes/s2/test_allowlist.py passes against it.",
        "SP_LISTENIP=0.0.0.0",
        "SP_PROXYPORT=2375",
        "SP_LOGLEVEL=INFO",
        "SP_ALLOWFROM=%s" % allowfrom,
        "SP_ALLOWBINDMOUNTFROM=%s" % host_root,
    ]
    for method in sorted(regexes):
        for index, pattern in enumerate(regexes[method]):
            name = "SP_ALLOW_%s" % method if index == 0 else "SP_ALLOW_%s_%d" % (method, index + 1)
            lines.append(quoted(name, pattern))
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "enforce.env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n### Candidate allowlist (written to spikes/s2/.data/enforce.env)\n")
    print("```")
    print("\n".join(lines))
    print("```")
    print("\nThe same, as command-line arguments:\n```")
    for method in sorted(regexes):
        for pattern in regexes[method]:
            print("-allow%s='%s'" % (method, pattern))
    print("-allowfrom=%s\n-allowbindmountfrom=%s\n```" % (allowfrom, host_root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
