# S2: Socket proxy allowlist

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24.

## Purpose

Find the exact method-and-path allowlist for `wollomatic/socket-proxy` 1.13.1 that lets the worker's Docker SDK calls through and nothing else,
including `-allowfrom` and `-allowbindmountfrom`, and prove with a test that allowed calls work and denied calls return 403.

## Prerequisites

- Docker Engine on this host (rootful, `/var/run/docker.sock`), network access to pull `wollomatic/socket-proxy:1.13.1`, `python:3.14-slim-trixie`,
  `busybox:1.37`, and to `pip install docker httpx` inside the client container.
- No container named `sonarqube` on the host (the spike creates and removes one with that name; set `S2_SONAR_NAME` to change it).
- The volume `securescan_data` is used if it exists, otherwise created and removed by `run.sh down`.

## How to run

```
sh spikes/s2/run.sh discover    # proxy allows all + DEBUG; derive_paths.py prints the SDK's requests and writes spikes/s2/.data/enforce.env
sh spikes/s2/run.sh enforce     # proxy with the candidate allowlist; test_allowlist.py and the intruder check
sh spikes/s2/run.sh all         # both
sh spikes/s2/run.sh down        # clean up
```

Outputs to paste below: the table of requests, the candidate regexes (`.data/enforce.env`), the proxy start-up log (it prints the parsed allowlist),
the PASS/FAIL list of `test_allowlist.py`, the probes, the intruder result, and the first lines of `.data/proxy-debug.log`.

Open questions the run answers (the notes are not certain about them): whether the proxy matches the path only or the query string too; whether it
cleans `..` segments before the bind-mount check; the API version the SDK uses (`/v1.NN`); whether `/version` is called unversioned with
`version="auto"`; whether the proxy image (user 65534) needs the Docker group (`user: "65534:<gid>"`, as in `spikes/s2/docker-compose.yml`).

## What to record

| Fact | Value |
| --- | --- |
| Docker Engine version, daemon API version | |
| API prefix the SDK uses (default pass / `version="auto"`) | |
| Every request of the lifecycle (method, path, query, status) | |
| Does the container create with two networks in `EndpointsConfig` work? | |
| `GET /volumes/securescan_data` Mountpoint | |
| Candidate regexes: `SP_ALLOW_GET`, `SP_ALLOW_POST`, `SP_ALLOW_DELETE` (and numbered variants) | |
| `SP_ALLOWFROM` value that works (service name of the worker) | |
| `SP_ALLOWBINDMOUNTFROM` value | |
| `test_allowlist.py`: number of tests, failures | |
| Denied (403): exec, container list, network create, image create, volume create, others | |
| Path tricks (`..`, `%2f`, double slash): status codes | |
| Bind from `/etc`, from the Docker socket, `Mounts[]` bind, `..` escape, `VolumesFrom`: refused with 403? | |
| Named volume mounts (`Mounts` type volume and `name:/path` binds): allowed? | |
| Probes: privileged, host network, CapAdd, unversioned paths, HEAD `/_ping` | |
| Intruder container (not in `-allowfrom`): result | |
| Does the proxy need `user: 65534:<docker gid>` to read the socket? | |

## Decision

(empty)

- Final contents of `deploy/socket-proxy/args.env` (paste, then update the file in M3):
- Whether the proxy needs a `user:` entry in `deploy/compose.yaml`:
- What the proxy cannot filter (probes) and therefore what the worker must guarantee itself:

## Deviations from the design

(empty)
