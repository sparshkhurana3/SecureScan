# Runbook: a scan is stuck, or a scanner container is orphaned

Use it when: the alert `SecureScanQueueStuck` fires (the oldest queued job waited more than 30 minutes), a scan shows *running* long after its
timeout, `docker ps` lists `securescan-job-*` containers that nobody expects, or a disk alert points at workspaces.

Shorthand: `sc` and `psql` are defined in `docs/install.md` and `docs/security-checklist.md`
(`psql` = `sc exec -T db psql -U postgres -d securescan -c`). Run everything from `/opt/securescan`.

## What the platform does by itself

- The worker sends a heartbeat for every running job. The periodic task `stalled_jobs` (every 5 minutes) re-queues or fails a job whose heartbeat is older than 5 minutes
  and re-defers `queued` jobs that lost their queue entry.
- On start the worker reconciles its containers with the database (`runner/recovery.py`): containers of jobs that no longer exist are removed.
- `workspace_gc` (hourly) removes workspaces older than 24 hours. The SonarQube server stops after 15 idle minutes, the egress proxy after 5.
- A job that exceeds its timeout is killed and ends `timed_out`; its container and workspace are removed.

So give a problem 5 to 10 minutes before acting.

## 1. Find out what is wrong

```
sc ps                                        # is the worker running and healthy?
sc logs --tail 200 worker                    # the last things it did
psql "select s.id, s.state, j.tool, j.state as job_state, j.heartbeat_at, j.container_id from scans s join scan_jobs j on j.scan_id = s.id where s.state in ('queued','running') order by s.created_at"
psql "select queue_name, status, count(*) from procrastinate_jobs group by 1,2 order by 1,2"
docker ps -a --filter name=securescan-job --format '{{.Names}}  {{.Status}}  {{.CreatedAt}}'
```

Reading the answers:

| You see | Meaning | Go to |
| --- | --- | --- |
| the worker is not running or is restarting | the host check failed, the database is down, or a crash | 2 |
| worker healthy, jobs `queued`, none `running` | a lock or a concurrency cap holds them (one DAST job at a time; `max_parallel` per tool), or the queue is paused by a long job | 3 |
| a job `running` with an old `heartbeat_at` and no matching container | the worker died mid-job | 4 |
| a `securescan-job-*` container with no running job | an orphan | 5 |
| the disk is nearly full | workspaces, images or artifacts | 6 |

## 2. The worker is down

`sc logs --tail 100 worker`. Common causes:

- `The host does not meet the requirements`: run `bash scripts/check_host.sh` and fix what it reports (cgroup v2, `vm.max_map_count`, Docker version). Do not set `SECURESCAN_HOST_CHECK=warn` to "get going": the limits of the scanner containers would not be enforced.
- The database is unreachable or the TLS certificate expired: `sc ps db`, `sc logs --tail 50 db`, `openssl x509 -in deploy/secrets/tls/server.crt -noout -enddate`.
- The socket proxy is down: `sc ps socket-proxy`; `sc logs socket-proxy`.

After the fix `sc up -d worker`. Jobs that were running resume through `stalled_jobs`.

## 3. Jobs wait in the queue

A heavy tool holds its slot: Dependency-Check, SonarQube and SpotBugs run one at a time, Semgrep two at a time; a DAST job blocks other DAST jobs.
Look at the running job's log in the portal (scan detail). If it is simply slow, wait; if it is hung past its timeout, cancel its scan in the portal (scan detail, Cancel).
**Do not edit `procrastinate_jobs` by hand.** If a job stays `doing` after a worker restart and 10 minutes, cancel the scan in the portal and start it again; tell the code owner.

## 4. A job is `running` but the worker died

Wait for `stalled_jobs` (5 minutes after the last heartbeat). If nothing happens, restart the worker (`sc restart worker`): its start-up reconciliation re-queues or fails the job.
If the scan stays `running` after that, cancel it in the portal and start a new one.

## 5. Remove an orphaned container

An orphan is a `securescan-job-*` (or `securescan-dast-*`) container whose job is finished or unknown:

```
docker ps -a --filter name=securescan-job --format '{{.Names}}'
docker rm -f securescan-job-<uuid>
```

`sonarqube` and `securescan-egress` are also created and removed by the worker; if they are stuck: `docker stop sonarqube` (it needs up to 5 minutes to stop cleanly, do not `kill` it) and `docker rm -f securescan-egress`.
Both come back by themselves when a job needs them.

## 6. Disk

```
df -h /var/lib/docker
docker system df
sudo du -sh /var/lib/docker/volumes/securescan_data/_data/workspaces/* 2>/dev/null | sort -h | tail
```

- Workspaces of finished jobs older than a day with no running job may be deleted: `sudo rm -rf /var/lib/docker/volumes/securescan_data/_data/workspaces/<job id>`.
- `docker image prune -f` removes only dangling images. **Never** run `docker system prune -a` or `--volumes`: it deletes the pinned scanner images (they cannot be pulled again through the socket proxy) and could delete data volumes.
- History, reports, raw reports and artifacts are kept forever by design; if `securescan_artifacts` or `securescan_pgdata` grows too fast, add disk (`docs/runbooks/performance.md`).

## Verify and record

- `sc ps` healthy; `docker ps --filter name=securescan-job` shows only containers of running jobs; the queue drains (`securescan_oldest_queued_job_age_seconds` returns to 0; the alert resolves).
- Note what happened and the cause in the operations log. A job that failed because of an image or rules update: `docs/runbooks/content-update-failed.md`.
