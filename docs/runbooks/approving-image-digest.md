# Runbook: approving a scanner image digest (the monthly review)

Every image SecureScan runs is pinned by digest in `deploy/images.lock.yaml`. A digest changes only through this process (design, "Scanner images"):
on the 1st of each month at 04:00 UTC the platform asks the registries, through the egress proxy, what every tag in the lock file points to now and which newer version tags exist.
New digests are stored as **proposals**; each is tested against the regression suite; an Admin approves, which makes the digest the one the **next scan** uses. Nothing changes without a person.

Shorthand `sc`, `psql`: `docs/install.md`. The Settings page for scanner images is a later addition to the portal (listed in `docs/build-notes/M11.md`); until it exists use the API from the browser, below.

## What a proposal is

| Field | Meaning |
| --- | --- |
| `tool` | the catalogue tool (`semgrep`, `gitleaks`, `grype`, `spotbugs`, ...) or the lower-cased lock name (`squid`, `postgres`, ...) |
| `tag`, `digest`, `previous_tag`, `previous_digest` | what is proposed and what runs now. `reason` is `rebuild` (the same tag now has a new digest) or `new_version` (a newer tag of the same series) |
| `scope` | `runtime`: started by the worker; approving takes effect at the next scan. `release`: part of the Compose bundle (PostgreSQL, Python, Node, nginx, the socket proxy, DefectDojo, Valkey); it cannot be approved here, it goes into `deploy/images.lock.yaml` with the next release |
| `regression_result` | `pending` / `testing` (queued or running), `passed`, `failed`, `error` (a job failed or ran the wrong image), `skipped` (nothing could be asserted) |
| `state` | `pending`, `active` (in use), `retired` (was active), `rejected` |
| `lock_line` | the line to put into `deploy/images.lock.yaml` in the next release commit |

What the platform will not propose: a different major version of PostgreSQL, Python, Node or DefectDojo; the self-built SpotBugs image
(rebuild it from new SpotBugs and Find Security Bugs releases: `scanners/spotbugs/README.md`); a digest you rejected before.

## Using the API from the browser (until the Settings page exists)

Sign in to the portal as an Admin, open the browser's developer console on the portal page and paste:

```js
const csrf = document.cookie.split('; ').find(c => c.startsWith('securescan_csrf=')).split('=')[1];
const call = (method, path, body) => fetch('/api/v1' + path, {
  method, credentials: 'same-origin',
  headers: {'X-CSRF-Token': csrf, 'Content-Type': 'application/json'},
  body: body ? JSON.stringify(body) : undefined,
}).then(r => r.json());
```

then, for example, `await call('GET', '/image-versions?state=pending')`. The endpoints (Admin only, all audited):

| Call | Effect |
| --- | --- |
| `GET /image-versions?state=pending&tool=...` | the list; `state` is `pending`, `active`, `retired` or `rejected` |
| `POST /image-versions/check` | look for new images now (queued; results appear within minutes) |
| `POST /image-versions/{id}/regression` | test a proposal again (after you fixed the cause of a failure) |
| `POST /image-versions/{id}/approve` with `{"acknowledge_skipped": true}` only for `skipped` | make it the image in use; the previously active row of that tool is retired |
| `POST /image-versions/{id}/reject` with `{"note": "why"}` | never propose that digest again |
| `POST /image-versions/{id}/deactivate` | stop using an approved image; scans fall back to the lock file's digest |

## The monthly review (about 30 minutes)

1. Open the pending list. Wait until no row says `pending` or `testing` for `regression_result` (a test is one scan per planted application; the first ones can take an hour).
2. For each **runtime** proposal:
   - `passed`: the new image reported every verified expected finding. Approve.
   - `skipped`: **nothing was asserted**: no expectation of that tool is verified yet, or the gate cannot test that image (the Syft image, squid, skopeo, ZAP, Nuclei: only Semgrep, Gitleaks, Grype and SpotBugs are gated, because only for those does the job record the digest that ran). Approving needs `acknowledge_skipped`, which means you tested it yourself:
     run a scan of a planted application with the candidate (or the suite by hand, `content-update-failed.md`, "Run the suite by hand"), read the job log and the findings, and only then approve. Consider verifying the expectations (`scanners/regression/README.md`) so the gate asserts something next month.
   - `failed`: the candidate lost a verified finding. Read `regression_detail.regression.results[*].missing`. Reject it, or wait for the next release of the tool. Never change the expectations to make a candidate pass without writing why in the commit (`scanners/regression/README.md`, rule 4).
   - `error`: a job failed, timed out, or the candidate image was not the one that ran. Look at the job outcome in the regression scan (application `regression-<app>`), fix the cause, request the test again.
3. For each **release** proposal: read the note, decide whether the next release takes it, and reject the rest so the list stays short.
4. After approving, check the next scan used it: `psql "select tool, image_digest, count(*) from scan_jobs where created_at > now() - interval '1 day' group by 1,2 order by 1"` shows the approved digest for the tool; each scan's detail shows the digest per job.

## Make it permanent

An approval lives in the database. In the next release commit, edit `deploy/images.lock.yaml` with the proposal's `lock_line` (tag and digest), run `python3 scripts/dev.py pin-images`, commit. After the release upgrade, deactivate the now redundant row (`release-upgrade.md`, "After").
The image must be present on the machine, and the worker may not pull. After approving a **runtime** image pull every approved reference from the host, **before** the next scan (otherwise that job fails with "image not found"; `stuck-scan.md` explains how to cancel and re-run it):

```
sc exec -T api python -m securescan.domain.image_updates active | while read ref; do docker pull "$ref"; done
```

(`python3 scripts/dev.py pull-images` reads only `deploy/images.env`, that is the lock file, so it does not know approved overlays until the release commit contains them.)

## Roll back

`POST /image-versions/{id}/deactivate` on the active row: the next scan uses the lock file's digest again (the old image is still on the machine). A job already running keeps what it started with.
If the new image wrote reports DefectDojo mis-parsed, see `defectdojo-unreachable.md` section 2.

## Record

The proposals reviewed, the decisions, the regression results and who acknowledged what. The audit log keeps `image.propose`, `image.regression`, `image.approve`, `image.reject` and `image.deactivate` with the actor.
