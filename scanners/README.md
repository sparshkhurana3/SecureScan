# Scanners: how to add or bump a tool

`scanners/` holds everything the platform knows about the tools it runs:

| Path | What |
| --- | --- |
| `catalogue.yaml` (+ `catalogue.d/*.yaml`) | the **only** source of container specifications: image, user, network, mounts, tmpfs, limits, command, allowed optional switches, outputs, exit-code mapping, the DefectDojo scan type. Nothing about a container is built from user input |
| `profiles/*.yaml` | scan profiles (which tools run together, per-tool limits, verdict thresholds) and per-tool settings files (`semgrep.yaml`, `dependency-check.yaml`) |
| `regression/` | the regression suite: expected findings of the planted apps, runner configuration, the broken-rule drill (`regression/README.md`) |
| `spotbugs/` | the Dockerfile of the self-built SpotBugs + Find Security Bugs image |
| `gitleaks.toml`, `dast/` | tool configuration read through the `config` mount |

The rules that do not bend (`CLAUDE.md`, plan sections 1.2 and 8.1): DefectDojo is the only parser of scanner output; no scanner outside the catalogue; no CodeQL; every image pinned by digest, never `latest`; code scanners get no network;
secrets never in a command line; scanner output and scanned code never go to an external AI service.

## Add a tool

Do these in order, in one branch, with the checks at the end. A tool that DefectDojo cannot parse does not belong in the platform.

1. **Decide with the owner.** Licence (free, source-available at least; record it in `docs/licences.md` with the source and the licence file you read), what it finds that the current tools do not, and which DefectDojo scan type parses its report (`defectdojo_scan_type`, from DefectDojo's parser list at the pinned version).
2. **Run it by hand** on the planted apps from the pinned image, the way spike S7 does (`spikes/s7/`): network none, read-only root, `--cap-drop ALL`, a non-root user. Record in `docs/spikes/` which paths it must write (`docker diff`), its exit codes for clean, findings and broken runs, and its output file name. Save one real report as `backend/tests/fixtures/reports/<file>`.
3. **Pin the image.** Add a line to `deploy/images.lock.yaml` (`name` in capitals, `image`, `tag`, `digest: null`), run `python3 scripts/dev.py pin-images`; add `SECURESCAN_IMAGE_<NAME>: ${IMG_<NAME>:?run pin-images first}` to the `worker` environment in `deploy/compose.yaml`.
4. **Catalogue entry** in `catalogue.yaml` or a new `catalogue.d/<tool>.yaml`: `tool`, `image: {name, tag, lock}`, `user`, `network` (`none` for code scanners), `mounts` (`src` read-only, `out`, `config`, `content`), `tmpfs`, `limits` (`cpus`, `memory`, `pids`), `timeout_minutes`, `max_parallel`,
   `command` (placeholders `{src}`, `{out}`, `{config}`, `{content}`, `{target_url}`, `{project_key}`), `optional_args` (an allowlist of switches with value shapes), `outputs` (`file`, `max_mb`, `format`), `exit_codes` (`"0": completed`, `">=2": failed`, `default: failed`), `defectdojo_scan_type`, `defectdojo_file`.
   The schema and the checks are in `backend/securescan/runner/catalogue.py`; `uv run pytest tests/unit/test_runner_catalogue.py` validates the real file.
5. **Command builder**: `backend/securescan/runner/tools/<tool>.py` with `BUILDER = ...` (subclass `DefaultToolBuilder` when the catalogue entry is enough; override `prepare`, `optional_args`, `extra_env`, `post_run` for the rest). It builds a command, it never parses findings. It is registered automatically.
6. **Profile**: add the tool to the profile that should run it (a new profile **version**: released versions never change) and to `securescan/db/seeds/` if it ships with the platform.
7. **Regression expectations** (`scanners/regression/README.md`): add the tool as a key (an empty list is allowed) in every `backend/tests/fixtures/sample-apps/*/expected-findings.yaml`, entries for weaknesses that are certain from the planted code, `verified: false` until a real run produced a matching finding; add the tool to `suite.yaml`;
   for the image gate add `<tool>: (<job tool>, <expectation key>)` to `REGRESSION_TOOLS` in `backend/securescan/domain/image_updates.py`.
8. **Tests**: a command-builder unit test, an exit-code mapping test, a contract test (`backend/tests/contract/`: the fixture report imports into DefectDojo with a non-zero finding count), an integration test against a planted app.
9. **Documents**: `docs/licences.md`, the design's tool table if the user-visible list changes (a design change: ask first), `docs/decisions.md` for anything that differed from expectations.

Checks before merging: `cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy securescan && uv run pytest`; `python3 scripts/dev.py test contract`; a scan of `java-planted` or the app the tool targets reaches `imported` and its findings appear in DefectDojo;
`docker inspect` of the running scanner shows the hardening of `docs/security-checklist.md` section 3.

## Bump a tool (a new version of an existing tool)

Normally the monthly proposals do this (`docs/runbooks/approving-image-digest.md`): the platform finds the new digest or tag, runs the regression suite against it and an Admin approves. A bump by hand (a tool that changed its output format, a breaking flag, a new Grype
database schema) is a commit instead:

1. Edit the `tag` of the tool's line in `deploy/images.lock.yaml` (and `image.tag` in the catalogue entry, if it names one), run `python3 scripts/dev.py pin-images` and `pull-images`.
2. Run the tool by hand on the planted apps from the new image. Compare flags with the entry (`--help`), exit codes, output file name and format. Fix the entry and the builder where it changed; record each difference in `docs/decisions.md`.
3. **Refresh the fixture report** `backend/tests/fixtures/reports/<file>` from the new image and run the contract test (`python3 scripts/dev.py test contract`): the report must still import into DefectDojo with the expected severities. A format DefectDojo's parser does not understand stops the bump.
4. Run the regression suite for the tool (`sc exec worker python -m securescan.domain.regression run --kind image --tool <key>`); fix expectations only with a commit message that says why.
5. SonarQube follows the December rule across calendar years (`docs/runbooks/sonarqube-upgrade.md`); Grype needs a bump at least quarterly because Anchore retires old database schemas; the self-built SpotBugs image is rebuilt from new SpotBugs and Find Security Bugs releases (`scanners/spotbugs/README.md`).
6. Release as usual (`docs/runbooks/release-upgrade.md`); retire any approved overlay row that the new lock file now contains.

## Remove a tool

Remove it from the profiles (new profile versions), then from the catalogue, the builder, the lock file and the worker environment; leave its history rows and reports alone (history is permanent). Record why in `docs/decisions.md`.
