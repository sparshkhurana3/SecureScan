#!/usr/bin/env python3
"""Spike S3: SonarQube Community Build on demand (plan M1, S3 steps 1-8).

Run (repository root, Docker on this host, vm.max_map_count >= 524288):

    uv run --project backend python spikes/s3/run.py

Environment variables (all optional)
    S3_URL               SonarQube URL as seen from the host (default http://127.0.0.1:9000)
    S3_COMPOSE_FILES     compose file arguments (default "-f <repo>/spikes/s3/docker-compose.yml"); see docker-compose.tls.yml
    S3_SCANNER_IMAGE     default sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0
    S3_NETWORK           internal network the scanner joins (default securescan-spike-s3_s3_sonarqube)
    S3_SOURCE_JS         source of the SonarQube analysis, default backend/tests/fixtures/sample-apps/js-planted
    S3_SOURCE_JAVA       default backend/tests/fixtures/sample-apps/java-planted
    S3_START_TIMEOUT     seconds to wait for status UP (default 900)
    S3_REPORTS_DIR       where sonarqube-issues.zip is written as fixture (default backend/tests/fixtures/reports);
                         set S3_WRITE_FIXTURE=0 to keep the zip under spikes/s3/.data only
    S3_KEEP_RUNNING      1 = leave the server running at the end (default: stopped, as the idle-stop would do)
    S3_DD_URL, S3_DD_TOKEN   optional: also import the zip into DefectDojo as "SonarQube Scan" (S1 does this too)

Steps: 1 start the server and time it, 2 time the status endpoint to UP, 3 change the admin password,
4 service user + tokens + project + analysis token, 5 run sonar-scanner-cli with the M3 hardening flags against js-planted
(report-task.txt, ce task polling), 6 quality gate, measures, issues export into a zip (type/severity check),
7 java-planted without sonar.java.binaries, 8 stop (timed), warm restart (timed), stop again.
The admin password and the service-user credentials are kept in spikes/s3/.data/s3-secrets.json (mode 0600). Nothing
secret is printed (tokens are passed to the scanner container through the environment, never on a command line).
"""

from __future__ import annotations

import datetime
import json
import os
import shlex
import shutil
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spikelib  # noqa: E402
from spikelib import Spike, SpikeFailure, env, run_cmd  # noqa: E402

HERE = Path(__file__).resolve().parent
PROJECT_JS = "s3-js-planted"
PROJECT_JAVA = "s3-java-planted"
SERVICE_USER = "securescan-sonar"


class Sonar:
    def __init__(self, spike: Spike, client: Any, base: str) -> None:
        self.spike = spike
        self.c = client
        self.base = base.rstrip("/")
        self.auth_headers = {}  # type: Dict[str, str]
        self.basic = None  # type: Optional[Tuple[str, str]]

    def call(self, method: str, path: str, expect: Optional[List[int]] = None, label: Optional[str] = None,
             data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, admin: bool = False,
             anonymous: bool = False, max_body: int = 2500, show_body: bool = True) -> Any:
        kwargs = {}  # type: Dict[str, Any]
        if admin:
            kwargs["auth"] = self.basic
        elif not anonymous:
            kwargs["headers"] = dict(self.auth_headers)
        return self.spike.http(self.c, method, self.base + path, expect=expect if expect is not None else [200],
                               label=label, data=data, params=params, max_body=max_body, show_body=show_body, **kwargs)

    def status(self) -> str:
        try:
            r = self.c.get(self.base + "/api/system/status", timeout=5)
            return str(r.json().get("status", ""))
        except Exception:
            return ""


def compose_argv(files: List[str], *args: str) -> List[str]:
    return ["docker", "compose"] + files + list(args)


def tomorrow() -> str:
    return (datetime.date.today() + datetime.timedelta(days=1)).isoformat()


def prepare_workspace(source: Path, key: str) -> Tuple[Path, Path]:
    """Copy the source to .data/ws/<key>/src and make it writable by any uid (uid 1000 in the container)."""
    base = HERE / ".data" / "ws" / key
    if base.exists():
        shutil.rmtree(str(base))
    src, out = base / "src", base / "out"
    shutil.copytree(str(source), str(src))
    out.mkdir(parents=True)
    for root, dirs, files in os.walk(str(base)):
        os.chmod(root, 0o777)
        for name in files:
            os.chmod(os.path.join(root, name), 0o666)
    return src, out


def run_scanner(
    spike: Spike, image: str, network: str, src: Path, out: Path, key: str, token: str, host_url: str,
    extra_args: List[str],
) -> Tuple[int, str, str]:
    """sonar-scanner-cli with the M3 hardening flags. Returns (exit code, output, the config that worked)."""
    ladder = [("ro", "noexec"), ("rw", "noexec"), ("rw", "exec")]
    last = (1, "", "")
    for src_mode, tmp_mode in ladder:
        tmpfs = "/tmp:rw,size=512m,uid=1000,gid=1000,mode=1777" + (",exec" if tmp_mode == "exec" else "")
        argv = [
            "docker", "run", "--rm", "--name", "s3-scanner-" + key, "--network", network,
            "--user", "1000:1000", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "512", "--memory", "2g", "--cpus", "2", "--tmpfs", tmpfs,
            "-v", "%s:/usr/src:%s" % (src, src_mode), "-v", "%s:/out:rw" % out,
            "-e", "SONAR_HOST_URL=" + host_url, "-e", "SONAR_TOKEN", "-e", "SONAR_USER_HOME=/tmp/.sonar",
            image,
            "sonar-scanner", "-Dsonar.projectKey=" + key, "-Dsonar.sources=.", "-Dsonar.scm.disabled=true",
            "-Dsonar.working.directory=/out/.scannerwork",
        ] + extra_args
        spike.note("scanner attempt: /usr/src mounted %s, /tmp tmpfs %s" % (src_mode, tmp_mode))
        if (out / ".scannerwork").exists():
            shutil.rmtree(str(out / ".scannerwork"), ignore_errors=True)
        code, output, secs = run_cmd(spike, argv, check=False, timeout=1800, env_extra={"SONAR_TOKEN": token},
                                     show=" ".join(shlex.quote(a) for a in argv) + "   (SONAR_TOKEN passed via environment)",
                                     max_out=3500)
        last = (code, output, "src=%s tmp=%s" % (src_mode, tmp_mode))
        spike.fact("scanner[%s]_attempt src=%s tmp=%s" % (key, src_mode, tmp_mode), "exit %d in %.0f s" % (code, secs))
        if code == 0:
            return last
    return last


def read_report_task(out: Path) -> Dict[str, str]:
    path = out / ".scannerwork" / "report-task.txt"
    if not path.exists():
        raise SpikeFailure("report-task.txt not found at %s" % path)
    values = {}  # type: Dict[str, str]
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
    return values


def body(spike: Spike) -> int:
    base = env("S3_URL", "http://127.0.0.1:9000") or ""
    compose_files = shlex.split(env("S3_COMPOSE_FILES", "-f %s" % (HERE / "docker-compose.yml")) or "")
    scanner_image = env("S3_SCANNER_IMAGE", "sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0") or ""
    network = env("S3_NETWORK", "securescan-spike-s3_s3_sonarqube") or ""
    src_js = Path(env("S3_SOURCE_JS", str(spikelib.SAMPLE_APPS_DIR / "js-planted")) or "")
    src_java = Path(env("S3_SOURCE_JAVA", str(spikelib.SAMPLE_APPS_DIR / "java-planted")) or "")
    start_timeout = float(env("S3_START_TIMEOUT", "900") or "900")
    reports_dir = Path(env("S3_REPORTS_DIR", str(spikelib.DEFAULT_REPORTS_DIR)) or "")
    write_fixture = (env("S3_WRITE_FIXTURE", "1") or "1") == "1"
    keep_running = (env("S3_KEEP_RUNNING", "0") or "0") == "1"
    store = spikelib.SecretStore(HERE / ".data" / "s3-secrets.json")
    client = spikelib.make_http_client(timeout=120.0)
    sonar = Sonar(spike, client, base)
    server_host_url = "http://sonarqube:9000"

    # ---- prerequisites ------------------------------------------------------------------------
    spike.step("Host prerequisites")
    try:
        max_map = int(Path("/proc/sys/vm/max_map_count").read_text().strip())
    except (OSError, ValueError):
        max_map = -1
    spike.fact("vm.max_map_count", max_map)
    if 0 <= max_map < 262144:
        spike.fail("vm.max_map_count is %d; SonarQube's Elasticsearch needs >= 262144 (plan: 524288). "
                   "sudo sysctl -w vm.max_map_count=524288" % max_map)
    if 0 <= max_map < 524288:
        spike.warn("vm.max_map_count %d is below the 524288 the plan asks for" % max_map)
    for p, label in ((src_js, "js-planted"), (src_java, "java-planted")):
        spike.expect(p.is_dir(), "source directory exists: %s (%s)" % (p, label))

    # ---- step 1 and 2: start and time to UP --------------------------------------------------------
    spike.step("S3.1/S3.2 start the server and time `GET /api/system/status` until UP")
    already = sonar.status()
    if already == "UP":
        spike.note("the server is already running and UP: first-start timing is not measured in this run "
                   "(docker compose down -v for a cold start)")
        spike.fact("first_start_seconds", "not measured (already running)")
    else:
        t0 = time.monotonic()
        run_cmd(spike, compose_argv(compose_files, "up", "-d"), timeout=900)
        waited = spikelib.wait_until(spike, "SonarQube status UP", lambda: sonar.status() == "UP", start_timeout, 3.0)
        total = time.monotonic() - t0
        spike.fact("first_start_seconds", "%.0f (compose up %.0f s + wait %.0f s); cold if the volumes were new" % (
            total, total - waited, waited))
    sonar.call("GET", "/api/system/status", anonymous=True, label="GET /api/system/status")
    run_cmd(spike, ["docker", "inspect", "--format", "{{.Config.Image}} user={{.Config.User}} restart={{.HostConfig.RestartPolicy.Name}}",
                    "sonarqube"], check=False)

    # ---- step 3: admin password ------------------------------------------------------------------------
    spike.step("S3.3 change the admin password (basic auth admin:admin)")
    stored_pw = store.get("admin_password")
    valid = False
    if stored_pw:
        r = client.get(base + "/api/authentication/validate", auth=("admin", str(stored_pw)))
        valid = r.status_code == 200 and r.json().get("valid") is True
    if valid:
        spike.note("admin password from an earlier run is still valid; reused")
        sonar.basic = ("admin", str(stored_pw))
    else:
        new_pw = spikelib.random_password(20)
        sonar.basic = ("admin", "admin")
        sonar.call("POST", "/api/users/change_password", expect=[204], admin=True,
                   data={"login": "admin", "previousPassword": "admin", "password": new_pw},
                   label="POST /api/users/change_password (admin:admin -> new password)")
        store.set("admin_password", new_pw)
        sonar.basic = ("admin", new_pw)
        spike.fact("admin_password_changed", True)
    sonar.call("GET", "/api/authentication/validate", admin=True, label="the new password works")

    # ---- step 4: service user and tokens -------------------------------------------------------------------
    spike.step("S3.4 service user, USER_TOKEN, project, PROJECT_ANALYSIS_TOKEN")
    r = sonar.call("GET", "/api/users/search", admin=True, params={"q": SERVICE_USER}, label="look up service user",
                   max_body=800)
    exists = any(u.get("login") == SERVICE_USER for u in r.json().get("users", []))
    if not exists:
        svc_pw = spikelib.random_password(20)
        sonar.call("POST", "/api/users/create", admin=True, label="POST /api/users/create (local service user)",
                   data={"login": SERVICE_USER, "name": "SecureScan service", "password": svc_pw, "local": "true"},
                   max_body=800)
        store.set("service_password", svc_pw)
    for permission in ("provisioning", "scan"):
        sonar.call("POST", "/api/permissions/add_user", expect=[204], admin=True,
                   data={"login": SERVICE_USER, "permission": permission},
                   label="grant global permission '%s' to the service user (least privilege first)" % permission)
    stamp = str(int(time.time()))
    r = sonar.call("POST", "/api/user_tokens/generate", admin=True, label="POST /api/user_tokens/generate type=USER_TOKEN",
                   data={"login": SERVICE_USER, "name": "securescan-spike-" + stamp, "type": "USER_TOKEN"})
    user_token = str(r.json()["token"])
    spike.fact("user_token_length", len(user_token))
    spike.fact("user_token_prefix", user_token[:4])
    sonar.auth_headers = {"Authorization": "Bearer " + user_token}
    r = sonar.call("GET", "/api/authentication/validate", label="Bearer USER_TOKEN is accepted", max_body=300)
    spike.expect(r.json().get("valid") is True, "the USER_TOKEN authenticates as the service user")

    def ensure_project(key: str, name: str) -> str:
        found = sonar.call("GET", "/api/projects/search", params={"projects": key}, label="look up project %s" % key,
                           max_body=600).json()
        if not found.get("components"):
            sonar.call("POST", "/api/projects/create", data={"project": key, "name": name},
                       label="POST /api/projects/create (service user token)", max_body=800)
        rr = sonar.call("POST", "/api/user_tokens/generate", label="PROJECT_ANALYSIS_TOKEN with expirationDate",
                        data={"name": "analysis-%s-%s" % (key, stamp), "type": "PROJECT_ANALYSIS_TOKEN",
                              "projectKey": key, "expirationDate": tomorrow()}, max_body=800)
        token = str(rr.json()["token"])
        spike.fact("analysis_token_length[%s]" % key, len(token))
        spike.fact("analysis_token_expiration[%s]" % key, rr.json().get("expirationDate"))
        return token

    token_js = ensure_project(PROJECT_JS, "S3 js-planted")

    # ---- step 5: scanner ---------------------------------------------------------------------------------------
    spike.step("S3.5 sonar-scanner-cli (M3 hardening flags) against js-planted")
    run_cmd(spike, ["docker", "image", "inspect", "--format", "scanner image user={{.Config.User}} workdir={{.Config.WorkingDir}} "
                    "entrypoint={{.Config.Entrypoint}} cmd={{.Config.Cmd}}", scanner_image], check=False)
    run_cmd(spike, ["docker", "network", "inspect", "--format", "{{.Name}} internal={{.Internal}}", network], check=True)
    run_cmd(spike, ["docker", "run", "--rm", "--user", "1000:1000", "--entrypoint", "sh", scanner_image, "-c",
                    "id; echo HOME=$HOME; echo SONAR_USER_HOME=$SONAR_USER_HOME; ls -ld /usr/src /opt/sonar-scanner "
                    "2>&1 | head"], check=False)
    src, out = prepare_workspace(src_js, PROJECT_JS)
    code, output, used = run_scanner(spike, scanner_image, network, src, out, PROJECT_JS, token_js, server_host_url, [])
    spike.fact("scanner_working_config", used)
    spike.expect(code == 0, "sonar-scanner exited 0 with config %s" % used)
    spike.fact("scanner_exit_code_on_findings", code)
    spike.fact("scanner_output_warnings", "; ".join(
        line.strip() for line in output.splitlines() if " WARN" in line)[:600] or "none")
    task = read_report_task(out)
    spike.block(json.dumps({k: v for k, v in task.items()}, indent=2), "json")
    spike.fact("report_task_keys", ", ".join(sorted(task)))
    ce_id = task["ceTaskId"]
    t0 = time.monotonic()
    state = {"status": ""}  # type: Dict[str, str]

    def ce_done() -> bool:
        rr = client.get(base + "/api/ce/task", params={"id": ce_id}, headers=sonar.auth_headers)
        state["status"] = str(rr.json().get("task", {}).get("status", ""))
        return state["status"] in ("SUCCESS", "FAILED", "CANCELED")

    spikelib.wait_until(spike, "compute-engine task %s" % ce_id, ce_done, 900, 2.0)
    spike.fact("ce_task_seconds_after_scanner_exit", "%.0f" % (time.monotonic() - t0))
    sonar.call("GET", "/api/ce/task", params={"id": ce_id}, label="GET /api/ce/task", max_body=1500)
    spike.expect(state["status"] == "SUCCESS", "compute engine task status is SUCCESS (is %s)" % state["status"])

    # ---- step 6: quality gate, measures, issues ----------------------------------------------------------------------
    spike.step("S3.6 quality gate, measures, issues export, import into DefectDojo")
    r = sonar.call("GET", "/api/qualitygates/project_status", params={"projectKey": PROJECT_JS},
                   label="GET /api/qualitygates/project_status", max_body=1800)
    spike.fact("quality_gate_status", r.json().get("projectStatus", {}).get("status"))
    metrics = "bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc,alert_status"
    r = sonar.call("GET", "/api/measures/component", params={"component": PROJECT_JS, "metricKeys": metrics},
                   label="GET /api/measures/component", max_body=2500)
    measures = {m["metric"]: m.get("value") for m in r.json().get("component", {}).get("measures", [])}
    spike.fact("measures", measures)

    def export_issues(project: str, target: Path) -> Tuple[int, Dict[str, Any]]:
        pages = []  # type: List[Dict[str, Any]]
        page, size = 1, 500
        while True:
            rr = sonar.call("GET", "/api/issues/search", params={"components": project, "ps": size, "p": page},
                            label="GET /api/issues/search page %d" % page, max_body=1200, show_body=(page == 1))
            data = rr.json()
            pages.append(data)
            total = int(data.get("paging", {}).get("total", len(data.get("issues", []))))
            if page * size >= total:
                break
            if page * size >= 10000:
                spike.warn("more than 10000 issues: the API cannot page beyond 10000; M8 must split by `types`")
                break
            page += 1
        with zipfile.ZipFile(str(target), "w", zipfile.ZIP_DEFLATED) as zf:
            for index, data in enumerate(pages, 1):
                zf.writestr("issues-%d.json" % index, json.dumps(data))
        return int(pages[0].get("paging", {}).get("total", 0)), pages[0]

    zip_path = HERE / ".data" / "sonarqube-issues.zip"
    total, first_page = export_issues(PROJECT_JS, zip_path)
    spike.fact("issues_total", total)
    issues = first_page.get("issues", [])
    if issues:
        keys = sorted(issues[0].keys())
        spike.fact("issue_keys", ", ".join(keys))
        has_std = "type" in issues[0] and "severity" in issues[0]
        spike.fact("issues_have_type_and_severity", has_std)
        r = sonar.call("GET", "/api/settings/values", admin=True, params={"keys": "sonar.multi-quality-mode.enabled"},
                       label="read the Mode setting (MQR on = default)", max_body=600)
        spike.fact("mqr_setting_value", json.dumps(r.json().get("settings", [])))
        if not has_std:
            r = sonar.call("POST", "/api/settings/set", admin=True, expect=[204, 400, 403, 404],
                           data={"key": "sonar.multi-quality-mode.enabled", "value": "false"},
                           label="switch to Standard Experience (sonar.multi-quality-mode.enabled=false)")
            spike.fact("standard_experience_switch_http_status", r.status_code)
            total, first_page = export_issues(PROJECT_JS, zip_path)
            issues = first_page.get("issues", [])
            spike.expect(bool(issues) and "type" in issues[0] and "severity" in issues[0],
                         "after switching modes the issues carry type and severity")
    else:
        spike.warn("SonarQube reported no issues for js-planted; check the analysis log above")
        spike.fact("issues_have_type_and_severity", "no issues to inspect")
    rr = sonar.call("GET", "/api/hotspots/search", params={"projectKey": PROJECT_JS, "ps": 500},
                    label="GET /api/hotspots/search (hotspots are NOT part of /api/issues/search)", max_body=800,
                    expect=[200, 400, 403, 404])
    if rr.status_code == 200:
        spike.fact("hotspots_total", rr.json().get("paging", {}).get("total"))
    spike.fact("issues_zip_bytes", zip_path.stat().st_size)
    if write_fixture:
        reports_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(zip_path), str(reports_dir / "sonarqube-issues.zip"))
        spike.note("fixture written: %s" % (reports_dir / "sonarqube-issues.zip"))
    dd_url, dd_token = env("S3_DD_URL"), env("S3_DD_TOKEN")
    if dd_url and dd_token:
        r = spike.http(client, "POST", dd_url.rstrip("/") + "/api/v2/reimport-scan/", expect=None,
                       headers={"Authorization": "Token " + dd_token},
                       data={"scan_type": "SonarQube Scan", "product_type_name": "Internal Applications",
                             "product_name": "spike-app", "engagement_name": "main", "test_title": "sonarqube:s3",
                             "auto_create_context": "true", "close_old_findings": "true",
                             "deduplication_on_engagement": "true", "deduplication_execution_mode": "async_wait",
                             "minimum_severity": "Info"},
                       files={"file": ("sonarqube-issues.zip", zip_path.read_bytes(), "application/zip")},
                       label="import the zip into DefectDojo as 'SonarQube Scan'", timeout=600, max_body=1500)
        spike.fact("defectdojo_import_status", r.status_code)
    else:
        spike.note("S3_DD_URL/S3_DD_TOKEN not set: the DefectDojo import of the zip is covered by S1 step 8")
    run_cmd(spike, ["docker", "stats", "--no-stream", "--format", "{{.Name}} mem={{.MemUsage}} cpu={{.CPUPerc}}", "sonarqube"],
            check=False)

    # ---- step 7: java without binaries -----------------------------------------------------------------------------------
    spike.step("S3.7 java-planted without sonar.java.binaries")
    token_java = ensure_project(PROJECT_JAVA, "S3 java-planted")
    src_j, out_j = prepare_workspace(src_java, PROJECT_JAVA)
    code, output, used = run_scanner(spike, scanner_image, network, src_j, out_j, PROJECT_JAVA, token_java, server_host_url, [])
    notes = [line.strip() for line in output.splitlines() if "binaries" in line.lower() or " ERROR" in line or " WARN" in line]
    spike.fact("java_without_binaries_exit_code", code)
    spike.fact("java_without_binaries_messages", " | ".join(notes)[:900] or "none")
    if code != 0:
        spike.note("the scan failed without binaries; retrying with an empty directory as sonar.java.binaries")
        (out_j / "empty-classes").mkdir(exist_ok=True)
        os.chmod(str(out_j / "empty-classes"), 0o777)
        code2, output2, used2 = run_scanner(spike, scanner_image, network, src_j, out_j, PROJECT_JAVA, token_java,
                                            server_host_url, ["-Dsonar.java.binaries=/out/empty-classes"])
        spike.fact("java_with_empty_binaries_dir_exit_code", code2)
        spike.expect(code2 == 0, "the plan's fallback (empty directory as sonar.java.binaries) works")
    else:
        task_j = read_report_task(out_j)
        ce_id = task_j["ceTaskId"]
        spikelib.wait_until(spike, "compute-engine task (java)", ce_done_factory(client, base, sonar, ce_id), 900, 2.0)
        rr = sonar.call("GET", "/api/issues/search", params={"components": PROJECT_JAVA, "ps": 50},
                        label="issues for java-planted (without bytecode)", max_body=600, show_body=False)
        spike.fact("java_without_binaries_issue_count", rr.json().get("paging", {}).get("total"))

    # ---- step 8: stop, warm restart, stop ------------------------------------------------------------------------------------
    spike.step("S3.8 stop (timed), warm restart (timed), stop again")
    _, _, stop_s = run_cmd(spike, compose_argv(compose_files, "stop", "sonarqube"), timeout=420)
    spike.fact("stop_seconds", "%.1f" % stop_s)
    t0 = time.monotonic()
    run_cmd(spike, compose_argv(compose_files, "start", "sonarqube"), timeout=300)
    spikelib.wait_until(spike, "SonarQube status UP after warm restart", lambda: sonar.status() == "UP", start_timeout, 3.0)
    spike.fact("warm_restart_seconds", "%.0f" % (time.monotonic() - t0))
    r = sonar.call("GET", "/api/projects/search", params={"projects": PROJECT_JS}, label="data survived the restart",
                   max_body=600, expect=[200, 401])
    spike.fact("data_survives_restart", r.status_code == 200)
    if not keep_running:
        _, _, stop2 = run_cmd(spike, compose_argv(compose_files, "stop", "sonarqube"), timeout=420)
        spike.fact("stop_seconds_second", "%.1f" % stop2)
    spike.note("Go/no-go for the 15-minute idle stop: compare warm_restart_seconds with the time a user waits for a "
               "SonarQube job; the worker does not wait for the stop, only for the start.")
    return 0


def ce_done_factory(client: Any, base: str, sonar: Sonar, ce_id: str) -> Any:
    def done() -> bool:
        rr = client.get(base + "/api/ce/task", params={"id": ce_id}, headers=sonar.auth_headers)
        return str(rr.json().get("task", {}).get("status", "")) in ("SUCCESS", "FAILED", "CANCELED")

    return done


def main() -> int:
    spike = Spike("s3", "S3 SonarQube on demand", HERE)
    return spikelib.run_spike(spike, body)


if __name__ == "__main__":
    sys.exit(main())
