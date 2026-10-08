#!/usr/bin/env python3
"""Spike S6: GitHub App (JWT, installation token, repository listing, credential-helper clone).

Run (repository root):

    GITHUB_APP_CLIENT_ID=Iv23... GITHUB_INSTALLATION_ID=12345678 GITHUB_REPO=my-org/my-repo \
    GITHUB_APP_KEY_FILE=deploy/secrets/github_app_key_1 \
    uv run --project backend python spikes/s6/run.py

Environment variables
    GITHUB_APP_CLIENT_ID   the App's client id (used as JWT `iss`, the form GitHub recommends); or GITHUB_APP_ID (numeric)
    GITHUB_INSTALLATION_ID installation id (from the URL of the installation settings page, or GET /app/installations)
    GITHUB_APP_KEY_FILE    PEM private key (default deploy/secrets/github_app_key_1, git-ignored)
    GITHUB_REPO            owner/name of a repository the App can read (required)
    GITHUB_API_URL         default https://api.github.com            (GitHub Enterprise: https://<host>/api/v3)
    GITHUB_GIT_URL         default https://github.com               (the git host used for the clone)
    GITHUB_API_VERSION     default 2026-03-10                        (X-GitHub-Api-Version header, plan S6 step 2)

Steps (plan S6): mint a JWT (RS256, iat 60 s in the past, exp 9 minutes ahead); check the App's permissions;
POST /app/installations/<id>/access_tokens scoped to the one repository with contents:read; list installation repositories
(paginated, with an unscoped token); read the default branch head; clone with a credential helper (token only in the
environment of the git process), with full history and all refs; `git remote remove origin`; assert that no token remains
anywhere under .git; revoke the token and confirm it stops working.
Secrets: the private key and tokens are never printed or put on a command line (only their lengths are shown).
Exit code 0 only when every assertion held.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spikelib  # noqa: E402
from spikelib import Spike, SpikeFailure, env, run_cmd  # noqa: E402

HERE = Path(__file__).resolve().parent
HELPER = "!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f"


def mint_jwt(key_pem: str, issuer: str) -> str:
    import jwt

    now = int(time.time())
    return str(jwt.encode({"iat": now - 60, "exp": now + 540, "iss": issuer}, key_pem, algorithm="RS256"))


def gh_headers(token: str, version: str) -> Dict[str, str]:
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": version,
    }


def git_out(args: List[str], cwd: Path) -> str:
    return subprocess.run(["git"] + args, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True).stdout.decode(
        "utf-8", "replace").strip()


def scan_tree_for(root: Path, needles: List[bytes], skip_dirs: Optional[List[str]] = None) -> List[str]:
    """Return the files below ``root`` that contain any of the byte strings (top-level dirs in skip_dirs are skipped)."""
    hits = []  # type: List[str]
    for path in root.rglob("*"):
        if skip_dirs and path.relative_to(root).parts and path.relative_to(root).parts[0] in skip_dirs:
            continue
        if path.is_file():
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if any(n and n in data for n in needles):
                hits.append(str(path.relative_to(root)))
    return hits


def body(spike: Spike) -> int:
    api = (env("GITHUB_API_URL", "https://api.github.com") or "").rstrip("/")
    git_url = (env("GITHUB_GIT_URL", "https://github.com") or "").rstrip("/")
    version = env("GITHUB_API_VERSION", "2026-03-10") or "2026-03-10"
    installation_id = env("GITHUB_INSTALLATION_ID", required=True) or ""
    repo_full = env("GITHUB_REPO", required=True) or ""
    issuer = env("GITHUB_APP_CLIENT_ID") or env("GITHUB_APP_ID") or ""
    if not issuer:
        raise SpikeFailure("set GITHUB_APP_CLIENT_ID (preferred) or GITHUB_APP_ID")
    key_file = Path(env("GITHUB_APP_KEY_FILE", str(spikelib.REPO_ROOT / "deploy" / "secrets" / "github_app_key_1")) or "")
    if not key_file.exists():
        raise SpikeFailure("private key file not found: %s" % key_file)
    if "/" not in repo_full:
        raise SpikeFailure("GITHUB_REPO must look like owner/name")
    owner, repo = repo_full.split("/", 1)
    key_pem = key_file.read_text(encoding="utf-8")
    client = spikelib.make_http_client(timeout=60.0)
    spike.fact("api_url", api)
    spike.fact("api_version_header", version)
    spike.fact("jwt_issuer_kind", "client id" if env("GITHUB_APP_CLIENT_ID") else "numeric app id")

    # ---- JWT and App ---------------------------------------------------------------------------------------------------
    spike.step("S6.2 mint the App JWT and read the App")
    app_jwt = mint_jwt(key_pem, issuer)
    spike.fact("jwt_length", len(app_jwt))
    spike.out("JWT claims: iat = now - 60 s, exp = now + 540 s, iss = <%s, %d chars>; algorithm RS256" % (
        "client id" if env("GITHUB_APP_CLIENT_ID") else "app id", len(issuer)))
    r = spike.http(client, "GET", api + "/app", expect=[200], headers=gh_headers(app_jwt, version), label="GET /app (JWT)",
                   max_body=2500)
    app = r.json()
    permissions = app.get("permissions", {})
    spike.fact("app_slug", app.get("slug"))
    spike.fact("app_permissions", permissions)
    spike.fact("app_events", app.get("events"))
    extra = {k: v for k, v in permissions.items() if k not in ("contents", "metadata")}
    spike.expect(not extra, "the App has no permission beyond contents and metadata (extra: %s)" % extra)
    spike.expect(permissions.get("contents") == "read", "contents permission is read")
    spike.expect(permissions.get("metadata") == "read", "metadata permission is read")
    spike.expect(not app.get("events"), "the App subscribes to no webhook events (webhook disabled)")
    r = spike.http(client, "GET", "%s/app/installations/%s" % (api, installation_id), expect=[200],
                   headers=gh_headers(app_jwt, version), label="GET /app/installations/<id> (JWT)", max_body=1800)
    inst = r.json()
    spike.fact("installation_repository_selection", inst.get("repository_selection"))
    spike.fact("installation_permissions", inst.get("permissions"))
    spike.fact("installation_suspended_at", inst.get("suspended_at"))
    spike.fact("installation_target_type", inst.get("target_type"))

    # ---- installation token scoped to one repository ------------------------------------------------------------------
    spike.step("S6.2 installation token scoped to the one repository (contents: read)")
    r = spike.http(client, "POST", "%s/app/installations/%s/access_tokens" % (api, installation_id), expect=[201],
                   headers=gh_headers(app_jwt, version), json_body={"repositories": [repo], "permissions": {"contents": "read"}},
                   label="POST access_tokens (repositories=[%s], permissions.contents=read)" % repo, max_body=1800)
    data = r.json()
    token = str(data["token"])
    expires = datetime.datetime.strptime(data["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    lifetime = (expires - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 60.0
    spike.fact("installation_token_length", len(token))
    spike.fact("installation_token_prefix", token[:4])
    spike.fact("installation_token_expires_at", data["expires_at"])
    spike.fact("installation_token_lifetime_minutes", "%.0f" % lifetime)
    spike.fact("installation_token_permissions", data.get("permissions"))
    spike.fact("installation_token_repository_selection", data.get("repository_selection"))
    spike.fact("installation_token_repositories", [x.get("full_name") for x in data.get("repositories", [])])
    spike.expect(data.get("permissions", {}).get("contents") == "read", "the token has contents:read")
    spike.expect(token.startswith("ghs_") or len(token) > 30, "the token looks like an installation token (treated as opaque)")

    # ---- repository listing (nightly discovery needs an unscoped token) ----------------------------------------------------
    spike.step("S6.3 list installation repositories (paginated) with an UNSCOPED token")
    r = spike.http(client, "POST", "%s/app/installations/%s/access_tokens" % (api, installation_id), expect=[201],
                   headers=gh_headers(app_jwt, version), json_body={"permissions": {"contents": "read"}},
                   label="POST access_tokens without `repositories` (all repositories of the installation)", max_body=600)
    wide_token = str(r.json()["token"])
    page, seen, total = 1, 0, None  # type: int, int, Optional[int]
    pages = 0
    started = time.monotonic()
    while True:
        rr = spike.http(client, "GET", api + "/installation/repositories", expect=[200],
                        headers=gh_headers(wide_token, version), params={"per_page": 100, "page": page},
                        label="GET /installation/repositories per_page=100 page=%d" % page, max_body=700,
                        show_body=(page == 1))
        info = rr.json()
        total = int(info.get("total_count", 0))
        seen += len(info.get("repositories", []))
        pages += 1
        if seen >= total or not info.get("repositories"):
            break
        page += 1
    spike.fact("installation_repositories_total", total)
    spike.fact("installation_repositories_pages_fetched", pages)
    spike.fact("listing_seconds", "%.1f" % (time.monotonic() - started))
    spike.http(client, "DELETE", api + "/installation/token", expect=[204], headers=gh_headers(wide_token, version),
               label="revoke the unscoped token (not needed any more)")
    r = spike.http(client, "GET", "%s/repos/%s/%s" % (api, owner, repo), expect=[200], headers=gh_headers(token, version),
                   label="GET /repos/{owner}/{repo} with the scoped token", max_body=600, show_body=False)
    default_branch = r.json()["default_branch"]
    spike.fact("default_branch", default_branch)
    spike.fact("repo_private", r.json().get("private"))
    r = spike.http(client, "GET", "%s/repos/%s/%s/branches/%s" % (api, owner, repo, default_branch), expect=[200],
                   headers=gh_headers(token, version), label="GET branches/<default> (head SHA for the poller)",
                   max_body=900)
    head_sha = r.json()["commit"]["sha"]
    spike.fact("head_sha", head_sha)
    r = spike.http(client, "GET", api + "/rate_limit", expect=[200], headers=gh_headers(token, version),
                   label="GET /rate_limit (installation token)", max_body=700)
    spike.fact("rate_limit_core", r.json().get("resources", {}).get("core"))
    other = spike.http(client, "GET", "%s/repos/%s/%s" % (api, owner, "definitely-not-in-the-token-scope-" + repo), expect=None,
                       headers=gh_headers(token, version), label="probe: a repository outside the token's scope", max_body=300,
                       show_body=False)
    spike.fact("status_for_repo_outside_scope", other.status_code)

    # ---- clone with a credential helper ----------------------------------------------------------------------------------------
    spike.step("S6.4 clone with a credential helper, full history, all refs; remove the remote; assert no token remains")
    dest = HERE / ".data" / "clone"
    if dest.exists():
        shutil.rmtree(str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    clone_url = "%s/%s/%s.git" % (git_url, owner, repo)
    argv = ["git", "-c", "credential.helper=", "-c", "credential.helper=" + HELPER, "clone", "--no-single-branch",
            clone_url, str(dest)]
    code, _, secs = run_cmd(spike, argv, env_extra={"GH_TOKEN": token, "GIT_TERMINAL_PROMPT": "0"}, timeout=1800,
                            show="git -c credential.helper= -c 'credential.helper=%s' clone --no-single-branch %s %s"
                                 "   (GH_TOKEN only in the git process environment)" % (HELPER, clone_url, dest))
    spike.fact("clone_seconds", "%.1f" % secs)
    shallow = git_out(["rev-parse", "--is-shallow-repository"], dest)
    spike.fact("clone_is_shallow", shallow)
    spike.expect(shallow == "false", "the clone is not shallow")
    spike.fact("clone_filter_config", git_out(["config", "--get-regexp", "remote.origin.*"], dest))
    commits_before = int(git_out(["rev-list", "--all", "--count"], dest))
    refs_remote = [x for x in git_out(["for-each-ref", "--format=%(refname)", "refs/remotes/origin"], dest).splitlines()
                   if x and not x.endswith("/HEAD")]
    refs_local_before = [x for x in git_out(["for-each-ref", "--format=%(refname)", "refs/heads"], dest).splitlines() if x]
    tags = [x for x in git_out(["for-each-ref", "--format=%(refname)", "refs/tags"], dest).splitlines() if x]
    spike.fact("commits_reachable_from_all_refs_before", commits_before)
    spike.fact("remote_tracking_branches_before", len(refs_remote))
    spike.fact("local_branches_before", len(refs_local_before))
    spike.fact("tags", len(tags))
    spike.fact("head_matches_api_sha", git_out(["rev-parse", "HEAD"], dest) == head_sha)

    # `git remote remove origin` deletes refs/remotes/origin/*; keep every branch as a local branch first.
    created = 0
    for ref in refs_remote:
        name = ref[len("refs/remotes/origin/"):]
        if "refs/heads/" + name in refs_local_before:
            continue
        sha = git_out(["rev-parse", ref], dest)
        git_out(["update-ref", "refs/heads/" + name, sha], dest)
        created += 1
    spike.fact("local_branches_created_from_remote_branches", created)
    git_out(["remote", "remove", "origin"], dest)
    remotes = git_out(["remote", "-v"], dest)
    commits_after = int(git_out(["rev-list", "--all", "--count"], dest))
    local_after = [x for x in git_out(["for-each-ref", "--format=%(refname)", "refs/heads"], dest).splitlines() if x]
    spike.fact("commits_reachable_from_all_refs_after", commits_after)
    spike.fact("local_branches_after", len(local_after))
    spike.fact("remote_remove_without_branch_copy_would_lose_commits",
               "see commits_before/after: equal here only because branches were copied first (%d remote-tracking refs existed)" % len(refs_remote))
    spike.expect(remotes == "", "git remote -v is empty after `git remote remove origin`")
    spike.expect(commits_after == commits_before, "no commits lost: %d before, %d after" % (commits_before, commits_after))

    config_text = (dest / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    spike.block(config_text, "ini")
    spike.expect("[remote" not in config_text, ".git/config has no [remote] section")
    spike.expect("x-access-token" not in config_text and "ghs_" not in config_text and token not in config_text,
                 ".git/config contains no token, user name or helper")
    # The exact token is searched everywhere (packfiles included); the short markers only outside objects/, where
    # compressed data could contain "ghs_" by chance.
    hits = scan_tree_for(dest / ".git", [token.encode()])
    hits += scan_tree_for(dest / ".git", [b"ghs_", b"x-access-token", b"GH_TOKEN"], skip_dirs=["objects"])
    spike.fact("files_under_dot_git_containing_token_markers", hits or "none")
    spike.expect(not hits, "grep -r ghs_ (and the token itself) over .git finds nothing")
    listing = git_out(["config", "--list", "--show-origin"], dest)
    spike.expect(token not in listing, "`git config --list --show-origin` does not show the token")
    spike.note("Gitleaks (`gitleaks git`) walks `git log --all`: branches must exist as refs/heads after the remote is gone. "
               "M3's sources/github.py must therefore copy remote-tracking branches into local branches before "
               "`git remote remove origin`, exactly as this script does.")

    # ---- revoke --------------------------------------------------------------------------------------------------------------------
    spike.step("Revoke the installation token and confirm it stops working")
    spike.http(client, "DELETE", api + "/installation/token", expect=[204], headers=gh_headers(token, version),
               label="DELETE /installation/token")
    r = spike.http(client, "GET", "%s/repos/%s/%s" % (api, owner, repo), expect=[401], headers=gh_headers(token, version),
                   label="the revoked token is refused", max_body=300, show_body=False)
    spike.fact("revoked_token_status", r.status_code)
    shutil.rmtree(str(dest), ignore_errors=True)
    return 0


def main() -> int:
    spike = Spike("s6", "S6 GitHub App", HERE)
    return spikelib.run_spike(spike, body)


if __name__ == "__main__":
    sys.exit(main())
