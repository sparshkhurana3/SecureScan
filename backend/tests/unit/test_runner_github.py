"""Repository clone: command construction (no secret in arguments, environment or URL), ref handling."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import types
from pathlib import Path
from typing import Any

import pytest

from securescan.runner.sources import github
from securescan.runner.sources.base import SourceError
from securescan.runner.sources.github import (
    CloneAuth,
    GitRunner,
    SecretFiles,
    _keep_branches,
    _resolve_target,
    base_git_args,
    clone_argv,
    clone_repository,
    clone_url_for,
    credential_helper,
    explain_git_failure,
    git_environment,
    scrub_text,
    ssh_command,
    url_host,
    validate_clone_url,
    validate_ref,
    verify_clean_repository,
)

TOKEN = "ghs_" + "A1b2C3d4" * 5
SHA = "a" * 40
OTHER = "b" * 40
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


# --------------------------------------------------------------------------- addresses and refs
def test_clone_url_for_locators() -> None:
    assert clone_url_for("owner/repo") == "https://github.com/owner/repo.git"
    assert clone_url_for("owner/repo", "https://ghe.example.com/") == "https://ghe.example.com/owner/repo.git"
    assert clone_url_for("owner/re.po-1", "ghe.example.com") == "https://ghe.example.com/owner/re.po-1.git"
    assert clone_url_for("https://vendor.example/x/y.git") == "https://vendor.example/x/y.git"
    assert clone_url_for("git@vendor.example:team/app.git") == "git@vendor.example:team/app.git"
    assert clone_url_for("ssh://git@vendor.example/team/app.git") == "ssh://git@vendor.example/team/app.git"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ext::sh -c id",
        "git://example.com/x.git",
        "http://example.com/x.git",
        "--upload-pack=touch /tmp/x",
        "-oProxyCommand=id",
        "https://user:pw@example.com/x.git",
        "https://token@example.com/x.git",
        "ssh://user:pw@example.com/x.git",
        "https://example.com/a b.git",
        "",
        "/local/path",
        "../relative",
    ],
)
def test_unsafe_clone_urls_are_rejected(url: str) -> None:
    with pytest.raises(SourceError):
        validate_clone_url(url)


def test_url_host() -> None:
    assert url_host("https://GitHub.com/o/r.git") == "github.com"
    assert url_host("git@vendor.example:t/a.git") == "vendor.example"
    assert url_host("ssh://git@vendor.example:2222/t/a.git") == "vendor.example"


@pytest.mark.parametrize("ref", ["main", "release/1.2", "v1.0.0", "feature_x", "a" * 40, "user@2"])
def test_good_refs(ref: str) -> None:
    assert validate_ref(ref) == ref


@pytest.mark.parametrize("ref", ["", "-x", "--upload-pack=x", "a..b", "a b", "x;y", "a/", "x.lock", "$(id)", "a\nb", "~1"])
def test_bad_refs(ref: str) -> None:
    with pytest.raises(SourceError) as caught:
        validate_ref(ref)
    assert caught.value.code == "git.bad_ref"


# --------------------------------------------------------------------------- commands, environment
def test_credential_helper_reads_the_token_from_a_file() -> None:
    helper = credential_helper("/work/ws/.git-auth-ab/token")
    assert helper == '!f() { echo username=x-access-token; echo "password=$(cat /work/ws/.git-auth-ab/token)"; }; f'
    assert TOKEN not in helper
    with pytest.raises(SourceError):
        credential_helper("/work/with space/token")
    with pytest.raises(SourceError):
        credential_helper("/work/token; rm -rf /")
    with pytest.raises(SourceError):
        credential_helper("/work/token", "bad user;")


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_credential_helper_prints_what_git_expects(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("sekret-value\n", encoding="utf-8")
    helper = credential_helper(str(token_file), "oauth2")
    out = subprocess.run(["sh", "-c", helper[1:]], capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == ["username=oauth2", "password=sekret-value"]


def test_clone_command_has_no_token_and_blocks_other_transports() -> None:
    helper = credential_helper("/work/ws/.git-auth-ab/token")
    argv = clone_argv("https://github.com/o/r.git", "/work/ws/src", helper=helper, proxy_url="http://proxy:3128")
    assert argv[0] == "git"
    assert TOKEN not in " ".join(argv)
    assert "https://github.com/o/r.git" in argv and argv[-1] == "/work/ws/src"
    assert argv[argv.index("clone") + 1 :][:3] == ["--no-single-branch", "--quiet", "--"]  # url comes after "--"
    joined = " ".join(argv)
    assert "protocol.allow=never" in joined and "protocol.https.allow=always" in joined
    assert "core.hooksPath=/dev/null" in joined
    assert "http.proxy=http://proxy:3128" in joined
    assert argv.count("credential.helper=") == 1 and f"credential.helper={helper}" in argv
    assert "--depth" not in argv and "--single-branch" not in argv  # full history, all refs


def test_clone_without_credential_clears_helpers_and_without_proxy() -> None:
    argv = clone_argv("https://github.com/o/r.git", "/d")
    assert "credential.helper=" in argv
    assert not any(a.startswith("http.proxy") for a in argv)
    assert "-c" in base_git_args()


def test_git_environment_holds_no_secret_and_no_inherited_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_DATABASE_PASSWORD", "db-pass-7f3a91")
    monkeypatch.setenv("SECURESCAN_MASTER_KEY", "master-key-9c1e44")
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    env = git_environment("/work/ws/.git-auth-ab")
    assert env["HOME"] == "/work/ws/.git-auth-ab"
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert "GIT_SSH_COMMAND" not in env
    flat = " ".join(f"{k}={v}" for k, v in env.items())
    assert "db-pass-7f3a91" not in flat and "master-key-9c1e44" not in flat and TOKEN not in flat


def test_ssh_command_names_the_key_file_and_keeps_host_key_checking() -> None:
    command = ssh_command("/work/ws/.git-auth-ab/key", "/work/ws/.git-auth-ab/known_hosts")
    assert "-i /work/ws/.git-auth-ab/key" in command
    assert "StrictHostKeyChecking=yes" in command and "IdentitiesOnly=yes" in command and "BatchMode=yes" in command
    assert "UserKnownHostsFile=/work/ws/.git-auth-ab/known_hosts" in command
    with pytest.raises(SourceError):
        ssh_command("/work/with space/key", "/work/known_hosts")


def test_secret_files_are_private_and_removed(tmp_path: Path) -> None:
    with SecretFiles(tmp_path) as files:
        path = Path(files.write("token", "value"))
        assert path.read_text() == "value\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        with pytest.raises(FileExistsError):
            files.write("token", "again")
    assert not path.exists() and list(tmp_path.glob(".git-auth-*")) == []


def test_scrubbing_removes_secrets_and_token_shapes() -> None:
    text = f"fatal: unable to access 'https://x-access-token:{TOKEN}@github.com/o/r.git' with {TOKEN} and hunter2hunter2"
    clean = scrub_text(text, ["hunter2hunter2", TOKEN, ""])
    assert TOKEN not in clean and "hunter2hunter2" not in clean and "***" in clean
    assert "ghs_" not in scrub_text("ghp_" + "x" * 30 + " " + "ghs_" + "y" * 30)


@pytest.mark.parametrize(
    ("stderr", "needle"),
    [
        ("fatal: unable to access: Could not resolve host: github.com", "reach"),
        ("remote: Invalid username or password.\nfatal: Authentication failed", "refused the credential"),
        ("fatal: repository 'https://github.com/o/r.git/' not found", "not found"),
        ("Host key verification failed.", "host key"),
        ("operation timed out", "timed out"),
        ("fatal: something odd", "git failed"),
    ],
)
def test_failures_are_explained_in_plain_language(stderr: str, needle: str) -> None:
    assert needle in explain_git_failure(stderr, "Cloning the repository").lower()


def test_verify_clean_repository(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    config = tmp_path / ".git" / "config"
    config.write_text("[core]\n\tbare = false\n", encoding="utf-8")
    verify_clean_repository(tmp_path, [TOKEN])
    config.write_text('[core]\n[remote "origin"]\n\turl = https://github.com/o/r.git\n', encoding="utf-8")
    with pytest.raises(SourceError):
        verify_clean_repository(tmp_path)
    config.write_text(f"[core]\n# {TOKEN}\n", encoding="utf-8")
    with pytest.raises(SourceError):
        verify_clean_repository(tmp_path, [TOKEN])
    config.write_text("[credential]\n\thelper = x\n", encoding="utf-8")
    with pytest.raises(SourceError):
        verify_clean_repository(tmp_path)


# --------------------------------------------------------------------------- clone sequence (git faked)
class Recorder:
    def __init__(self, auth_dir: Path) -> None:
        self.auth_dir = auth_dir
        self.calls: list[types.SimpleNamespace] = []

    async def run(
        self,
        runner: GitRunner,
        argv: Any,
        *,
        cwd: Path | None = None,
        timeout_s: float = 600,
        what: str = "git",
        stdin: str | None = None,
    ) -> str:
        files = sorted(self.auth_dir.glob(".git-auth-*/*"))
        modes = [stat.S_IMODE(f.stat().st_mode) for f in files]
        self.calls.append(
            types.SimpleNamespace(
                argv=list(argv), env=dict(runner.env), stdin=stdin, files=[f.name for f in files], modes=modes, cwd=cwd
            )
        )
        joined = " ".join(argv)
        if " clone " in joined:
            return ""
        if "%(objectname) %(refname)" in joined:
            return f"{SHA} refs/remotes/origin/main\n{SHA} refs/remotes/origin/dev\n{SHA} refs/heads/main\n"
        if "for-each-ref" in joined:
            return "refs/tags/v1\nrefs/tags/v2\n"
        if "--verify" in argv:
            return SHA + "\n"
        if "rev-parse" in argv and "HEAD" in argv:
            return OTHER + "\n"
        return ""


async def test_token_clone_never_exposes_the_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder(tmp_path)

    async def fake_run(self: GitRunner, argv: Any, **kwargs: Any) -> str:
        return await recorder.run(self, argv, **kwargs)

    monkeypatch.setattr(github.GitRunner, "run", fake_run)
    claimed: list[str] = []

    async def claim(sha: str) -> str:
        claimed.append(sha)
        return sha

    dest = tmp_path / "src"
    result = await clone_repository(
        "https://github.com/o/r.git",
        dest,
        auth=CloneAuth(kind="token", secret=TOKEN),
        auth_dir=tmp_path,
        ref="main",
        proxy_url="http://proxy:3128",
        claim_commit=claim,
    )
    assert (result.commit_sha, result.branches, result.tags) == (SHA, 2, 2)
    assert claimed == [SHA]
    first = recorder.calls[0]
    assert "clone" in first.argv and first.files == ["token"] and first.modes == [0o600]
    for call in recorder.calls:
        assert TOKEN not in " ".join(call.argv)
        assert TOKEN not in " ".join(f"{k}={v}" for k, v in call.env.items())
        assert TOKEN not in (call.stdin or "")
    assert any("checkout" in c.argv and "--detach" in c.argv and SHA in c.argv for c in recorder.calls)
    assert any(c.stdin == f"create refs/heads/dev {SHA}\n" for c in recorder.calls)
    removal = [i for i, c in enumerate(recorder.calls) if c.argv[-3:] == ["remote", "remove", "origin"]]
    assert removal and removal[0] == max(i for i, c in enumerate(recorder.calls) if "update-ref" in c.argv) + 1
    assert list(tmp_path.glob(".git-auth-*")) == []  # the credential files are gone


async def test_ssh_clone_uses_a_key_file_and_known_hosts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder(tmp_path)

    async def fake_run(self: GitRunner, argv: Any, **kwargs: Any) -> str:
        return await recorder.run(self, argv, **kwargs)

    monkeypatch.setattr(github.GitRunner, "run", fake_run)
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nQUJDREVGRw==\n-----END OPENSSH PRIVATE KEY-----"
    await clone_repository(
        "ssh://git@vendor.example/team/app.git",
        tmp_path / "src",
        auth=CloneAuth(kind="ssh", secret=key, known_hosts="vendor.example ssh-ed25519 AAAAC3Nza"),
        auth_dir=tmp_path,
    )
    first = recorder.calls[0]
    assert sorted(first.files) == ["key", "known_hosts"] and first.modes == [0o600, 0o600]
    ssh = first.env["GIT_SSH_COMMAND"]
    assert "StrictHostKeyChecking=yes" in ssh and "QUJDREVGRw" not in ssh
    for call in recorder.calls:
        assert "QUJDREVGRw" not in " ".join(call.argv) + " ".join(call.env.values())
    assert list(tmp_path.glob(".git-auth-*")) == []


async def test_ssh_without_known_hosts_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SourceError) as caught:
        await clone_repository(
            "ssh://git@vendor.example/team/app.git",
            tmp_path / "src",
            auth=CloneAuth(kind="ssh", secret="key"),
            auth_dir=tmp_path,
        )
    assert caught.value.code == "git.known_hosts_missing"
    assert list(tmp_path.glob(".git-auth-*")) == []


async def test_bad_inputs_are_refused_before_git_runs(tmp_path: Path) -> None:
    with pytest.raises(SourceError):
        await clone_repository("file:///etc", tmp_path / "s", auth=CloneAuth(), auth_dir=tmp_path)
    with pytest.raises(SourceError):
        await clone_repository("https://github.com/o/r.git", tmp_path / "s", auth=CloneAuth(), auth_dir=tmp_path, ref="--x")
    with pytest.raises(SourceError):
        await clone_repository("https://github.com/o/r.git", tmp_path / "s", auth=CloneAuth(), auth_dir=tmp_path, commit="xyz")
    with pytest.raises(SourceError):
        await clone_repository("https://github.com/o/r.git", tmp_path / "s", auth=CloneAuth(kind="weird"), auth_dir=tmp_path)


# --------------------------------------------------------------------------- real git
def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_origin(tmp_path: Path) -> Path:
    origin = tmp_path / "origin"
    origin.mkdir()
    git(origin, "init", "-q")
    (origin / "a.txt").write_text("a", encoding="utf-8")
    git(origin, "add", ".")
    git(origin, "commit", "-q", "-m", "one")
    git(origin, "checkout", "-q", "-b", "feature/x")
    (origin / "b.txt").write_text("b", encoding="utf-8")
    git(origin, "add", ".")
    git(origin, "commit", "-q", "-m", "on feature")
    git(origin, "tag", "v1")
    git(origin, "checkout", "-q", "main")
    (origin / "c.txt").write_text("c", encoding="utf-8")
    git(origin, "add", ".")
    git(origin, "commit", "-q", "-m", "on main")
    return origin


@needs_git
async def test_branches_survive_removing_the_remote(tmp_path: Path) -> None:
    origin = make_origin(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "--no-single-branch", "-q", str(origin), str(clone)], check=True, capture_output=True)
    before = int(git(clone, "rev-list", "--all", "--count"))
    runner = GitRunner(git_environment(str(tmp_path)))
    kept = await _keep_branches(runner, clone)
    await runner.run([*base_git_args(), "remote", "remove", "origin"], cwd=clone)
    heads = git(clone, "for-each-ref", "--format=%(refname)", "refs/heads").splitlines()
    assert sorted(heads) == ["refs/heads/feature/x", "refs/heads/main"] and kept == 2
    assert int(git(clone, "rev-list", "--all", "--count")) == before == 3
    assert git(clone, "remote") == ""
    verify_clean_repository(clone)


@needs_git
async def test_refs_resolve_while_the_remote_exists(tmp_path: Path) -> None:
    origin = make_origin(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "--no-single-branch", "-q", str(origin), str(clone)], check=True, capture_output=True)
    runner = GitRunner(git_environment(str(tmp_path)))
    feature = git(clone, "rev-parse", "refs/remotes/origin/feature/x")
    assert await _resolve_target(runner, clone, "feature/x", None) == feature
    assert await _resolve_target(runner, clone, "v1", None) == feature  # a tag
    assert await _resolve_target(runner, clone, None, feature[:10]) == feature  # an abbreviated commit
    assert await _resolve_target(runner, clone, None, None) == git(clone, "rev-parse", "HEAD")
    with pytest.raises(SourceError) as caught:
        await _resolve_target(runner, clone, "nope", None)
    assert caught.value.code == "git.ref_not_found"
    with pytest.raises(SourceError) as missing:
        await _resolve_target(runner, clone, None, "f" * 40)
    assert missing.value.code == "git.ref_not_found"


@pytest.mark.skipif(shutil.which("sleep") is None, reason="needs sleep")
async def test_git_runner_times_out_and_scrubs() -> None:
    runner = GitRunner({"PATH": os.environ.get("PATH", "")}, secrets=["topsecretvalue"])
    with pytest.raises(SourceError) as caught:
        await runner.run(["sleep", "5"], timeout_s=0.2)
    assert caught.value.code == "git.timeout"
    with pytest.raises(SourceError) as failed:
        await runner.run(["sh", "-c", "echo topsecretvalue >&2; exit 3"], what="Testing")
    assert "topsecretvalue" not in str(failed.value) and failed.value.code == "git.failed"
