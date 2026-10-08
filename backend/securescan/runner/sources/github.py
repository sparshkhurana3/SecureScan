"""Clone a repository into a workspace: full history, all refs, no remote, no credentials left behind.

Authentication, chosen by the caller (``CloneAuth``):

* ``token``: HTTPS with a token (a GitHub App installation token, or a vendor token). The token is written
  to a 0600 file in a private directory and handed to git through a *credential helper*:
  ``!f() { echo username=<user>; echo "password=$(cat <file>)"; }; f``. The token is therefore never in
  the argument list, the environment or the URL, and not in ``.git/config`` either (the helper is passed
  with ``-c``, not stored).
* ``ssh``: a deploy key. The private key is written to a 0600 file; ``GIT_SSH_COMMAND`` names the key file
  and a ``known_hosts`` file (host key checking stays on). Only paths are in the environment.
* ``none``: public repository.

Layout after a clone (``Workspace.src`` is the working tree):

1. ``git clone --no-single-branch`` (full history, every branch and tag),
2. check out the requested commit (or ref, or the default branch head), detached,
3. copy every remote-tracking branch to a local branch (``git remote remove`` deletes
   ``refs/remotes/origin/*`` and Gitleaks walks ``git log --all``, so the branches must survive),
4. ``git remote remove origin``, then verify that ``.git/config`` holds no remote and no secret.

Errors are plain language and scrubbed of the secret and of known token shapes.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from securescan.logging import get_logger, scrub
from securescan.runner.sources.base import SourceError, SourceInfo, SourceRequest

log = get_logger(__name__)

CommitClaim = Callable[[str], Awaitable[str]]

_SAFE_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")
_SAFE_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,254}$")
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_FULL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")
_SCP_URL = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._/~-]+$")
_STDERR_KEEP = 1500
_BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")


@dataclass(frozen=True)
class CloneAuth:
    """How to authenticate. ``secret`` is a token or a PEM private key; it is never printed."""

    kind: str = "none"  # none | token | ssh
    secret: str = field(default="", repr=False)
    username: str = "x-access-token"
    known_hosts: str | None = None  # known_hosts content (ssh); falls back to ``known_hosts_file``
    known_hosts_file: str | None = None


@dataclass
class CloneResult:
    commit_sha: str
    branches: int
    tags: int


def validate_ref(ref: str) -> str:
    """A branch, tag or commit name that is safe to hand to git (no option injection, no tricks)."""
    text = ref.strip()
    if not _SAFE_REF.match(text) or ".." in text or text.endswith("/") or text.endswith(".lock"):
        raise SourceError(f"The reference {text[:60]!r} is not acceptable.", code="git.bad_ref")
    return text


def clone_url_for(locator: str, git_host: str = "github.com") -> str:
    """The clone URL for a target locator: ``owner/name``, an https URL, an ssh URL or ``user@host:path``."""
    text = locator.strip()
    if _FULL_NAME.match(text):
        host = git_host.replace("https://", "").replace("http://", "").strip("/")
        return f"https://{host}/{text}.git"
    return validate_clone_url(text)


def validate_clone_url(url: str) -> str:
    """Only https and ssh remotes; no credentials in the URL; no option-looking values."""
    text = url.strip()
    if not text or text.startswith("-") or any(ch.isspace() for ch in text) or "\x00" in text:
        raise SourceError("The repository address is not valid.", code="git.bad_url")
    if _SCP_URL.match(text):
        return text
    parts = urlsplit(text)
    if parts.scheme not in ("https", "ssh") or not parts.hostname:
        raise SourceError(
            "Only https:// and ssh:// repository addresses can be cloned.", code="git.bad_url"
        )
    if parts.password or (parts.username and parts.scheme == "https"):
        raise SourceError(
            "Do not put credentials in the repository address; use a stored credential.",
            code="git.url_credentials",
        )
    return text


def url_host(url: str) -> str:
    """The host name of a clone URL (for the egress allowlist)."""
    if _SCP_URL.match(url):
        return url.split("@", 1)[1].split(":", 1)[0].lower()
    return (urlsplit(url).hostname or "").lower()


def credential_helper(token_file: str, username: str = "x-access-token") -> str:
    """The git credential helper definition that reads the token from ``token_file`` on demand."""
    if not _SAFE_PATH.match(token_file):
        raise SourceError("internal: unsafe credential file path", code="git.internal")
    if not _SAFE_USER.match(username):
        raise SourceError("The stored credential has an unusable user name.", code="git.bad_user")
    return f'!f() {{ echo username={username}; echo "password=$(cat {token_file})"; }}; f'


def base_git_args(helper: str | None = None, proxy_url: str | None = None) -> list[str]:
    """Options common to every git call: only https and ssh transports, no prompts, no hooks."""
    args = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.ssh.allow=always",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "advice.detachedHead=false",
        "-c", "safe.directory=*",
    ]  # fmt: skip
    if helper is not None:
        args += ["-c", "credential.helper=", "-c", f"credential.helper={helper}"]
    else:
        args += ["-c", "credential.helper="]
    if proxy_url:
        args += ["-c", f"http.proxy={proxy_url}"]
    return args


def clone_argv(
    url: str, dest: str, *, helper: str | None = None, proxy_url: str | None = None
) -> list[str]:
    """``git clone`` of every branch and tag into ``dest`` (an existing empty directory)."""
    return [
        *base_git_args(helper, proxy_url),
        "clone", "--no-single-branch", "--quiet", "--", validate_clone_url(url), dest,
    ]  # fmt: skip


def ssh_command(key_file: str, known_hosts_file: str) -> str:
    for path in (key_file, known_hosts_file):
        if not _SAFE_PATH.match(path):
            raise SourceError("internal: unsafe ssh file path", code="git.internal")
    return (
        f"ssh -i {key_file} -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no "
        f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts_file} "
        "-o ConnectTimeout=30"
    )


def git_environment(home: str, ssh: str | None = None) -> dict[str, str]:
    """A minimal environment for git. It holds no secret: only paths and switches."""
    env = {key: os.environ[key] for key in _BASE_ENV_KEYS if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update(
        {
            "HOME": home,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ASKPASS": "/bin/false",
            "LC_ALL": "C",
        }
    )
    if ssh is not None:
        env["GIT_SSH_COMMAND"] = ssh
    return env


def scrub_text(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove the given secrets and any known token shape from ``text``."""
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")
    return scrub(text)


def explain_git_failure(stderr: str, what: str) -> str:
    """A plain-language reason for a failed git call (stderr is scrubbed by the caller)."""
    text = stderr.lower()
    if "could not resolve host" in text or "connection refused" in text or ("proxy" in text and "connect" in text):
        return f"{what}: git could not reach the repository host. Check the egress proxy and DNS."
    if "authentication failed" in text or "403" in text or "permission denied" in text or "could not read username" in text:
        return f"{what}: the repository refused the credential (permissions or expiry)."
    if "not found" in text or "404" in text or "does not appear to be a git repository" in text:
        return f"{what}: the repository was not found with this credential."
    if "host key verification failed" in text:
        return f"{what}: the SSH host key is not trusted (add it to the credential's known hosts)."
    if "timed out" in text or "timeout" in text:
        return f"{what}: git timed out."
    return f"{what}: git failed."


class GitRunner:
    """Runs git as a subprocess with a fixed environment, a timeout and scrubbed errors."""

    def __init__(self, env: dict[str, str], secrets: Sequence[str] = ()) -> None:
        self.env = env
        self.secrets = [s for s in secrets if s]

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_s: float = 600,
        what: str = "git",
        stdin: str | None = None,
    ) -> str:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd) if cwd else None,
            env=self.env,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout_s
            )
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise SourceError(f"{what}: git timed out.", code="git.timeout") from exc
        except asyncio.CancelledError:
            proc.kill()
            raise
        stdout = out.decode("utf-8", "replace")
        stderr = scrub_text(err.decode("utf-8", "replace"), self.secrets)[-_STDERR_KEEP:]
        if proc.returncode != 0:
            log.warning("git_failed", what=what, returncode=proc.returncode, stderr=stderr[-300:])
            raise SourceError(explain_git_failure(stderr, what), code="git.failed")
        return stdout


class SecretFiles:
    """Private 0600 files for a token or key, in a directory that is removed on exit."""

    def __init__(self, parent: Path) -> None:
        self._parent = parent
        self.root: Path | None = None

    def __enter__(self) -> SecretFiles:
        self.root = Path(tempfile.mkdtemp(prefix=".git-auth-", dir=str(self._parent)))
        os.chmod(self.root, 0o700)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.root is not None:
            shutil.rmtree(self.root, ignore_errors=True)

    def write(self, name: str, content: str) -> str:
        assert self.root is not None  # noqa: S101 - used inside the with block
        path = self.root / name
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content if content.endswith("\n") else content + "\n")
        return str(path)


async def clone_repository(
    url: str,
    dest: Path,
    *,
    auth: CloneAuth,
    auth_dir: Path,
    ref: str | None = None,
    commit: str | None = None,
    proxy_url: str | None = None,
    timeout_s: float = 1800,
    claim_commit: CommitClaim | None = None,
    known_hosts_default: str | None = None,
) -> CloneResult:
    """Clone ``url`` into the existing empty directory ``dest``. See the module docstring."""
    url = validate_clone_url(url)
    safe_ref = validate_ref(ref) if ref else None
    if commit is not None and not _SHA.match(commit):
        raise SourceError("The commit id is not valid.", code="git.bad_ref")
    secrets = [auth.secret] if auth.secret else []
    with SecretFiles(auth_dir) as files:
        helper: str | None = None
        ssh: str | None = None
        if auth.kind == "token":
            helper = credential_helper(files.write("token", auth.secret), auth.username)
        elif auth.kind == "ssh":
            key_file = files.write("key", auth.secret)
            hosts_text = auth.known_hosts
            hosts_file = auth.known_hosts_file or known_hosts_default
            if hosts_text:
                hosts_path = files.write("known_hosts", hosts_text)
            elif hosts_file and Path(hosts_file).is_file():
                hosts_path = hosts_file
            else:
                raise SourceError(
                    "SSH host keys are not configured for this repository host "
                    "(set SECURESCAN_SSH_KNOWN_HOSTS_FILE or add known hosts to the credential).",
                    code="git.known_hosts_missing",
                )
            ssh = ssh_command(key_file, hosts_path)
        elif auth.kind != "none":
            raise SourceError("internal: unknown authentication kind", code="git.internal")
        runner = GitRunner(git_environment(str(files.root), ssh), secrets)
        git = base_git_args(None, None)

        await runner.run(
            clone_argv(url, str(dest), helper=helper, proxy_url=proxy_url),
            timeout_s=timeout_s,
            what="Cloning the repository",
        )
        # From here on nothing needs the network or the credential.
        sha = await _resolve_target(runner, dest, safe_ref, commit)
        if claim_commit is not None:
            canonical = await claim_commit(sha)
            if canonical != sha:
                sha = await _resolve_sha(runner, dest, canonical)
        head = (await runner.run([*git, "rev-parse", "HEAD"], cwd=dest, what="Reading the commit")).strip()
        if head != sha:
            await runner.run(
                [*git, "checkout", "--detach", "--quiet", sha], cwd=dest, what="Checking out the commit"
            )
        branches = await _keep_branches(runner, dest)
        await runner.run([*git, "remote", "remove", "origin"], cwd=dest, what="Removing the remote")
        tags = len(
            [
                line
                for line in (
                    await runner.run([*git, "for-each-ref", "--format=%(refname)", "refs/tags"], cwd=dest)
                ).splitlines()
                if line
            ]
        )
        await asyncio.to_thread(verify_clean_repository, dest, secrets)
        return CloneResult(commit_sha=sha, branches=branches, tags=tags)


async def _resolve_sha(runner: GitRunner, repo: Path, name: str) -> str:
    try:
        out = await runner.run(
            [*base_git_args(), "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}"],
            cwd=repo,
            what="Finding the commit",
        )
    except SourceError as exc:
        raise SourceError(
            "The requested commit or reference was not found in the repository.",
            code="git.ref_not_found",
        ) from exc
    sha = out.strip()
    if not sha:
        raise SourceError("The requested commit or reference was not found.", code="git.ref_not_found")
    return sha


async def _resolve_target(
    runner: GitRunner, repo: Path, ref: str | None, commit: str | None
) -> str:
    if commit:
        return await _resolve_sha(runner, repo, commit)
    if ref:
        candidates = [f"refs/remotes/origin/{ref}", f"refs/tags/{ref}"]
        if _SHA.match(ref):
            candidates.append(ref)
        for candidate in candidates:
            try:
                return await _resolve_sha(runner, repo, candidate)
            except SourceError:
                continue
        raise SourceError(
            f"The branch, tag or commit {ref!r} was not found in the repository.",
            code="git.ref_not_found",
        )
    return await _resolve_sha(runner, repo, "HEAD")


async def _keep_branches(runner: GitRunner, repo: Path) -> int:
    """Copy ``refs/remotes/origin/<b>`` to ``refs/heads/<b>`` for every branch lacking one."""
    git = base_git_args()
    listing = await runner.run(
        [*git, "for-each-ref", "--format=%(objectname) %(refname)", "refs/remotes/origin", "refs/heads"],
        cwd=repo,
        what="Listing branches",
    )
    remote: dict[str, str] = {}
    local: set[str] = set()
    for line in listing.splitlines():
        sha, _, name = line.partition(" ")
        if name.startswith("refs/remotes/origin/"):
            short = name[len("refs/remotes/origin/") :]
            if short != "HEAD":
                remote[short] = sha
        elif name.startswith("refs/heads/"):
            local.add(name[len("refs/heads/") :])
    commands = [f"create refs/heads/{name} {sha}" for name, sha in sorted(remote.items()) if name not in local]
    if commands:
        await runner.run(
            [*git, "update-ref", "--stdin"],
            cwd=repo,
            what="Keeping the branches",
            stdin="\n".join(commands) + "\n",
        )
    return len(local | set(remote))


def verify_clean_repository(repo: Path, secrets: Sequence[str] = ()) -> None:
    """``.git/config`` must have no remote and no credential. Raises ``SourceError`` otherwise."""
    config = repo / ".git" / "config"
    text = config.read_text(encoding="utf-8", errors="replace") if config.is_file() else ""
    lowered = text.lower()
    if "[remote" in lowered or "x-access-token" in lowered or "credential" in lowered:
        raise SourceError("internal: the clone still holds a remote or credential", code="git.internal")
    for secret in secrets:
        if secret and secret in text:
            raise SourceError("internal: the clone still holds a credential", code="git.internal")


# --------------------------------------------------------------------------- the source handler
async def acquire_repository(request: SourceRequest) -> SourceInfo:
    """Source handler for ``github_repo`` and ``vendor_repo`` targets."""
    from securescan.db.models.credentials import Credential
    from securescan.db.models.enums import CredentialKind, TargetKind
    from securescan.domain.credentials import reveal_secret
    from securescan.runner.egress import EgressError, egress_lease
    from securescan.util import utcnow

    target = request.target
    settings = request.settings
    scan = request.scan
    commit = scan.commit_sha or None
    ref = None if commit else (scan.source_ref or None)

    auth = CloneAuth()
    git_host = "github.com"
    hosts: set[str] = set()
    use_app = False

    if target.credential_id is not None:
        credential = await request.session.get(Credential, target.credential_id)
        if credential is None or credential.revoked_at is not None:
            raise SourceError("The credential of this target was revoked or removed.", code="git.credential_missing")
        # Defence in depth (the API refuses these too): only a vendor repository uses a stored credential, and only a
        # deploy key or a vendor token. Any other secret would be sent to the host the locator names.
        if target.kind != TargetKind.VENDOR_REPO or credential.kind not in (
            CredentialKind.DEPLOY_KEY,
            CredentialKind.VENDOR_TOKEN,
        ):
            raise SourceError(
                "This target carries a credential that a repository clone does not use.", code="git.credential_kind"
            )
        secret = reveal_secret(credential)
        credential.last_used_at = utcnow()
        extra = credential.extra or {}
        if credential.kind == CredentialKind.DEPLOY_KEY:
            auth = CloneAuth(kind="ssh", secret=secret, known_hosts=str(extra.get("known_hosts") or "") or None)
        else:
            auth = CloneAuth(kind="token", secret=secret, username=str(extra.get("username") or "x-access-token"))
    elif target.kind == TargetKind.GITHUB_REPO:
        use_app = True

    if use_app:
        from securescan.integrations.github.app import GitHubError, explain_error
        from securescan.integrations.github.connection import (
            get_connection,
            github_client,
            github_hosts,
        )

        connection = await get_connection(request.session, enabled_only=True)
        if connection is None:
            raise SourceError(
                "GitHub is not connected. An Admin can connect the GitHub App in Settings.",
                code="git.github_not_connected",
            )
        git_host = connection.git_host
        hosts = set(github_hosts(connection))
        url = clone_url_for(target.locator, git_host)
        await request.log("requesting a short-lived read token from GitHub")
        try:
            async with github_client(request.session, connection) as client:
                token = await client.mint_clone_token(
                    target.locator, request.application.github_repo_id
                )
        except GitHubError as exc:
            raise SourceError(explain_error(exc), code="git.github_token") from exc
        auth = CloneAuth(kind="token", secret=token.token)
    else:
        url = clone_url_for(target.locator, git_host)
        if auth.kind != "ssh":
            host = url_host(url)
            if host:
                hosts.add(host)

    # No transaction (and no row lock on the credential) is held while git runs.
    await request.session.commit()
    await request.log(f"cloning {_loggable(url)} (full history)")
    try:
        if auth.kind == "ssh" or not hosts:
            proxy_url = ""
            result = await _clone(request, url, auth, ref, commit, proxy_url)
        else:
            async with egress_lease(hosts) as proxy_url:
                result = await _clone(request, url, auth, ref, commit, proxy_url or "")
    except EgressError as exc:
        raise SourceError(str(exc), code="git.egress") from exc
    await request.log(
        f"cloned: commit {result.commit_sha[:12]}, {result.branches} branches, {result.tags} tags; remote removed"
    )
    return SourceInfo(
        kind="git",
        is_git=True,
        commit_sha=result.commit_sha,
        ref=ref or scan.source_ref,
        description=f"repository {target.locator} at {result.commit_sha[:12]}",
        details={"branches": result.branches, "tags": result.tags},
    )


def _loggable(url: str) -> str:
    return url if not _SCP_URL.match(url) else url.split("@", 1)[1]


async def _clone(
    request: SourceRequest,
    url: str,
    auth: CloneAuth,
    ref: str | None,
    commit: str | None,
    proxy_url: str,
) -> CloneResult:
    return await clone_repository(
        url,
        request.workspace.src,
        auth=auth,
        auth_dir=request.workspace.root,
        ref=ref,
        commit=commit,
        proxy_url=proxy_url or None,
        timeout_s=float(request.settings.git_clone_timeout_seconds),
        claim_commit=request.claim_commit,
        known_hosts_default=request.settings.ssh_known_hosts_file or None,
    )
