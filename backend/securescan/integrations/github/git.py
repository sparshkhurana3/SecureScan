"""``git ls-remote`` against GitHub for the connection test (no checkout, nothing is written).

The installation token is handed to git through a throw-away ``GIT_ASKPASS`` script that prints it from
the process environment. It is never in a URL, a command line, a file or a log line. The script and the
home directory live in a private temporary directory that is removed afterwards.
"""

from __future__ import annotations

import asyncio
import os
import stat
import tempfile
from pathlib import Path

from securescan.logging import scrub

ASKPASS_SCRIPT = """#!/bin/sh
case "$1" in
  Username*) printf '%s\\n' "x-access-token" ;;
  *) printf '%s\\n' "$SECURESCAN_GIT_TOKEN" ;;
esac
"""


class GitError(Exception):
    """``git`` failed; the message is plain language with no secrets."""


def repository_url(git_host: str, full_name: str) -> str:
    """The HTTPS clone URL (no credentials in it)."""
    return "https://%s/%s.git" % (git_host.strip("/"), full_name.strip("/"))


def _explain(stderr: str, returncode: int) -> str:
    text = scrub(stderr).strip().lower()
    if "could not resolve host" in text or ("proxy" in text and "connect" in text):
        return "git could not reach GitHub. Check the egress proxy and DNS."
    if "authentication failed" in text or "invalid username or password" in text or "403" in text:
        return (
            "git was refused. The token may lack Contents: read, or the organisation's IP allow list "
            "may not include this machine's egress address."
        )
    if "not found" in text or "404" in text:
        return "git could not find the repository with this token."
    if "timed out" in text or "timeout" in text:
        return "git timed out talking to GitHub."
    return "git ls-remote failed (exit code %d)." % returncode


async def git_ls_remote(
    url: str,
    ref: str = "HEAD",
    *,
    token: str | None = None,
    proxy_url: str | None = None,
    timeout: float = 60.0,
) -> str:
    """The commit SHA ``ref`` points to on the remote. Raises ``GitError``."""
    with tempfile.TemporaryDirectory(prefix="securescan-git-") as tmp:
        directory = Path(tmp)
        os.chmod(directory, 0o700)
        askpass = directory / "askpass.sh"
        askpass.write_text(ASKPASS_SCRIPT, encoding="ascii")
        os.chmod(askpass, stat.S_IRWXU)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(directory),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "LC_ALL": "C",
        }
        if token:
            env["GIT_ASKPASS"] = str(askpass)
            env["SECURESCAN_GIT_TOKEN"] = token
        if proxy_url:
            env["HTTPS_PROXY"] = proxy_url
            env["https_proxy"] = proxy_url
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                "ls-remote",
                "--exit-code",
                url,
                ref,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise GitError("git is not installed in the worker image.") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise GitError("git timed out talking to GitHub.") from exc
    if process.returncode != 0:
        raise GitError(_explain(stderr.decode("utf-8", "replace"), process.returncode or 1))
    first = stdout.decode("utf-8", "replace").split("\n", 1)[0]
    sha = first.split("\t", 1)[0].strip()
    if len(sha) < 40:
        raise GitError("git returned no commit for %s." % ref)
    return sha
