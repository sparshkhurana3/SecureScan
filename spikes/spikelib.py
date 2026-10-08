"""Shared helpers for the M1 spike scripts. Throwaway code: never imported by production code.

Every spike script does::

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import spikelib

and then builds a ``Spike`` object. The helper prints every HTTP request and response in a
fenced block that can be pasted into docs/spikes/<name>.md, redacts secrets (it shows the length
instead of the value), keeps a transcript under spikes/<spike>/.data/, collects "facts" for the
"What to record" tables, and turns the first unexpected result into a non-zero exit code.

Only the standard library and httpx are used. The syntax is kept compatible with Python 3.9 so
that ``python -m py_compile`` can check the files on a machine without the project toolchain.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import string
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

SPIKES_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPIKES_DIR.parent
DEFAULT_REPORTS_DIR = REPO_ROOT / "backend" / "tests" / "fixtures" / "reports"
SAMPLE_APPS_DIR = REPO_ROOT / "backend" / "tests" / "fixtures" / "sample-apps"

# JSON keys (case-insensitive substrings) whose values are never printed.
_SECRET_KEY_RE = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|private|credential)", re.I)
# Free-text patterns that look like credentials, replaced wherever they appear.
_SECRET_TEXT_RES = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\b(Bearer|Token|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),
]
# Keys that look secret by name but are harmless metadata the findings files need.
_SECRET_KEY_ALLOW = {
    "token_type",
    "tokentype",
    "token_endpoint",
    "expires_in",
    "token_expiry",
    "token_last_reset",
    "password_last_reset",
    "force_password_reset",
    "token_length",
}


class SpikeFailure(Exception):
    """An unexpected result. The spike stops and exits non-zero."""


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_value(value: Any) -> str:
    text = str(value)
    return "<redacted len=%d>" % len(text)


def redact_json(data: Any) -> Any:
    """Return a copy of ``data`` with secret-looking values replaced by their length."""
    if isinstance(data, dict):
        out = {}  # type: Dict[str, Any]
        for key, value in data.items():
            lowered = str(key).lower()
            if (
                _SECRET_KEY_RE.search(lowered)
                and lowered not in _SECRET_KEY_ALLOW
                and isinstance(value, (str, int))
                and not isinstance(value, bool)
            ):
                out[key] = redact_value(value)
            else:
                out[key] = redact_json(value)
        return out
    if isinstance(data, list):
        return [redact_json(item) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def redact_text(text: str) -> str:
    for pattern in _SECRET_TEXT_RES:
        text = pattern.sub(lambda m: "<redacted len=%d>" % len(m.group(0)), text)
    return text


def random_password(length: int = 24) -> str:
    """A password that satisfies typical complexity rules (upper, lower, digit, symbol)."""
    symbols = "!@#%^*-_=+"
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length - 2))
        pw += secrets.choice(symbols) + secrets.choice(symbols)
        pw = "".join(secrets.SystemRandom().sample(pw, len(pw)))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in symbols for c in pw)
        ):
            return pw


def env(name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """Read an environment variable; a ``NAME_FILE`` variable wins and is read from disk."""
    file_var = os.environ.get(name + "_FILE")
    if file_var:
        return Path(file_var).read_text(encoding="utf-8").strip()
    value = os.environ.get(name)
    if value is None or value == "":
        if required:
            raise SpikeFailure("missing required environment variable %s (see the header of the script)" % name)
        return default
    return value


class SecretStore:
    """A tiny JSON file (mode 0600) under spikes/<spike>/.data/ for values reused across runs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data = {}  # type: Dict[str, Any]
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                self._data = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        try:
            os.chmod(str(self.path), 0o600)
        except OSError:
            pass


class Spike:
    """Transcript, HTTP helper and fact collector for one spike run."""

    def __init__(self, name: str, title: str, spike_dir: Path) -> None:
        self.name = name
        self.title = title
        self.dir = spike_dir
        self.data_dir = spike_dir / ".data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.transcript_path = self.data_dir / ("transcript-%s.md" % stamp)
        self._fh = open(str(self.transcript_path), "w", encoding="utf-8")
        self.facts = []  # type: List[Tuple[str, str]]
        self.warnings = []  # type: List[str]
        self._step_no = 0
        self.out("# %s" % title)
        self.out("")
        self.out("Run started %s. Secrets are redacted (the length is shown instead of the value)." % now_utc())
        self.out("")

    # ----- output -------------------------------------------------------------------------
    def out(self, text: str = "") -> None:
        print(text, flush=True)
        self._fh.write(text + "\n")
        self._fh.flush()

    def step(self, label: str) -> None:
        self._step_no += 1
        self.out("")
        self.out("## Step %d: %s" % (self._step_no, label))
        self.out("")

    def note(self, text: str) -> None:
        self.out("> " + text)

    def block(self, text: str, lang: str = "") -> None:
        self.out("```" + lang)
        self.out(text.rstrip("\n"))
        self.out("```")

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        self.out("WARNING: " + text)

    def fact(self, key: str, value: Any) -> None:
        """Record one fact for the 'What to record' table of the findings file."""
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        self.facts.append((key, text))
        self.out("FACT %s = %s" % (key, text))

    # ----- checks -------------------------------------------------------------------------
    def expect(self, condition: Any, message: str) -> None:
        if condition:
            self.out("PASS: " + message)
        else:
            raise SpikeFailure("FAIL: " + message)

    def fail(self, message: str) -> None:
        raise SpikeFailure(message)

    # ----- HTTP ---------------------------------------------------------------------------
    def http(
        self,
        client: Any,
        method: str,
        url: str,
        expect: Optional[Iterable[int]] = None,
        label: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Any] = None,
        json_body: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Tuple[str, bytes, str]]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[float] = None,
        max_body: int = 3000,
        show_body: bool = True,
    ) -> Any:
        """Send one request with an httpx client, print it and the response, check the status.

        ``expect`` is a collection of acceptable status codes; ``None`` accepts any status (a
        probe: the result is recorded, not judged). Returns the httpx response.
        """
        headers = dict(headers or {})
        shown_headers = {k: (redact_value(v) if k.lower() in ("authorization", "cookie") else v)
                         for k, v in headers.items()}
        if auth is not None:
            shown_headers["Authorization"] = "Basic <redacted>"
        if label:
            self.out("**%s**" % label)
        req_lines = ["%s %s" % (method, url)]
        if params:
            req_lines[0] += "  params=" + json.dumps(redact_json(dict(params)) if isinstance(params, dict) else params, default=str)
        for k, v in shown_headers.items():
            req_lines.append("%s: %s" % (k, v))
        if json_body is not None:
            req_lines.append("")
            req_lines.append(json.dumps(redact_json(json_body), indent=2, default=str))
        if data:
            req_lines.append("")
            req_lines.append("(form) " + json.dumps(redact_json(dict(data)), default=str))
        if files:
            for field, (fname, content, ctype) in files.items():
                req_lines.append("(file) %s=%s (%d bytes, %s)" % (field, fname, len(content), ctype))
        self.block("\n".join(req_lines), "http")
        started = time.monotonic()
        kwargs = {}  # type: Dict[str, Any]
        if headers:
            kwargs["headers"] = headers
        if params is not None:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        if data:
            kwargs["data"] = data
        if files:
            kwargs["files"] = files
        if auth is not None:
            kwargs["auth"] = auth
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            response = client.request(method, url, **kwargs)
        except Exception as exc:  # network errors are failures of the spike
            raise SpikeFailure("request failed: %s %s: %s: %s" % (method, url, type(exc).__name__, exc))
        elapsed_ms = int((time.monotonic() - started) * 1000)
        body_text = response.text if show_body else "<body hidden>"
        shown_body = body_text
        try:
            parsed = response.json()
            shown_body = json.dumps(redact_json(parsed), indent=2, default=str)
        except ValueError:
            shown_body = redact_text(body_text)
        if len(shown_body) > max_body:
            shown_body = shown_body[:max_body] + "\n... <truncated, %d bytes total>" % len(body_text)
        keep = ("content-type", "location", "www-authenticate", "retry-after", "x-ratelimit-remaining",
                "x-ratelimit-limit", "x-ratelimit-reset", "x-github-request-id", "link")
        resp_lines = ["HTTP %d  (%d ms)" % (response.status_code, elapsed_ms)]
        for k, v in response.headers.items():
            if k.lower() in keep:
                resp_lines.append("%s: %s" % (k, redact_text(v)))
        if show_body and shown_body:
            resp_lines.append("")
            resp_lines.append(shown_body)
        self.block("\n".join(resp_lines), "http")
        if expect is not None and response.status_code not in set(expect):
            raise SpikeFailure(
                "unexpected status %d for %s %s (expected one of %s)"
                % (response.status_code, method, url, sorted(set(expect)))
            )
        return response

    # ----- finish -------------------------------------------------------------------------
    def finish(self, exit_code: int = 0) -> int:
        self.out("")
        self.out("## Recorded facts (paste into the 'What to record' table)")
        self.out("")
        self.out("| Fact | Value |")
        self.out("| --- | --- |")
        for key, value in self.facts:
            self.out("| %s | %s |" % (key, value.replace("|", "\\|").replace("\n", " ")))
        if self.warnings:
            self.out("")
            self.out("Warnings:")
            for text in self.warnings:
                self.out("- " + text)
        self.out("")
        self.out("Transcript written to %s" % self.transcript_path)
        self._fh.close()
        return exit_code


def run_spike(spike: Spike, body: Callable[[Spike], Optional[int]]) -> int:
    """Run ``body(spike)``; map SpikeFailure and unexpected exceptions to exit code 1."""
    try:
        code = body(spike)
        return spike.finish(code or 0)
    except SpikeFailure as exc:
        spike.out("")
        spike.out("STOPPED ON FIRST UNEXPECTED RESULT: %s" % exc)
        spike.finish(1)
        return 1
    except KeyboardInterrupt:
        spike.out("interrupted")
        spike.finish(130)
        return 130
    except Exception as exc:  # a bug in the spike script itself; show it, still exit non-zero
        import traceback

        spike.out("")
        spike.out("SPIKE SCRIPT ERROR: %s: %s" % (type(exc).__name__, exc))
        spike.block(traceback.format_exc(), "")
        spike.finish(1)
        return 1


def run_cmd(
    spike: Spike,
    argv: Sequence[str],
    check: bool = True,
    timeout: Optional[float] = None,
    env_extra: Optional[Dict[str, str]] = None,
    show: Optional[str] = None,
    max_out: int = 4000,
) -> Tuple[int, str, float]:
    """Run a command, print command line, output tail, exit code and wall time.

    Never put secrets on ``argv``: pass them through ``env_extra``. ``show`` replaces the printed
    command line when the real one is long. Returns (exit code, combined output, seconds).
    """
    import subprocess

    spike.block("$ " + (show or " ".join(argv)), "sh")
    environment = dict(os.environ)
    if env_extra:
        environment.update(env_extra)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=environment,
        )
        output = proc.stdout.decode("utf-8", "replace")
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", "replace") + "\n<timed out>"
        code = 124
    except FileNotFoundError as exc:
        raise SpikeFailure("command not found: %s" % exc)
    seconds = time.monotonic() - started
    shown = redact_text(output)
    if len(shown) > max_out:
        shown = "... <first part omitted>\n" + shown[-max_out:]
    spike.block("%s\n[exit %d, %.1f s]" % (shown.rstrip(), code, seconds), "")
    if check and code != 0:
        raise SpikeFailure("command failed with exit code %d: %s" % (code, show or " ".join(argv)))
    return code, output, seconds


def make_http_client(verify: Any = True, timeout: float = 60.0) -> Any:
    import httpx

    return httpx.Client(verify=verify, timeout=timeout, follow_redirects=False)


def wait_until(
    spike: Spike,
    description: str,
    probe: Callable[[], bool],
    timeout_s: float,
    interval_s: float = 2.0,
) -> float:
    """Poll ``probe`` until it returns True; return the seconds waited or raise SpikeFailure."""
    started = time.monotonic()
    last_print = 0.0
    while True:
        try:
            if probe():
                waited = time.monotonic() - started
                spike.out("%s: ready after %.1f s" % (description, waited))
                return waited
        except Exception:  # connection refused etc. while the service starts
            pass
        elapsed = time.monotonic() - started
        if elapsed > timeout_s:
            raise SpikeFailure("timed out after %.0f s waiting for %s" % (timeout_s, description))
        if elapsed - last_print >= 15:
            spike.out("... still waiting for %s (%.0f s)" % (description, elapsed))
            last_print = elapsed
        time.sleep(interval_s)
