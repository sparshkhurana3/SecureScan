"""Render a report: sandboxed Jinja2 to one HTML string, WeasyPrint from that string to a PDF.

* ``render_html`` loads the template only from its own directory through a
  ``jinja2.sandbox.SandboxedEnvironment`` with ``autoescape=True``. The finished HTML has its CSS
  inlined into ``<style>`` blocks and its images converted to ``data:`` URIs, so the same string is
  served to the portal under a strict Content-Security-Policy and handed to WeasyPrint.
* ``render_pdf`` gives WeasyPrint that string with a URL fetcher that allows ``data:`` URLs and
  files inside the template directory and refuses everything else (``blocked`` lists what it
  refused).
* ``check_template`` is the test render used when an Admin uploads a template: static checks, then a
  render of the sample snapshots (HTML and, when WeasyPrint is installed, PDF). The raw ``<script>``
  payload of the sample must come out escaped. ``check_template_isolated`` runs the same check in a
  child process with a CPU limit and a wall-clock timeout (``python -m securescan.reports.renderer
  --check DIR ENTRY``), so a hostile template cannot hang or crash the API.

Nothing here touches the database or the settings.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import subprocess  # noqa: S404 - runs this very module, with fixed arguments
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from jinja2 import ChainableUndefined, FileSystemLoader, TemplateError
from jinja2.exceptions import SecurityError
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

from securescan.reports.snapshot import Snapshot

DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "default-sonacomstar"
DEFAULT_TEMPLATE_NAME = "SonaComstar default"
ENTRY_FILE = "template.html"
STYLE_FILE = "style.css"
ALLOWED_EXTENSIONS = frozenset({".html", ".css", ".svg", ".png", ".ttf", ".otf"})
ASSET_TYPES = {
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
}
MAX_HTML_BYTES = 40 * 1024 * 1024
CHECK_TIMEOUT_SECONDS = 90

_JINJA_BLOCK = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.DOTALL)
_DUNDER = re.compile(r"__[A-Za-z0-9_]+__")
_FORBIDDEN_MARKUP = re.compile(
    r"<\s*(script|iframe|object|embed|applet|base|meta\s+http-equiv)\b|javascript\s*:|"
    r"\bon[a-z]+\s*=\s*[\"']",
    re.IGNORECASE,
)
_FORBIDDEN_JINJA_NAMES = re.compile(r"\.\s*(mro|subclasses|globals|builtins)\b|\|\s*attr\b")
_EXTERNAL = re.compile(r"^\s*(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)
_SRC_ATTR = re.compile(r"""\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_IMG_TAG = re.compile(r"<img\b[^>]*>", re.IGNORECASE | re.DOTALL)
_LINK_TAG = re.compile(r"<link\b[^>]*>", re.IGNORECASE | re.DOTALL)
_HREF_ATTR = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)"'\s]*))\s*\)""", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"@import\b[^;]*;?", re.IGNORECASE)
_CSS_SCRIPTING = re.compile(r"expression\s*\(|behavior\s*:|-moz-binding", re.IGNORECASE)


class RenderError(Exception):
    """A template could not be rendered."""


# --------------------------------------------------------------------------- environment


def _format_utc(value: Any, with_time: bool = True) -> str:
    text = str(value or "")
    if not text:
        return ""
    # ISO text written by snapshot.iso(): 2026-10-07T09:30:00Z
    date_part, _, time_part = text.rstrip("Z").partition("T")
    if not with_time or not time_part:
        return date_part
    return f"{date_part} {time_part[:5]} UTC"


class ReportUndefined(ChainableUndefined):
    """Missing names print as nothing, but a name the sandbox refused to hand out raises.

    Jinja's sandbox answers an unsafe attribute (``x.__class__``, ``cycler.__init__.__globals__``)
    with an ``Undefined`` that carries a ``SecurityError``; the plain classes print it as an empty
    string. Raising when it is printed turns every sandbox violation into a failed render.
    """

    __slots__ = ()

    def __str__(self) -> str:
        if self._undefined_exception is SecurityError:
            self._fail_with_undefined_error()
        return ""


def make_environment(template_dir: Path) -> SandboxedEnvironment:
    """The only Jinja environment the application uses to render templates."""
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
        undefined=ReportUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["utc"] = _format_utc
    env.filters["utcdate"] = lambda value: _format_utc(value, with_time=False)
    return env


# --------------------------------------------------------------------------- assets


def data_uri(path: Path) -> str:
    kind = ASSET_TYPES.get(path.suffix.lower()) or mimetypes.guess_type(path.name)[0]
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{kind or 'application/octet-stream'};base64,{encoded}"


def resolve_inside(template_dir: Path, base_dir: Path, reference: str) -> Path | None:
    """A relative reference as an existing file below ``template_dir``, else None."""
    ref = unquote(reference.strip().split("#", 1)[0].split("?", 1)[0])
    if not ref or _EXTERNAL.match(ref) or ref.startswith("/"):
        return None
    root = template_dir.resolve()
    try:
        target = (base_dir / ref).resolve()
    except (OSError, ValueError):
        return None
    if target != root and root not in target.parents:
        return None
    if not target.is_file():
        return None
    return target


def _css_with_data_uris(css: str, template_dir: Path, base_dir: Path, problems: list[str]) -> str:
    if _CSS_IMPORT.search(css):
        problems.append("CSS @import is not allowed; put all rules in one file")
        css = _CSS_IMPORT.sub("", css)

    def replace(match: re.Match[str]) -> str:
        ref = match.group(1) or match.group(2) or match.group(3) or ""
        if ref.startswith("data:"):
            return match.group(0)
        target = resolve_inside(template_dir, base_dir, ref)
        if target is None or target.suffix.lower() not in ASSET_TYPES:
            problems.append(f"CSS refers to {ref[:80]!r}, which is not a file of the template")
            return "none"
        return f'url("{data_uri(target)}")'

    css = _CSS_URL.sub(replace, css)
    return css.replace("</", "<\\/")


def read_css(template_dir: Path, name: str = STYLE_FILE, problems: list[str] | None = None) -> str:
    """The template's stylesheet with every ``url()`` turned into a ``data:`` URI."""
    sink = problems if problems is not None else []
    path = (template_dir / name)
    if not path.is_file():
        return ""
    return _css_with_data_uris(path.read_text(encoding="utf-8"), template_dir, path.parent, sink)


def inline_assets(html: str, template_dir: Path, problems: list[str]) -> str:
    """Inline stylesheet links and turn relative ``<img src>`` into ``data:`` URIs.

    A reference that is not a file of the template (a URL, an absolute path, a path that leaves the
    directory) is removed and reported in ``problems``; the fetcher would refuse it anyway.
    """
    root = template_dir.resolve()

    def link(match: re.Match[str]) -> str:
        tag = match.group(0)
        if not re.search(r"""rel\s*=\s*["']?stylesheet""", tag, re.IGNORECASE):
            return ""
        href_match = _HREF_ATTR.search(tag)
        ref = (href_match.group(1) or href_match.group(2) or "") if href_match else ""
        target = resolve_inside(template_dir, root, ref)
        if target is None or target.suffix.lower() != ".css":
            problems.append(f"stylesheet {ref[:80]!r} is not a .css file of the template")
            return ""
        source_css = target.read_text(encoding="utf-8")
        css = _css_with_data_uris(source_css, template_dir, target.parent, problems)
        return f"<style>{css}</style>"

    def image(match: re.Match[str]) -> str:
        tag = match.group(0)

        def source(src: re.Match[str]) -> str:
            ref = src.group(1) if src.group(1) is not None else (src.group(2) or "")
            if ref.startswith("data:"):
                return src.group(0)
            target = resolve_inside(template_dir, root, ref)
            if target is None or target.suffix.lower() not in (".svg", ".png"):
                problems.append(f"image {ref[:80]!r} is not an .svg or .png file of the template")
                return 'src=""'
            return f'src="{data_uri(target)}"'

        return _SRC_ATTR.sub(source, tag)

    html = _LINK_TAG.sub(link, html)
    return _IMG_TAG.sub(image, html)


# --------------------------------------------------------------------------- rendering


def snapshot_context(snapshot: Snapshot | dict[str, Any]) -> dict[str, Any]:
    if isinstance(snapshot, Snapshot):
        return snapshot.model_dump(mode="json")
    return snapshot


def render_html(
    template_dir: Path,
    entry_file: str,
    snapshot: Snapshot | dict[str, Any],
    report_hash: str = "",
    *,
    target: str = "html",
    problems: list[str] | None = None,
) -> str:
    """Render the template of ``template_dir`` for ``snapshot`` to a self-contained HTML string.

    The template sees ``snapshot`` (plain dicts and lists), ``report_hash``, ``target`` (``html`` or
    ``pdf``) and ``inline_css`` (the stylesheet as safe markup). Raises ``RenderError``.
    """
    sink = problems if problems is not None else []
    env = make_environment(template_dir)
    try:
        template = env.get_template(entry_file)
        html = template.render(
            snapshot=snapshot_context(snapshot),
            report_hash=report_hash,
            target=target,
            inline_css=Markup(read_css(template_dir, problems=sink)),  # noqa: S704 - sanitised CSS
        )
    except TemplateError as exc:
        raise RenderError(f"{type(exc).__name__}: {exc}") from exc
    except RecursionError as exc:
        raise RenderError("the template recurses too deeply") from exc
    html = inline_assets(html, template_dir, sink)
    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        raise RenderError("the rendered report is larger than 40 MB")
    return html


def _is_allowed(url: str, root: Path) -> bool:
    parts = urlsplit(url)
    if parts.scheme == "data":
        return True
    if parts.scheme == "file":
        if parts.netloc not in ("", "localhost"):
            return False
        try:
            target = Path(url2pathname(parts.path)).resolve()
        except (OSError, ValueError):
            return False
        return target == root or root in target.parents
    return False


def _decode_data_url(url: str) -> tuple[bytes, str]:
    head, _, payload = url[5:].partition(",")
    mime = head.split(";", 1)[0] or "text/plain"
    if head.endswith(";base64"):
        return base64.b64decode(payload), mime
    return unquote(payload).encode("utf-8"), mime


@dataclass
class UrlPolicy:
    """What WeasyPrint may load: ``data:`` URLs and files inside the template directory."""

    root: Path
    blocked: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)

    def allows(self, url: str) -> bool:
        return _is_allowed(url, self.root.resolve())

    def function_fetcher(self) -> Callable[..., dict[str, Any]]:
        """Fetcher for WeasyPrint before 68 (plain function returning a dict)."""

        def fetch(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if not self.allows(url):
                self.blocked.append(url[:200])
                raise ValueError("blocked by the SecureScan url_fetcher policy")
            self.allowed.append(url[:120])
            if url.startswith("data:"):
                data, mime = _decode_data_url(url)
                return {"string": data, "mime_type": mime}
            path = Path(url2pathname(urlsplit(url).path))
            kind = mimetypes.guess_type(path.name)[0]
            return {"string": path.read_bytes(), "mime_type": kind or "application/octet-stream"}

        return fetch


def build_fetcher(policy: UrlPolicy) -> Any:
    """A WeasyPrint URL fetcher enforcing ``policy`` (class API of 68+, else a function)."""
    try:
        from weasyprint.urls import URLFetcher  # type: ignore[attr-defined]
    except ImportError:
        return policy.function_fetcher()

    class RestrictedFetcher(URLFetcher):  # type: ignore[misc,valid-type]
        def fetch(self, url: str, headers: dict[str, str] | None = None) -> Any:
            if not policy.allows(url):
                policy.blocked.append(url[:200])
                raise ValueError("blocked by the SecureScan url_fetcher policy")
            policy.allowed.append(url[:120])
            return super().fetch(url, headers)

    try:
        return RestrictedFetcher(allowed_protocols=("data", "file"))
    except TypeError:
        return RestrictedFetcher()


def render_pdf(html: str, template_dir: Path, policy: UrlPolicy | None = None) -> bytes:
    """PDF bytes from the finished HTML string. Blocking and CPU heavy: call from a thread."""
    try:
        import weasyprint
    except (ImportError, OSError) as exc:  # missing package or native library
        raise RenderError(f"WeasyPrint is not available: {exc}") from exc
    active = policy or UrlPolicy(root=template_dir)
    try:
        document = weasyprint.HTML(
            string=html,
            base_url=str(template_dir.resolve()) + "/",
            url_fetcher=build_fetcher(active),
        )
        pdf = document.write_pdf()
    except Exception as exc:  # noqa: BLE001 - WeasyPrint raises many types
        raise RenderError(f"PDF rendering failed: {type(exc).__name__}: {exc}") from exc
    return bytes(pdf)


@dataclass
class Rendered:
    html: str
    pdf: bytes


def render_report(
    template_dir: Path, entry_file: str, snapshot: Snapshot | dict[str, Any], report_hash: str = ""
) -> Rendered:
    """HTML and PDF of one report (blocking; the callers run it in a thread)."""
    html = render_html(template_dir, entry_file, snapshot, report_hash, target="html")
    pdf_html = render_html(template_dir, entry_file, snapshot, report_hash, target="pdf")
    return Rendered(html=html, pdf=render_pdf(pdf_html, template_dir))


# --------------------------------------------------------------------------- validation


def static_problems(template_dir: Path, entry_file: str = ENTRY_FILE) -> list[str]:
    """Checks that need no rendering: entry file, allowed content, forbidden constructs."""
    problems: list[str] = []
    root = template_dir.resolve()
    if not (root / entry_file).is_file():
        return [f"the template has no {entry_file} at its top level"]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            problems.append(f"{rel}: file type {suffix or '(none)'} is not allowed")
            continue
        if suffix in (".html", ".css", ".svg"):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                problems.append(f"{rel}: not valid UTF-8 text")
                continue
            if suffix == ".html":
                for block in _JINJA_BLOCK.findall(text):
                    if _DUNDER.search(block):
                        problems.append(
                            f"{rel}: template code may not use names with double underscores"
                        )
                        break
                    if _FORBIDDEN_JINJA_NAMES.search(block):
                        problems.append(
                            f"{rel}: template code uses a forbidden attribute or filter"
                        )
                        break
            if suffix in (".html", ".svg") and _FORBIDDEN_MARKUP.search(text):
                problems.append(
                    f"{rel}: scripts, frames, embedded objects and event handlers are not allowed"
                )
            if suffix == ".css" and _CSS_SCRIPTING.search(text):
                problems.append(f"{rel}: script-bearing CSS is not allowed")
        elif suffix == ".png" and not path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
            problems.append(f"{rel}: not a PNG image")
        elif suffix in (".ttf", ".otf"):
            magic = path.read_bytes()[:4]
            if magic not in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf"):
                problems.append(f"{rel}: not a TrueType or OpenType font")
    return problems


def check_template(
    template_dir: Path, entry_file: str = ENTRY_FILE, *, with_pdf: bool = True
) -> list[str]:
    """Static checks plus a test render of the sample snapshots; returns the problems found."""
    from securescan.reports.sample import XSS_PAYLOAD, sample_snapshot

    problems = static_problems(template_dir, entry_file)
    if problems:
        return problems
    for kind in ("application", "vendor"):
        snapshot = sample_snapshot(kind)
        asset_problems: list[str] = []
        try:
            html = render_html(
                template_dir, entry_file, snapshot, "0" * 64, problems=asset_problems
            )
        except RenderError as exc:
            return [f"test render ({kind}) failed: {exc}"]
        problems.extend(f"{kind} report: {p}" for p in asset_problems)
        if XSS_PAYLOAD in html:
            problems.append(
                f"{kind} report: the template prints scanner text without escaping it "
                "(do not use |safe or turn autoescape off)"
            )
        if "sk_live_THIS_MUST_NOT_APPEAR" in html:
            problems.append(f"{kind} report: the template prints a secret value")
        if not html.strip():
            problems.append(f"{kind} report: the template rendered an empty page")
    if problems or not with_pdf:
        return problems
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError):
        return problems  # PDF check skipped where WeasyPrint is not installed
    policy = UrlPolicy(root=template_dir)
    try:
        html = render_html(
            template_dir, entry_file, sample_snapshot("vendor"), "0" * 64, target="pdf"
        )
        pdf = render_pdf(html, template_dir, policy)
    except RenderError as exc:
        return [f"test PDF render failed: {exc}"]
    if not pdf.startswith(b"%PDF"):
        problems.append("the test render did not produce a PDF")
    if policy.blocked:
        problems.append(
            f"the template refers to resources that are not allowed: {policy.blocked[:3]}"
        )
    return problems


def check_template_isolated(
    template_dir: Path, entry_file: str = ENTRY_FILE, *, timeout: int = CHECK_TIMEOUT_SECONDS
) -> list[str]:
    """``check_template`` in a child process with a timeout and a CPU limit."""
    keep = ("PATH", "LANG", "LC_ALL", "HOME", "PYTHONPATH", "VIRTUAL_ENV", "FONTCONFIG_PATH",
            "FONTCONFIG_FILE", "XDG_CACHE_HOME", "XDG_DATA_DIRS", "TMPDIR")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    command = [
        sys.executable,
        "-m",
        "securescan.reports.renderer",
        "--check",
        str(template_dir),
        entry_file,
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed command, no shell, no user input in argv
            command, capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except subprocess.TimeoutExpired:
        return [f"the test render took longer than {timeout} seconds and was stopped"]
    except OSError as exc:
        return [f"the test render could not start: {exc}"]
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        problems = [str(p) for p in result["problems"]]
    except (IndexError, ValueError, KeyError, TypeError):
        tail = (completed.stderr or completed.stdout or "").strip()[-300:]
        return [f"the test render crashed (exit code {completed.returncode}): {tail}"]
    return problems


def _limit_cpu() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (60, 75))
    except (ImportError, ValueError, OSError):
        pass  # not available (Windows); the parent's timeout still applies


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 3 and args[0] == "--check":
        _limit_cpu()
        try:
            problems = check_template(Path(args[1]), args[2])
        except Exception as exc:  # noqa: BLE001 - report every failure as a problem
            problems = [f"the test render failed: {type(exc).__name__}: {exc}"]
        sys.stdout.write(json.dumps({"problems": problems}) + "\n")
        return 0
    sys.stderr.write("usage: python -m securescan.reports.renderer --check DIR ENTRY\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
