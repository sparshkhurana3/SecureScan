#!/usr/bin/env python3
"""Spike S5: render a sample PDF with WeasyPrint inside the backend image, with a restricted url_fetcher, and stamp it.

Runs INSIDE the image built from deploy/backend/Dockerfile (run.sh does the docker build and docker run):

    python /spike/render.py --out /out

Steps and assertions
  1. print the versions of WeasyPrint, pydyf, pypdf, Python;
  2. render templates/sample.html (two pages, inline CSS, wordmark SVG as a data: URI, table, severity badges,
     @page counters) with a url_fetcher that only allows data: URLs and file: URLs under the template directory;
     assert two pages, the local stylesheet and image were fetched, nothing was blocked, Liberation Sans is embedded;
  3. render templates/hostile.html, which references http, https, ftp, file:///etc/passwd, a parent-directory file and
     @import; assert every one of them was refused while the PDF is still produced;
  4. stamp every page with "Downloaded by Test User on 2026-10-07 10:00 UTC" (overlay rendered by WeasyPrint, merged with
     pypdf) and assert the stamp and the original text are extractable;
  5. write sample.pdf, hostile.pdf, sample-watermarked.pdf and print timings and sizes.

Exit code 1 on the first failed assertion. Stdlib + weasyprint + pypdf only.
"""

from __future__ import annotations

import argparse
import base64
import io
import logging
import sys
import time
from pathlib import Path
from typing import Any, List, Optional
from urllib.parse import urlsplit
from urllib.request import url2pathname

STAMP = "Downloaded by Test User on 2026-10-07 10:00 UTC"
HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"

try:  # WeasyPrint 68+: fetchers are classes
    from weasyprint.urls import URLFetcher  # type: ignore[attr-defined]
except ImportError:  # older API: plain function
    URLFetcher = None  # type: ignore[assignment,misc]


def is_allowed(url: str, root: Path) -> bool:
    """data: always; file: only for paths inside ``root`` after resolving symlinks and dot segments."""
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


def build_fetcher(root: Path, allowed: List[str], blocked: List[str]) -> Any:
    root = root.resolve()
    if URLFetcher is not None:

        class RestrictedFetcher(URLFetcher):  # type: ignore[misc,valid-type]
            def fetch(self, url: str, headers: Optional[dict] = None) -> Any:  # type: ignore[override]
                if not is_allowed(url, root):
                    blocked.append(url)
                    raise ValueError("blocked by the SecureScan url_fetcher policy: %s" % url[:80])
                allowed.append(url[:120])
                return super().fetch(url, headers)

        try:
            return RestrictedFetcher(allowed_protocols=("data", "file"))
        except TypeError:  # constructor without allowed_protocols
            return RestrictedFetcher()

    from weasyprint import default_url_fetcher  # type: ignore[attr-defined]

    def fetcher(url: str, *args: Any, **kwargs: Any) -> Any:
        if not is_allowed(url, root):
            blocked.append(url)
            raise ValueError("blocked by the SecureScan url_fetcher policy: %s" % url[:80])
        allowed.append(url[:120])
        return default_url_fetcher(url, *args, **kwargs)

    return fetcher


class Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records = []  # type: List[str]

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append("%s: %s" % (record.levelname, record.getMessage()[:200]))


def wordmark_data_uri() -> str:
    for candidate in (Path("/brand/wordmark.svg"), HERE.parent.parent / "frontend" / "src" / "brand" / "wordmark.svg"):
        if candidate.exists():
            svg = candidate.read_bytes()
            break
    else:
        svg = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 32"><text x="0" y="24" '
               b'font-family="Liberation Sans" font-size="26" font-weight="700">SonaComstar</text></svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(svg).decode("ascii")


def check(condition: bool, message: str) -> None:
    if not condition:
        print("FAIL: " + message)
        sys.exit(1)
    print("PASS: " + message)


def render(html_path: Path, replace_wordmark: bool) -> Any:
    import weasyprint

    allowed = []  # type: List[str]
    blocked = []  # type: List[str]
    capture = Capture()
    logger = logging.getLogger("weasyprint")
    logger.addHandler(capture)
    logger.setLevel(logging.DEBUG)
    text = html_path.read_text(encoding="utf-8")
    if replace_wordmark:
        text = text.replace("{{WORDMARK_DATA_URI}}", wordmark_data_uri())
    started = time.monotonic()
    document = weasyprint.HTML(
        string=text, base_url=str(html_path.parent) + "/", url_fetcher=build_fetcher(TEMPLATES, allowed, blocked)
    )
    pdf_bytes = document.write_pdf()
    seconds = time.monotonic() - started
    logger.removeHandler(capture)
    return pdf_bytes, allowed, blocked, capture.records, seconds


def font_names(reader: Any) -> List[str]:
    names = []  # type: List[str]
    for page in reader.pages:
        resources = page.get("/Resources")
        fonts = resources.get_object().get("/Font") if resources else None
        if not fonts:
            continue
        for ref in fonts.get_object().values():
            name = str(ref.get_object().get("/BaseFont", ""))
            if name and name not in names:
                names.append(name)
    return names


def overlay_pdf() -> bytes:
    import weasyprint

    html = (
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "@page { size: A4; margin: 0 } html { font-family: 'Liberation Sans', Arial, sans-serif }"
        ".stamp { position: absolute; left: 18mm; bottom: 9mm; font-size: 7.5pt; color: #555 }"
        "</style></head><body><div class='stamp'>%s</div></body></html>" % STAMP
    )
    return weasyprint.HTML(string=html, url_fetcher=build_fetcher(TEMPLATES, [], [])).write_pdf()


def stamp(pdf_bytes: bytes) -> bytes:
    from pypdf import PdfReader, PdfWriter

    overlay_page = PdfReader(io.BytesIO(overlay_pdf())).pages[0]
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        page.merge_page(overlay_page)
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/out")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        import pydyf
        import pypdf
        import weasyprint
    except OSError as exc:
        print("FAIL: WeasyPrint could not load a native library: %s" % exc)
        print("Candidates to add to the apt list in deploy/backend/Dockerfile: libharfbuzz0b libfontconfig1 libcairo2 libgdk-pixbuf-2.0-0")
        return 1
    print("python %s | weasyprint %s | pydyf %s | pypdf %s" % (sys.version.split()[0], weasyprint.__version__,
                                                               getattr(pydyf, "__version__", "?"), pypdf.__version__))
    print("URLFetcher class available: %s" % (URLFetcher is not None))

    # ---- 2 sample ------------------------------------------------------------------------------------------------
    pdf, allowed, blocked, logs, seconds = render(TEMPLATES / "sample.html", True)
    (out / "sample.pdf").write_bytes(pdf)
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(pdf))
    print("sample.pdf: %d bytes, %d pages, %.2f s" % (len(pdf), len(reader.pages), seconds))
    check(len(reader.pages) == 2, "the sample has exactly two pages")
    check(any(u.endswith("extra.css") for u in allowed), "the local stylesheet was fetched")
    check(any(u.endswith("dot.svg") for u in allowed), "the local image was fetched")
    check(not blocked, "nothing was blocked while rendering the legitimate template (blocked: %s)" % blocked)
    fonts = font_names(reader)
    print("embedded fonts: %s" % fonts)
    check(any("Liberation" in f for f in fonts), "Liberation Sans is embedded")
    text = " ".join(" ".join(p.extract_text().split()) for p in reader.pages)
    check("Page 1 of 2" in text and "Page 2 of 2" in text, "page numbers 'Page 1 of 2' and 'Page 2 of 2' are in the text")
    check("Known limits of this report" in text, "text of page 2 is extractable")
    check("caf" in text and "100" in text, "non-ASCII sample text produced output")
    print("weasyprint log lines for the sample (%d): %s" % (len(logs), logs[:5]))

    # ---- 3 hostile -----------------------------------------------------------------------------------------------
    hostile_pdf, h_allowed, h_blocked, h_logs, h_seconds = render(TEMPLATES / "hostile.html", False)
    (out / "hostile.pdf").write_bytes(hostile_pdf)
    print("hostile.pdf: %d bytes, %.2f s" % (len(hostile_pdf), h_seconds))
    print("allowed: %s" % h_allowed)
    print("blocked: %s" % h_blocked)
    for needle in ("http://example.invalid/evil.css", "file:///etc/hostname", "http://example.invalid/import.css",
                   "http://example.invalid/bg.png", "file:///etc/passwd", "http://example.invalid/remote.png",
                   "https://example.invalid/remote.png", "ftp://example.invalid/a.png"):
        check(any(b == needle or b.startswith(needle) for b in h_blocked), "blocked: %s" % needle)
    check(any(b.endswith("/render.py") for b in h_blocked), "blocked: parent-directory file ../render.py")
    check(any(a.endswith("dot.svg") for a in h_allowed), "allowed: dot.svg inside the template directory")
    check(len(PdfReader(io.BytesIO(hostile_pdf)).pages) >= 1, "the hostile template still produced a PDF")
    print("weasyprint log lines for the hostile template (%d): %s" % (len(h_logs), h_logs[:8]))

    # ---- 4 watermark --------------------------------------------------------------------------------------------------
    stamped = stamp(pdf)
    (out / "sample-watermarked.pdf").write_bytes(stamped)
    sreader = PdfReader(io.BytesIO(stamped))
    check(len(sreader.pages) == 2, "the stamped PDF still has two pages")
    for index, page in enumerate(sreader.pages, 1):
        page_text = " ".join(page.extract_text().split())
        check(STAMP in page_text, "page %d carries the stamp text, extractable: %r" % (index, STAMP))
    full = " ".join(" ".join(p.extract_text().split()) for p in sreader.pages)
    check("Application security report (sample)" in full, "the original content is still extractable after stamping")
    print("sample-watermarked.pdf: %d bytes; fonts: %s" % (len(stamped), font_names(sreader)))
    print("DONE: files written to %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
