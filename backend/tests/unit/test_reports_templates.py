from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

import pytest

from securescan.reports import renderer
from securescan.reports import template_package as package
from securescan.reports.sample import XSS_PAYLOAD, sample_snapshot

DEFAULT_DIR = renderer.DEFAULT_TEMPLATE_DIR
HAS_WEASYPRINT = importlib.util.find_spec("weasyprint") is not None

MINIMAL_TEMPLATE = (
    "<!doctype html><html><head><title>{{ snapshot.header.title }}</title></head><body>"
    "<h1>{{ snapshot.header.application_name }}</h1>"
    "{% for f in snapshot.findings %}<p>{{ f.title }}</p>{% endfor %}"
    "</body></html>"
)


def make_zip(files: dict[str, bytes | str], *, symlink: str | None = None) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777) << 16
            archive.writestr(info, "template.html")
    return out.getvalue()


def write_template(root: Path, files: dict[str, str | bytes]) -> Path:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        else:
            target.write_bytes(content)
    return root


# --------------------------------------------------------------------------- the zip


def test_the_default_template_zips_and_unzips() -> None:
    data = package.zip_directory(DEFAULT_DIR)
    files = package.read_zip(data)
    assert set(files) == {
        "template.html",
        "style.css",
        "brand/wordmark.svg",
        "vendor/assessment.html",
    }
    assert package.zip_directory(DEFAULT_DIR) == data  # reproducible


def test_a_zip_of_the_folder_itself_is_accepted() -> None:
    data = make_zip({"my-template/template.html": MINIMAL_TEMPLATE, "my-template/a.css": "p {}"})
    assert set(package.read_zip(data)) == {"template.html", "a.css"}


def test_macos_litter_is_ignored() -> None:
    data = make_zip(
        {"template.html": MINIMAL_TEMPLATE, "__MACOSX/._template.html": "x", "brand/.DS_Store": "x"}
    )
    assert set(package.read_zip(data)) == {"template.html"}


@pytest.mark.parametrize(
    ("files", "needle"),
    [
        ({"template.html": "x", "run.py": "print(1)"}, "only"),
        ({"template.html": "x", "tool.exe": "MZ"}, "only"),
        ({"template.html": "x", "../escape.html": "x"}, "unsafe"),
        ({"template.html": "x", "/abs.html": "x"}, "unsafe"),
        ({"template.html": "x", "a\\b.html": "x"}, "unsafe"),
        ({"template.html": "x", ".hidden.css": "x"}, "not allowed"),
        ({"template.html": "x", "a b$.css": "x"}, "not allowed"),
        ({"style.css": "p {}"}, "no template.html"),
        ({}, "empty"),
    ],
)
def test_zip_validation_refuses(files: dict[str, str], needle: str) -> None:
    with pytest.raises(package.PackageError) as info:
        package.read_zip(make_zip(files))  # type: ignore[arg-type]
    assert needle in str(info.value)


def test_a_zip_with_a_link_is_refused() -> None:
    data = make_zip({"template.html": "x"}, symlink="link.html")
    with pytest.raises(package.PackageError, match="link"):
        package.read_zip(data)


def test_a_file_that_is_not_a_zip_is_refused() -> None:
    with pytest.raises(package.PackageError, match="not a zip"):
        package.read_zip(b"this is not a zip")


def test_size_and_count_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    data = make_zip({"template.html": "x" * 200})
    monkeypatch.setattr(package, "MAX_ZIP_BYTES", 100)
    with pytest.raises(package.PackageError, match="20 MB"):
        package.read_zip(data)
    monkeypatch.undo()
    monkeypatch.setattr(package, "MAX_FILE_BYTES", 50)
    with pytest.raises(package.PackageError, match="larger"):
        package.read_zip(data)
    monkeypatch.undo()
    monkeypatch.setattr(package, "MAX_FILES", 2)
    many = make_zip({"template.html": "x", "a.css": "x", "b.css": "x"})
    with pytest.raises(package.PackageError, match="200 files"):
        package.read_zip(many)


def test_duplicate_names_by_case_are_refused() -> None:
    with pytest.raises(package.PackageError, match="twice"):
        package.read_zip(make_zip({"template.html": "x", "Style.css": "x", "style.CSS": "x"}))


def test_write_files_cannot_escape(tmp_path: Path) -> None:
    with pytest.raises(package.PackageError):
        package.write_files({"../evil.html": b"x"}, tmp_path / "t")


def test_files_digest_depends_on_names_and_contents() -> None:
    one = package.files_sha256({"a.css": b"1"})
    assert one == package.files_sha256({"a.css": b"1"})
    assert one != package.files_sha256({"b.css": b"1"})
    assert one != package.files_sha256({"a.css": b"2"})


# --------------------------------------------------------------------------- the default template


def test_the_default_template_passes_the_static_checks() -> None:
    assert renderer.static_problems(DEFAULT_DIR) == []


def test_the_default_template_passes_its_test_render() -> None:
    assert renderer.check_template(DEFAULT_DIR, with_pdf=False) == []


@pytest.mark.skipif(not HAS_WEASYPRINT, reason="WeasyPrint is not installed")
def test_the_default_template_passes_its_test_render_with_pdf() -> None:
    assert renderer.check_template(DEFAULT_DIR, with_pdf=True) == []


def test_the_default_template_has_the_brand_files() -> None:
    assert "SonaComstar" in (DEFAULT_DIR / "brand" / "wordmark.svg").read_text(encoding="utf-8")
    assert (DEFAULT_DIR / "style.css").is_file()


# --------------------------------------------------------------------------- hostile templates


def test_the_cycler_payload_is_rejected_by_the_upload_check(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"template.html": "{{ cycler.__init__.__globals__ }}"})
    problems = renderer.check_template(root, with_pdf=False)
    assert problems
    assert "double underscores" in problems[0]


def test_the_sandbox_itself_refuses_the_cycler_payload(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"template.html": "{{ cycler.__init__.__globals__ }}"})
    with pytest.raises(renderer.RenderError, match="unsafe"):
        renderer.render_html(root, "template.html", sample_snapshot())


@pytest.mark.parametrize(
    "expression",
    [
        "{{ snapshot.__class__ }}",
        "{{ ''.__class__.__mro__ }}",
        "{{ snapshot|attr('__class__') }}",
        "{{ lipsum.__globals__ }}",
        "{{ self._TemplateReference__context }}",
    ],
)
def test_sandbox_escape_attempts_do_not_render(tmp_path: Path, expression: str) -> None:
    root = write_template(tmp_path, {"template.html": expression})
    with pytest.raises(renderer.RenderError):
        renderer.render_html(root, "template.html", sample_snapshot())


@pytest.mark.parametrize(
    "expression",
    [
        "{{ snapshot.__class__ }}",
        "{{ x.mro() }}",
        "{{ snapshot|attr('x') }}",
        "{% set a = namespace.__init__ %}",
    ],
)
def test_static_check_rejects_dangerous_template_code(tmp_path: Path, expression: str) -> None:
    root = write_template(tmp_path, {"template.html": expression})
    assert renderer.static_problems(root)


@pytest.mark.parametrize(
    "markup",
    [
        "<script>alert(1)</script>",
        "<iframe src='x'></iframe>",
        "<a href='javascript:alert(1)'>x</a>",
        "<img src='data:,' onerror='alert(1)'>",
        "<object data='x'></object>",
    ],
)
def test_static_check_rejects_scripts_and_frames(tmp_path: Path, markup: str) -> None:
    html = "<p>{{ snapshot.header.title }}</p>" + markup
    root = write_template(tmp_path, {"template.html": html})
    assert any("not allowed" in p for p in renderer.static_problems(root))


def test_disallowed_files_are_rejected(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"template.html": MINIMAL_TEMPLATE, "x.py": "print(1)"})
    assert any("x.py" in p for p in renderer.static_problems(root))


def test_a_fake_png_is_rejected(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"template.html": MINIMAL_TEMPLATE, "logo.png": b"not a png"})
    assert any("not a PNG" in p for p in renderer.static_problems(root))


def test_a_template_without_the_entry_file_is_rejected(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"style.css": "p {}"})
    assert renderer.static_problems(root) == ["the template has no template.html at its top level"]


def test_a_template_that_prints_text_unescaped_is_rejected(tmp_path: Path) -> None:
    html = "<p>{% for f in snapshot.findings %}{{ f.title|safe }}{% endfor %}</p>"
    root = write_template(tmp_path, {"template.html": html})
    problems = renderer.check_template(root, with_pdf=False)
    assert any("without escaping" in p for p in problems)


def test_a_template_with_a_jinja_error_is_rejected(tmp_path: Path) -> None:
    root = write_template(tmp_path, {"template.html": "{% for x in %}"})
    problems = renderer.check_template(root, with_pdf=False)
    assert problems and "test render" in problems[0]


def test_external_images_and_stylesheets_are_reported(tmp_path: Path) -> None:
    html = (
        "<link rel='stylesheet' href='https://evil.example/x.css'>"
        "<img src='http://evil.example/p.png'><p>{{ snapshot.header.title }}</p>"
    )
    root = write_template(tmp_path, {"template.html": html})
    problems = renderer.check_template(root, with_pdf=False)
    assert any("evil.example/x.css" in p for p in problems)
    assert any("evil.example/p.png" in p for p in problems)


def test_a_benign_custom_template_renders(tmp_path: Path) -> None:
    files = {"template.html": MINIMAL_TEMPLATE, "style.css": "p { margin: 0 }"}
    root = write_template(tmp_path, files)
    assert renderer.check_template(root, with_pdf=False) == []
    html = renderer.render_html(root, "template.html", sample_snapshot())
    assert "Payroll Portal" in html


def test_isolated_check_in_a_child_process(tmp_path: Path) -> None:
    good = write_template(tmp_path / "good", {"template.html": MINIMAL_TEMPLATE})
    assert renderer.check_template_isolated(good, timeout=120) == []
    bad = write_template(tmp_path / "bad", {"template.html": "{{ cycler.__init__.__globals__ }}"})
    problems = renderer.check_template_isolated(bad, timeout=120)
    assert problems and "double underscores" in problems[0]


# --------------------------------------------------------------------------- assets and fetcher


def test_images_and_css_urls_become_data_uris(tmp_path: Path) -> None:
    svg = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'
    root = write_template(
        tmp_path,
        {
            "template.html": "<link rel='stylesheet' href='style.css'><img src='brand/a.svg'>",
            "style.css": "p { background: url(brand/a.svg) } /* </style> */",
            "brand/a.svg": svg,
        },
    )
    problems: list[str] = []
    html = renderer.render_html(root, "template.html", sample_snapshot(), problems=problems)
    assert problems == []
    assert "brand/a.svg" not in html
    assert html.count("data:image/svg+xml;base64,") == 2
    assert "<link" not in html and "<style>" in html
    assert "</style> */" not in html  # a closing tag inside the CSS cannot end the style block


def test_references_outside_the_template_are_neutralised(tmp_path: Path) -> None:
    (tmp_path / "secret.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    root = tmp_path / "t"
    write_template(root, {"template.html": "<img src='../secret.png'><img src='/etc/passwd'>"})
    problems: list[str] = []
    html = renderer.render_html(root, "template.html", sample_snapshot(), problems=problems)
    assert len(problems) == 2
    assert "secret.png" not in html and "passwd" not in html


def test_the_fetcher_policy_allows_only_data_and_template_files(tmp_path: Path) -> None:
    root = write_template(tmp_path / "t", {"template.html": "x", "brand/a.png": b"\x89PNG"})
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    policy = renderer.UrlPolicy(root=root)
    assert policy.allows("data:text/plain;base64,aGk=")
    assert policy.allows((root / "brand" / "a.png").as_uri())
    assert not policy.allows(outside.as_uri())
    assert not policy.allows((root / ".." / "outside.txt").as_uri())
    assert not policy.allows("file:///etc/passwd")
    assert not policy.allows("http://example.com/x.png")
    assert not policy.allows("https://example.com/x.png")
    assert not policy.allows("ftp://example.com/x")
    assert not policy.allows("file://otherhost/etc/passwd")


def test_the_function_fetcher_reads_allowed_files_and_blocks_the_rest(tmp_path: Path) -> None:
    root = write_template(tmp_path / "t", {"brand/a.png": b"\x89PNGdata"})
    policy = renderer.UrlPolicy(root=root)
    fetch = policy.function_fetcher()
    got = fetch((root / "brand" / "a.png").as_uri())
    assert got["string"] == b"\x89PNGdata" and got["mime_type"] == "image/png"
    assert fetch("data:text/plain;base64,aGk=")["string"] == b"hi"
    with pytest.raises(ValueError):
        fetch("http://example.com/")
    assert policy.blocked == ["http://example.com/"]


def test_the_known_limits_block_is_in_every_default_render() -> None:
    html = renderer.render_html(DEFAULT_DIR, "template.html", sample_snapshot())
    assert "Known limits" in html
    assert "traces taint only within one function" in html


def test_html_of_the_sample_never_contains_the_raw_payload() -> None:
    html = renderer.render_html(DEFAULT_DIR, "template.html", sample_snapshot())
    assert XSS_PAYLOAD not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
