from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader, PdfWriter

from securescan.domain import reports as report_service
from securescan.reports.sample import sample_snapshot
from securescan.reports.watermark import pdf_text, stamp_pdf, stamp_text

# --------------------------------------------------------------------------- CSV


def parse(snapshot_csv: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(snapshot_csv)))


def test_csv_has_a_header_and_one_row_per_finding() -> None:
    snapshot = sample_snapshot()
    rows = parse("".join(report_service.findings_csv(snapshot)))
    assert rows[0] == list(report_service.CSV_HEADER)
    assert len(rows) == 1 + len(snapshot.findings) + len(snapshot.triaged)
    assert all(len(row) == len(report_service.CSV_HEADER) for row in rows)
    first = dict(zip(rows[0], rows[1], strict=True))
    assert first["Severity"] == "Critical"
    assert first["CWE"] == "CWE-79"
    assert first["OWASP Top 10"] == "A03 Injection"
    assert first["CWE Top 25 rank"] == "1"
    assert first["File"] == "web/render.js"
    assert first["Line"] == "7"
    assert first["Report"] == "SSR-20261007-SAMPLE1"
    triaged = dict(zip(rows[0], rows[-1], strict=True))
    assert triaged["Status"] == "False positive"


@pytest.mark.parametrize(
    "title",
    [
        "=HYPERLINK(\"http://evil.example\",\"x\")",
        "+SUM(1+1)",
        "-2+3",
        "@SUM(A1)",
        "\tinjected",
        "\rinjected",
    ],
)
def test_cells_that_could_be_formulas_are_prefixed(title: str) -> None:
    snapshot = sample_snapshot()
    snapshot.findings[0].title = title
    snapshot.findings[0].file_path = title
    rows = parse("".join(report_service.findings_csv(snapshot)))
    record = dict(zip(rows[0], rows[1], strict=True))
    assert record["Title"] == "'" + title
    assert record["File"] == "'" + title


def test_commas_quotes_and_newlines_stay_in_one_cell() -> None:
    snapshot = sample_snapshot()
    snapshot.findings[1].title = 'He said "hi", then\nleft'
    rows = parse("".join(report_service.findings_csv(snapshot)))
    assert any(row[4] == 'He said "hi", then\nleft' for row in rows[1:])
    assert len(rows) == 1 + len(snapshot.findings) + len(snapshot.triaged)


def test_a_title_that_only_looks_safe_is_left_alone() -> None:
    snapshot = sample_snapshot()
    snapshot.findings[0].title = "a=b"
    rows = parse("".join(report_service.findings_csv(snapshot)))
    assert dict(zip(rows[0], rows[1], strict=True))["Title"] == "a=b"


# --------------------------------------------------------------------------- watermark


def blank_pdf(pages: int = 2, width: float = 595, height: float = 842) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=width, height=height)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_stamp_text_names_the_user_and_the_utc_time() -> None:
    moment = datetime(2026, 10, 7, 14, 5, 59, tzinfo=timezone.utc)
    assert stamp_text("Jane Doe", moment) == "Downloaded by Jane Doe on 2026-10-07 14:05 UTC"


def test_stamp_text_converts_to_utc_and_cleans_the_name() -> None:
    from datetime import timedelta

    local = datetime(2026, 10, 7, 20, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert stamp_text("  A\n B  ", local) == "Downloaded by A B on 2026-10-07 14:30 UTC"
    assert stamp_text("", local).startswith("Downloaded by unknown user")


def test_the_stamp_is_extractable_on_every_page() -> None:
    moment = datetime(2026, 10, 7, 14, 5, tzinfo=timezone.utc)
    stamped = stamp_pdf(blank_pdf(3), "Jane Doe (jane@example.com)", moment)
    reader = PdfReader(io.BytesIO(stamped))
    assert len(reader.pages) == 3
    for page in reader.pages:
        text = page.extract_text()
        assert "Downloaded by Jane Doe (jane@example.com) on 2026-10-07 14:05 UTC" in " ".join(
            text.split()
        )


def test_special_characters_in_the_name_do_not_break_the_pdf() -> None:
    stamped = stamp_pdf(blank_pdf(1), r"O'Brien (x) \ y", datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert r"O'Brien (x) \ y" in " ".join(pdf_text(stamped).split())


def test_names_outside_latin_1_are_replaced_not_fatal() -> None:
    stamped = stamp_pdf(blank_pdf(1), "Zoe 中文", datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert "Downloaded by Zoe" in pdf_text(stamped)


def test_the_original_bytes_are_not_changed() -> None:
    original = blank_pdf(1)
    before = bytes(original)
    stamp_pdf(original, "Jane", datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert original == before
    assert "Downloaded by" not in pdf_text(original)


def test_stamping_keeps_the_page_size() -> None:
    stamped = stamp_pdf(blank_pdf(1, 300, 400), "Jane", datetime(2026, 1, 2, tzinfo=timezone.utc))
    page = PdfReader(io.BytesIO(stamped)).pages[0]
    assert (float(page.mediabox.width), float(page.mediabox.height)) == (300.0, 400.0)
