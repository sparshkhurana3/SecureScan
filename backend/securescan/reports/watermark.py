"""Per-download PDF stamp.

``stamp_pdf`` writes "Downloaded by <name> on <UTC time>" in small grey Helvetica at the bottom of
every page of a PDF, using pypdf only (the overlay page is built from a content stream, so no other
PDF library is needed). The stored report PDF stays unstamped and is the record; each download gets
its own stamped copy, which makes a leaked copy traceable to the person who downloaded it.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from pypdf import PageObject, PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

STAMP_FONT_SIZE = 7.5
STAMP_MARGIN_LEFT = 51.0  # points (18 mm)
STAMP_MARGIN_BOTTOM = 14.0  # points


def stamp_text(name: str, when: datetime | None = None) -> str:
    """The text of the stamp: ``Downloaded by <name> on <YYYY-MM-DD HH:MM> UTC``."""
    moment = when or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    clean = " ".join((name or "unknown user").split())[:120]
    return f"Downloaded by {clean} on {moment.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC"


def _pdf_literal(text: str) -> bytes:
    """``text`` as the body of a PDF literal string in WinAnsi encoding (unknown characters: ?)."""
    raw = text.encode("cp1252", errors="replace")
    out = bytearray()
    for byte in raw:
        if byte in (0x28, 0x29, 0x5C):  # ( ) \
            out += b"\\" + bytes([byte])
        elif byte < 0x20:
            out += b" "
        else:
            out.append(byte)
    return bytes(out)


def _overlay(width: float, height: float, text: str) -> PageObject:
    """A transparent page of the given size holding only the stamp."""
    overlay = PageObject.create_blank_page(None, width, height)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
            NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
        }
    )
    overlay[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/SSStampFont"): font})}
    )
    content = b"q 0.35 g BT /SSStampFont %s Tf %s %s Td (" % (
        f"{STAMP_FONT_SIZE:g}".encode("ascii"),
        f"{STAMP_MARGIN_LEFT:g}".encode("ascii"),
        f"{STAMP_MARGIN_BOTTOM:g}".encode("ascii"),
    ) + _pdf_literal(text) + b") Tj ET Q"
    stream = DecodedStreamObject()
    stream.set_data(content)
    overlay[NameObject("/Contents")] = stream
    return overlay


def stamp_pdf(pdf_bytes: bytes, name: str, when: datetime | None = None) -> bytes:
    """Return a copy of ``pdf_bytes`` with the download stamp on every page."""
    text = stamp_text(name, when)
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)
        page.merge_page(_overlay(width, height, text))
        writer.add_page(page)
    writer.add_metadata({"/Subject": text})
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def pdf_text(pdf_bytes: bytes) -> str:
    """All extractable text of a PDF (used by tests and the acceptance check)."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)
