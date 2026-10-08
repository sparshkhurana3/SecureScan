"""The regression gate of one image proposal.

``image_regression`` runs the regression suite (``securescan/domain/regression.py``) with the image of a
proposal in place of the approved one, then records the outcome on the ``ImageVersion`` row:

``pending`` -> ``testing`` -> ``passed`` | ``failed`` | ``error`` | ``skipped``

* ``passed``: every verified expectation of the tool was found by the candidate image.
* ``failed``: a verified expectation disappeared (the new image reports less than the old one).
* ``error``: a job failed, timed out or ran another image than the candidate (the gate does not guess).
* ``skipped``: nothing could be asserted (no verified expectation yet, or no expectations for the tool).
  The Admin can still approve, but must acknowledge that nothing was tested.

While the row is ``testing`` it carries a random token in ``regression_detail["candidate_token"]``. The
scans of the test carry the same token in their job options, which is the only way a scan can run an
image that is not approved (see ``runner/catalogue.py``). The token is removed when the test ends and
is never returned by the API.

Tasks are deferred with ``lock="regression"`` so that proposals are tested one at a time.
"""

from __future__ import annotations

import uuid
from typing import Any

from procrastinate import RetryStrategy
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.images import ImageVersion
from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.domain.image_updates import REGRESSION_TOOLS, SOURCE_PROPOSAL, regression_job_for
from securescan.domain.regression import (
    STATUS_ERROR,
    STATUS_FAILED,
    STATUS_PASSED,
    CandidateImage,
    RegressionReport,
    new_candidate_token,
    run_regression,
)
from securescan.jobs.app import app
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

FINISHED_RESULTS = frozenset({"passed", "failed", "error", "skipped"})


def result_for_report(report: RegressionReport) -> str:
    """Map a suite outcome to the ``regression_result`` of a row."""
    if any(r.status == STATUS_ERROR for r in report.results):
        return "error"
    if report.outcome == STATUS_FAILED:
        return "failed"
    if report.outcome == STATUS_PASSED:
        return "passed"
    return "skipped"


def finished_detail(old: dict[str, Any], report: RegressionReport | None, note: str | None) -> dict[str, Any]:
    """The new ``regression_detail``: the old keys without the token, plus the suite's result."""
    detail = {k: v for k, v in (old or {}).items() if k not in ("candidate_token", "started_at")}
    detail["finished_at"] = utcnow().isoformat()
    if report is not None:
        detail["regression"] = report.to_detail()
    if note:
        detail["note"] = note
    return detail


async def _begin(session: AsyncSession, row_id: uuid.UUID) -> tuple[ImageVersion, str] | None:
    row = await session.get(ImageVersion, row_id)
    if row is None or row.source != SOURCE_PROPOSAL or row.active or row.approved_at is not None:
        return None
    if row.regression_result in FINISHED_RESULTS:
        return None
    token = new_candidate_token()
    row.regression_result = "testing"
    row.regression_detail = {
        **{k: v for k, v in (row.regression_detail or {}).items() if k != "candidate_token"},
        "candidate_token": token,
        "started_at": utcnow().isoformat(),
    }
    await session.flush()
    return row, token


async def run_image_regression(image_version_id: uuid.UUID) -> str | None:
    """Test one proposal; returns the final ``regression_result`` (None when there was nothing to do)."""
    async with session_scope() as session:
        begun = await _begin(session, image_version_id)
        if begun is None:
            log.info("image_regression_nothing_to_do", image_version_id=str(image_version_id))
            return None
        row, token = begun
        tool, digest, scope = row.tool, row.digest, str((row.regression_detail or {}).get("scope") or "")
        job_tool = regression_job_for(tool, scope)
        if job_tool is None:
            row.regression_result = "skipped"
            row.regression_detail = finished_detail(
                row.regression_detail, None, "No regression expectations exist for this image."
            )
            return "skipped"
    mapping = REGRESSION_TOOLS[tool]
    report: RegressionReport | None = None
    note: str | None = None
    result = "error"
    try:
        report = await run_regression(
            "image",
            tools=[mapping[1]],
            candidates={tool: CandidateImage(tool, str(image_version_id), token, digest)},
        )
        result = result_for_report(report)
    except Exception as exc:  # noqa: BLE001 - the gate must end in a stored result, never in a stuck "testing"
        log.warning("image_regression_crashed", image_version_id=str(image_version_id), error=type(exc).__name__)
        note = "The regression run could not be completed (%s). Run it again from Settings." % type(exc).__name__
    async with session_scope() as session:
        row = await session.get(ImageVersion, image_version_id)
        if row is None:
            return None
        row.regression_result = result
        row.regression_detail = finished_detail(row.regression_detail, report, note)
        await record_audit(
            session, SYSTEM_ACTOR, "image.regression", "image_version", row.id,
            {"tool": row.tool, "tag": row.tag, "digest": row.digest, "result": result},
        )  # fmt: skip
    log.info("image_regression_done", image_version_id=str(image_version_id), tool=tool, result=result)
    return result


@app.task(
    name="image_regression",
    queue="maintenance",
    retry=RetryStrategy(max_attempts=2, wait=300),
)
async def image_regression(image_version_id: str) -> None:
    """Regression-test the image proposal ``image_version_id`` (a row of ``image_versions``)."""
    await run_image_regression(uuid.UUID(image_version_id))
