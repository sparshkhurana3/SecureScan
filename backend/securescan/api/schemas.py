"""Shared request and response building blocks for the API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Criticality = Literal["low", "medium", "high", "critical"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]
RiskTier = Literal["low", "medium", "high", "critical"]
Hosting = Literal["deployable", "saas"]
LabelKind = Literal["branch", "tag", "upload", "image_digest", "release"]

CRITICALITIES = ("low", "medium", "high", "critical")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


class ORMModel(BaseModel):
    """Base of response models built from ORM rows (``Model.model_validate(row)``)."""

    model_config = ConfigDict(from_attributes=True)


class BlackoutWindow(BaseModel):
    """A period in which scans must not start: one-off (``starts_at``/``ends_at``, UTC) or weekly.

    Weekly windows give ``days`` (0 = Monday ... 6 = Sunday) and ``start``/``end`` as ``HH:MM`` UTC.
    """

    starts_at: datetime | None = None
    ends_at: datetime | None = None
    days: list[int] | None = Field(default=None, max_length=7)
    start: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    end: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    reason: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _one_kind(self) -> BlackoutWindow:
        one_off = self.starts_at is not None or self.ends_at is not None
        weekly = self.days is not None or self.start is not None or self.end is not None
        if one_off == weekly:
            raise ValueError("give either starts_at and ends_at, or days with start and end")
        if one_off and (self.starts_at is None or self.ends_at is None or self.ends_at <= self.starts_at):
            raise ValueError("ends_at must be after starts_at")
        if weekly:
            if not self.days or self.start is None or self.end is None:
                raise ValueError("a weekly window needs days, start and end")
            if any(d < 0 or d > 6 for d in self.days):
                raise ValueError("days are 0 (Monday) to 6 (Sunday)")
        return self
