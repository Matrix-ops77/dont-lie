"""Lightweight CRM lead pipe.

Models a tiny in-memory CRM with leads, status, and notes. The same
shape is what's POSTed to /api/leads from the landing page. Operators
can read, score, and route; this is the data layer for the outreach
funnel.

Lead lifecycle
==============

- ``new`` — captured from the site or manual entry.
- ``qualified`` — confirmed an active AI incident.
- ``piloting`` — design partner or paid pilot.
- ``won`` — converted.
- ``lost`` — disqualified.

Scores
======

- ``hot``  — 70+ (active incident, named budget)
- ``warm`` — 40–69 (curious, no incident)
- ``cold`` — < 40 (bookmark, no engagement)
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATUSES = ("new", "qualified", "piloting", "won", "lost")


class CRMPipelineError(Exception):
    """Raised for invalid lead operations."""


@dataclass
class Lead:
    lead_id: str
    email: str
    company: str = ""
    status: str = "new"
    score: int = 0
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def grade(self) -> str:
        if self.score >= 70:
            return "hot"
        if self.score >= 40:
            return "warm"
        return "cold"

    def to_dict(self) -> dict:
        return {
            "lead_id": self.lead_id,
            "email": self.email,
            "company": self.company,
            "status": self.status,
            "score": self.score,
            "grade": self.grade(),
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CRMPipeline:
    """In-memory lead pipeline with optional disk persistence."""

    def __init__(self) -> None:
        self.leads: dict[str, Lead] = {}

    def add(
        self,
        email: str,
        company: str = "",
        *,
        score: int = 0,
        notes: str = "",
        status: str = "new",
    ) -> Lead:
        if not email:
            raise CRMPipelineError("email is required")
        if "@" not in email:
            raise CRMPipelineError(f"invalid email: {email!r}")
        if status not in STATUSES:
            raise CRMPipelineError(f"invalid status: {status!r}")
        for lead in self.leads.values():
            if lead.email.lower() == email.lower():
                lead.company = company or lead.company
                lead.score = max(lead.score, score)
                lead.notes = (lead.notes + "\n" + notes).strip() if notes else lead.notes
                lead.updated_at = datetime.now(timezone.utc).isoformat()
                return lead
        lead = Lead(
            lead_id=uuid.uuid4().hex[:12],
            email=email,
            company=company,
            score=score,
            notes=notes,
            status=status,
        )
        self.leads[lead.lead_id] = lead
        return lead

    def update(self, lead_id: str, **fields: object) -> Lead:
        lead = self.leads.get(lead_id)
        if not lead:
            raise CRMPipelineError(f"unknown lead: {lead_id}")
        for key, value in fields.items():
            if not hasattr(lead, key):
                raise CRMPipelineError(f"unknown field: {key}")
            if key == "status" and value not in STATUSES:
                raise CRMPipelineError(f"invalid status: {value!r}")
            setattr(lead, key, value)
        lead.updated_at = datetime.now(timezone.utc).isoformat()
        return lead

    def by_status(self, status: str) -> list[Lead]:
        if status not in STATUSES:
            raise CRMPipelineError(f"invalid status: {status!r}")
        return [lead for lead in self.leads.values() if lead.status == status]

    def hot(self) -> list[Lead]:
        return [lead for lead in self.leads.values() if lead.grade() == "hot"]

    def count(self) -> dict[str, int]:
        counts = {status: 0 for status in STATUSES}
        for lead in self.leads.values():
            counts[lead.status] += 1
        return counts


def persistence_path() -> Path:
    config = os.environ.get("DONTLIE_CRM_PATH", "leads.jsonl")
    return Path(config)


def save(crm: CRMPipeline, path: Path | None = None) -> None:
    path = path or persistence_path()
    with path.open("w", encoding="utf-8") as handle:
        for lead in crm.leads.values():
            handle.write(json.dumps(lead.to_dict()) + "\n")


def load(path: Path | None = None) -> CRMPipeline:
    path = path or persistence_path()
    crm = CRMPipeline()
    if not path.exists():
        return crm
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        lead = Lead(
            lead_id=record["lead_id"],
            email=record["email"],
            company=record.get("company", ""),
            score=record.get("score", 0),
            notes=record.get("notes", ""),
            status=record.get("status", "new"),
            created_at=record.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=record.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )
        crm.leads[lead.lead_id] = lead
    return crm


__all__ = [
    "STATUSES",
    "CRMPipeline",
    "CRMPipelineError",
    "Lead",
    "load",
    "persistence_path",
    "save",
]
