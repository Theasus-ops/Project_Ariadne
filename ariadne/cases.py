"""Case management and evidence packaging for investigations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import EvidenceSigner


class InvestigationCase:
    """A lightweight case container for analyst workflows."""

    def __init__(self, case_id: str, title: str, investigator: str = "operator") -> None:
        self.case_id = case_id
        self.title = title
        self.investigator = investigator
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.notes: list[str] = []
        self.evidence: list[dict[str, Any]] = []
        self.tags: list[str] = []
        self.timeline: list[dict[str, Any]] = []

    def add_note(self, note: str) -> None:
        self.notes.append(note)
        self.timeline.append({"timestamp": datetime.now(timezone.utc).isoformat(), "type": "note", "detail": note})
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, evidence: dict[str, Any]) -> None:
        self.evidence.append(evidence)
        self.timeline.append({"timestamp": datetime.now(timezone.utc).isoformat(), "type": "evidence", "detail": evidence})
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_tag(self, tag: str) -> None:
        self.tags.append(tag)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "investigator": self.investigator,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "notes": self.notes,
            "evidence": self.evidence,
            "tags": self.tags,
            "timeline": self.timeline,
        }


class CaseStore:
    """Simple JSON-backed case store for local deployments."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else Path("reports/cases.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def list_cases(self) -> list[dict[str, Any]]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def save_case(self, case: InvestigationCase) -> dict[str, Any]:
        cases = self.list_cases()
        cases = [c for c in cases if c.get("case_id") != case.case_id]
        cases.append(case.as_dict())
        self.path.write_text(json.dumps(cases, indent=2), encoding="utf-8")
        return case.as_dict()

    def load_case(self, case_id: str) -> dict[str, Any] | None:
        for case in self.list_cases():
            if case.get("case_id") == case_id:
                return case
        return None

    def export_bundle(self, case_id: str, outdir: str | Path | None = None) -> Path:
        case = self.load_case(case_id)
        if case is None:
            raise FileNotFoundError(case_id)
        outdir = Path(outdir) if outdir is not None else Path("reports/evidence")
        outdir.mkdir(parents=True, exist_ok=True)
        payload = {
            "case": case,
            "evidence_bundle": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": case.get("title", "Untitled case"),
                "notes": case.get("notes", []),
                "evidence": case.get("evidence", []),
                "timeline": case.get("timeline", []),
            },
        }
        payload["signature"] = EvidenceSigner.sign(payload)
        bundle_path = outdir / f"{case_id}.json"
        bundle_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return bundle_path
