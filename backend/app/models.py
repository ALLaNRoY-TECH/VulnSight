"""Core data structures shared by every scanner module."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["fail", "warn", "pass", "info"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_PENALTY = {"critical": 25, "high": 14, "medium": 7, "low": 2, "info": 0}

MODULES = ("headers", "tls", "ports", "exposure", "dns")


class Finding(BaseModel):
    id: str
    module: str
    title: str
    status: Status
    severity: Severity = "info"
    description: str = ""
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


def finding(
    id: str,
    module: str,
    title: str,
    status: Status,
    severity: Severity = "info",
    description: str = "",
    evidence: Any = None,
    remediation: str | None = None,
    references: list[str] | None = None,
) -> Finding:
    if status == "pass":
        severity = "info"
    return Finding(
        id=id,
        module=module,
        title=title,
        status=status,
        severity=severity,
        description=description,
        evidence=None if evidence is None else str(evidence)[:1200],
        remediation=remediation,
        references=references or [],
    )


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=300)
    modules: list[str] = Field(default_factory=lambda: list(MODULES))
    authorized: bool = Field(
        False, description="Caller confirms they own or are authorised to test the target."
    )
