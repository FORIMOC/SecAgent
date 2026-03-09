from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CVEConstraint:
    cve_id: str
    cwe_ids: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    repo_url: str = ""
    language: str = ""
    target_files: list[str] = field(default_factory=list)
    patch_old_lines: list[str] = field(default_factory=list)
    patch_new_lines: list[str] = field(default_factory=list)
    patch_focus_variables: list[str] = field(default_factory=list)
    advisory_summary: str = ""
    advisory_refs: list[str] = field(default_factory=list)
    vulnerability_hint: str = "generic"
    checkout_ref: str = ""


@dataclass
class FlowEvidence:
    file_path: str
    source_line: int | None
    source_code: str | None
    sink_line: int | None
    sink_code: str | None
    context: list[str] = field(default_factory=list)
    source_to_sink_path: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DirectedFinding:
    cve_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    source: str | None
    sink: str | None
    suggestion: str
    confidence: float
    verdict: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source_to_sink_path: list[dict[str, Any]] | None = None


@dataclass
class PipelineResult:
    findings: list[DirectedFinding]
    summary: dict[str, Any]
