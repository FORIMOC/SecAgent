from __future__ import annotations

from typing import Any

from .models import DirectedFinding, PipelineResult


def _desc_for_node(node_type: str, code: str) -> str:
    code = (code or "").strip()
    if not code:
        return f"{node_type} node"
    if node_type == "Source":
        return f"用户可控数据在此进入: {code[:120]}"
    if node_type == "Sink":
        return f"危险操作在此触发: {code[:120]}"
    return f"污点在此传播/转换: {code[:120]}"


def _to_nodes(f: DirectedFinding) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    file_path = f.file_path or ""
    for n in (f.source_to_sink_path or []):
        kind = str(n.get("kind") or "").lower()
        ntype = "Propagation"
        if kind == "source":
            ntype = "Source"
        elif kind == "sink":
            ntype = "Sink"
        start_line = n.get("start_line", n.get("line"))
        end_line = n.get("end_line", start_line)
        try:
            start_line = int(start_line) if start_line is not None else 0
        except Exception:
            start_line = 0
        try:
            end_line = int(end_line) if end_line is not None else start_line
        except Exception:
            end_line = start_line
        code = str(n.get("code") or "").strip()
        node_file = str(n.get("file_path") or n.get("File") or file_path).strip()
        nodes.append(
            {
                "Type": ntype,
                "File": node_file,
                "StartLine": start_line,
                "EndLine": end_line,
                "Desc": _desc_for_node(ntype, code),
                "code": code,
            }
        )
    return nodes


def _to_issue(f: DirectedFinding) -> dict[str, Any]:
    return {
        "CVEID": f.cve_id,
        "type": f.vulnerability_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "Nodes": _to_nodes(f),
        "confidence": f.confidence,
        "verdict": f.verdict,
        "ai_explanation": (
            (f.evidence or {}).get("verification_details")
            or "CVE定向审计生成的 source->sink 证据路径。"
        ),
    }


def result_to_deepaudit_dict(result: PipelineResult) -> dict[str, Any]:
    issues = [_to_issue(f) for f in result.findings]
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        s = str(i.get("severity", "low")).lower()
        if s not in severities:
            s = "low"
        severities[s] += 1

    quality_score = max(
        0.0,
        100.0 - (
            severities["critical"] * 20
            + severities["high"] * 8
            + severities["medium"] * 3
            + severities["low"] * 1
        ),
    )

    return {
        "issues": issues,
        "quality_score": round(quality_score, 1),
        "issues_count": len(issues),
        "severity_summary": severities,
        "summary": result.summary,
    }
