from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TextIO

from .deepaudit_adapter import result_to_deepaudit_dict
from .pipeline import run_pipeline, run_pipeline_from_constraints
from .cve_parser import parse_cve_file
from .models import PipelineResult
from .agent_runner import run_verifier_only


DEFAULT_RESULT_OUT = "data/result/result.json"
DEFAULT_EVIDENCE_OUT = "data/result/evidence.json"


class GroupedThoughtLog:
    _CVE_RE = re.compile(r"^\[THOUGHT\]\[CVE=([^\]]+)\]")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_cve: dict[str, list[str]] = {}
        self._misc: list[str] = []
        self._order: list[str] = []

    def set_order(self, cve_ids: list[str]) -> None:
        with self._lock:
            self._order = [str(x).strip() for x in cve_ids if str(x).strip()]

    def add_line(self, line: str) -> None:
        m = self._CVE_RE.match(line)
        with self._lock:
            if not m:
                self._misc.append(line)
                return
            cve = m.group(1).strip() or "-"
            self._by_cve.setdefault(cve, []).append(line)

    def dump(self, out: TextIO) -> None:
        with self._lock:
            seen: set[str] = set()
            for cve in self._order:
                lines = self._by_cve.get(cve, [])
                if not lines:
                    continue
                seen.add(cve)
                out.write(f"===== {cve} =====\n")
                for ln in lines:
                    out.write(ln)
                out.write("\n")
            for cve in sorted(self._by_cve.keys()):
                if cve in seen:
                    continue
                out.write(f"===== {cve} =====\n")
                for ln in self._by_cve[cve]:
                    out.write(ln)
                out.write("\n")
            for ln in self._misc:
                out.write(ln)


class TeeStream:
    def __init__(self, stream: TextIO, log_stream: TextIO, thought_only: bool = True, grouped: GroupedThoughtLog | None = None) -> None:
        self._stream = stream
        self._log_stream = log_stream
        self._thought_only = thought_only
        self._grouped = grouped
        self._line_buf = ""

    def _should_keep_line(self, line: str) -> bool:
        if not self._thought_only:
            return True
        return line.startswith("[THOUGHT][")

    def _write_log_filtered(self, data: str) -> None:
        chunk = self._line_buf + data
        lines = chunk.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._line_buf = lines.pop()
        else:
            self._line_buf = ""
        for line in lines:
            if self._should_keep_line(line):
                if self._grouped:
                    self._grouped.add_line(line)
                else:
                    self._log_stream.write(line)

    def write(self, data: str) -> int:
        written = self._stream.write(data)
        if self._thought_only:
            self._write_log_filtered(data)
        else:
            self._log_stream.write(data)
        self._log_stream.flush()
        return written

    def flush(self) -> None:
        if self._line_buf:
            if self._should_keep_line(self._line_buf):
                if self._grouped:
                    self._grouped.add_line(self._line_buf)
                else:
                    self._log_stream.write(self._line_buf)
            self._line_buf = ""
        self._stream.flush()
        self._log_stream.flush()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SecAgent: CVE-guided directed vulnerability finder")
    p.add_argument(
        "--cve",
        required=True,
        help="Path to CVE semantic JSON file (or existing result file when --verify-evidence is enabled)",
    )
    p.add_argument("--out", default=DEFAULT_RESULT_OUT, help="Output JSON file path, '-' for stdout")
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Parallel workers for CVE processing (also used by --verify-evidence)",
    )
    p.add_argument("--workspace-root", default=None, help="Workspace root for temporary git clones")
    p.add_argument(
        "--repo-cache-root",
        default=None,
        help="Global repository cache root (default: <project>/data/repos)",
    )
    p.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep cloned repositories in workspace for debugging",
    )
    p.add_argument(
        "--log-dir",
        default="data/log",
        help="Run log directory (default: data/log)",
    )
    p.add_argument(
        "--log-full",
        action="store_true",
        help="Write full stdout/stderr to run log (default: thought-only log)",
    )
    p.add_argument(
        "--no-resume",
        action="store_true",
        help="Disable checkpoint resume from existing --out file",
    )
    p.add_argument(
        "--verify-evidence",
        action="store_true",
        help=(
            "Verifier-only mode: treat --cve as existing result JSON, verify source-to-sink paths, "
            "and write merged compact result JSON (issues+summary) to --out"
        ),
    )
    return p


def _collect_completed_cveids(payload: dict) -> set[str]:
    done: set[str] = set()
    try:
        issues = _extract_issues_from_result_payload(payload)
    except Exception:
        issues = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        cve = str(issue.get("CVEID") or issue.get("cve_id") or "").strip()
        if cve:
            done.add(cve)
    return done


def _is_flat_path_issue(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if isinstance(item.get("Nodes"), list):
        return True
    if isinstance(item.get("source_to_sink_path"), list):
        return True
    if str(item.get("CVEID") or "").strip():
        return True
    return False


def _extract_path_issues_from_issue_entry(entry: Any) -> list[dict[str, Any]]:
    if not isinstance(entry, dict):
        return []
    if _is_flat_path_issue(entry):
        return [entry]

    out: list[dict[str, Any]] = []
    path_result = entry.get("path_result")
    if isinstance(path_result, dict):
        for key in ("findings", "issues", "paths"):
            raw = path_result.get(key)
            if isinstance(raw, list):
                out.extend([x for x in raw if _is_flat_path_issue(x)])
                break
    elif isinstance(path_result, list):
        out.extend([x for x in path_result if _is_flat_path_issue(x)])
    return out


def _merge_issues(old_issues: list[dict], new_issues: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    def _key(item: dict) -> tuple[str, str, str, str, str]:
        node_loc = ""
        nodes = item.get("Nodes")
        if isinstance(nodes, list) and nodes:
            first = nodes[0] if isinstance(nodes[0], dict) else {}
            node_loc = f"{first.get('File','')}:{first.get('StartLine','')}-{first.get('EndLine','')}"
        return (
            str(item.get("CVEID") or ""),
            str(item.get("type") or ""),
            node_loc,
            str(item.get("title") or ""),
            str(item.get("severity") or ""),
        )

    old_flat = [x for i in (old_issues or []) for x in _extract_path_issues_from_issue_entry(i)]
    new_flat = [x for i in (new_issues or []) for x in _extract_path_issues_from_issue_entry(i)]
    for src in old_flat + new_flat:
        if not isinstance(src, dict):
            continue
        k = _key(src)
        if k in seen:
            continue
        seen.add(k)
        merged.append(src)
    return merged


def _build_payload_from_issues(issues: list[dict], summary: dict) -> dict:
    return _build_compact_payload(
        result_payload={"issues": [x for x in (issues or []) if isinstance(x, dict)], "summary": summary or {}},
        evidence_payload=None,
        strip_path_evidence=False,
    )


def _issue_from_finding(finding) -> dict | None:
    try:
        payload = result_to_deepaudit_dict(PipelineResult(findings=[finding], summary={}))
        issues = payload.get("issues", [])
        if isinstance(issues, list) and issues:
            return issues[0]
    except Exception:
        return None
    return None


def _raise_fd_limit(target_soft: int = 8192) -> tuple[int | None, int | None]:
    try:
        import resource
    except Exception:
        return None, None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < target_soft:
            new_soft = min(hard, target_soft)
            if new_soft > soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
                soft = new_soft
        return soft, hard
    except Exception:
        return None, None


def _safe_int(v: Any) -> int | None:
    try:
        if v is None:
            return None
        return int(v)
    except Exception:
        return None


def _safe_float(v: Any, default: float = 0.5) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _to_repo_relative_path(repo_root: Path | None, file_path: str) -> str:
    p = str(file_path or "").strip()
    if not p:
        return ""
    p = p.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    if repo_root is None:
        return p
    pp = Path(p)
    if pp.is_absolute():
        try:
            rel = pp.resolve().relative_to(repo_root.resolve())
            return str(rel).replace("\\", "/")
        except Exception:
            return p
    return p


def _read_repo_code_range(repo_root: Path, file_path: str, start_line: int, end_line: int) -> str:
    if not file_path or start_line <= 0 or end_line <= 0 or end_line < start_line:
        return ""
    try:
        full = (repo_root / file_path).resolve()
        if not str(full).startswith(str(repo_root.resolve())):
            return ""
        if not full.is_file():
            return ""
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(1, start_line)
        e = min(len(lines), end_line)
        if s > e:
            return ""
        return "\n".join(lines[s - 1:e]).strip()[:2000]
    except Exception:
        return ""


def _extract_code_from_desc(desc: str) -> str:
    text = str(desc or "").strip()
    if not text:
        return ""
    if ":" in text:
        tail = text.split(":", 1)[1].strip()
        if tail:
            return tail
    return text


def _normalize_node_kind(value: str) -> str:
    t = str(value or "").strip().lower()
    if t in {"source", "sink", "propagation"}:
        return t
    if t in {"src"}:
        return "source"
    if t in {"dst"}:
        return "sink"
    return "propagation"


def _normalize_issue_nodes(issue: dict, repo_root: Path | None) -> list[dict[str, Any]]:
    raw_nodes = issue.get("Nodes")
    if not isinstance(raw_nodes, list):
        raw_nodes = issue.get("source_to_sink_path")
    if not isinstance(raw_nodes, list):
        return []

    fallback_file = _to_repo_relative_path(repo_root, str(issue.get("file_path") or ""))
    out: list[dict[str, Any]] = []
    for node in raw_nodes:
        if not isinstance(node, dict):
            continue
        file_path = _to_repo_relative_path(
            repo_root,
            str(node.get("file_path") or node.get("File") or fallback_file),
        )
        start_line = _safe_int(node.get("start_line", node.get("StartLine")))
        if start_line is None:
            start_line = _safe_int(node.get("line"))
        end_line = _safe_int(node.get("end_line", node.get("EndLine")))
        if end_line is None:
            end_line = start_line
        if start_line is None or start_line <= 0:
            continue
        if end_line is None or end_line < start_line:
            end_line = start_line

        code = str(node.get("code") or "").strip()
        if not code:
            code = _extract_code_from_desc(str(node.get("Desc") or node.get("description") or ""))
        if not code and file_path and repo_root is not None:
            code = _read_repo_code_range(repo_root, file_path, start_line, end_line)
        if not code:
            continue

        kind = _normalize_node_kind(str(node.get("kind") or node.get("Type") or ""))
        out.append(
            {
                "kind": kind,
                "file_path": file_path,
                "line": start_line,
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
                "Type": "Source" if kind == "source" else ("Sink" if kind == "sink" else "Propagation"),
                "File": file_path,
                "StartLine": start_line,
                "EndLine": end_line,
            }
        )
    return out


def _issue_to_verification_finding(
    issue: dict,
    issue_index: int,
    repo_root: Path | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(issue, dict):
        return None, "issue is not object"

    nodes = _normalize_issue_nodes(issue, repo_root)
    if not nodes:
        return None, "missing valid Nodes/source_to_sink_path with resolvable code"

    file_path = _to_repo_relative_path(repo_root, str(issue.get("file_path") or ""))
    if not file_path:
        file_path = str(nodes[0].get("file_path") or "")
    if not file_path:
        return None, "missing file_path"

    source_line = None
    sink_line = None
    source_code = ""
    sink_code = ""
    for n in nodes:
        kind = str(n.get("kind") or "").lower()
        if kind == "source" and source_line is None:
            source_line = _safe_int(n.get("start_line") or n.get("line"))
            source_code = str(n.get("code") or "")
        if kind == "sink":
            sink_line = _safe_int(n.get("start_line") or n.get("line")) or sink_line
            sink_code = str(n.get("code") or sink_code)

    line_start = _safe_int(issue.get("line_start")) or source_line or _safe_int(nodes[0].get("start_line")) or 1
    line_end = _safe_int(issue.get("line_end")) or sink_line or _safe_int(nodes[-1].get("end_line")) or line_start
    if line_end < line_start:
        line_end = line_start

    ai_explanation = str(issue.get("ai_explanation") or "").strip()
    verification_details = str(issue.get("verification_details") or "").strip()
    verification_method = str(issue.get("verification_method") or "").strip()
    poc = issue.get("poc") if isinstance(issue.get("poc"), dict) else {}
    is_verified = bool(issue.get("is_verified"))
    if ai_explanation and not verification_details:
        verification_details = ai_explanation
    if ai_explanation and not verification_method:
        verification_method = "path_result_ai_explanation"

    return (
        {
            "_origin_issue_index": issue_index,
            "cve_id": str(issue.get("CVEID") or issue.get("cve_id") or "UNKNOWN"),
            "vulnerability_type": str(issue.get("type") or issue.get("vulnerability_type") or "generic"),
            "severity": str(issue.get("severity") or "medium"),
            "title": str(issue.get("title") or f"Issue#{issue_index}"),
            "description": str(issue.get("description") or ""),
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "source": source_code or None,
            "sink": sink_code or None,
            "code_snippet": str(issue.get("code_snippet") or ""),
            "source_to_sink_path": nodes,
            "confidence": _safe_float(issue.get("confidence"), 0.5),
            "verdict": str(issue.get("verdict") or "uncertain"),
            "is_verified": is_verified,
            "needs_verification": True,
            "ai_explanation": ai_explanation,
            "verification_method": verification_method,
            "verification_details": verification_details,
            "poc": poc,
        },
        None,
    )


def _extract_issues_from_result_payload(payload: Any) -> list[Any]:
    issues: list[Any]
    if isinstance(payload, dict):
        issues = payload.get("issues", [])
    elif isinstance(payload, list):
        issues = payload
    else:
        raise ValueError("Result payload must be a JSON object with `issues` or a JSON array")

    if not isinstance(issues, list):
        raise ValueError("`issues` must be a JSON array")

    out: list[dict[str, Any]] = []
    for item in issues:
        out.extend(_extract_path_issues_from_issue_entry(item))
    return out


def _normalize_cve_id(value: Any) -> str:
    cve_id = str(value or "").strip()
    return cve_id if cve_id else "UNKNOWN"


def _collect_cveids_from_result_payload(payload: Any) -> set[str]:
    cve_ids: set[str] = set()
    if isinstance(payload, dict):
        raw_issues = payload.get("issues", [])
        if isinstance(raw_issues, list):
            for entry in raw_issues:
                if not isinstance(entry, dict):
                    continue
                cid = _normalize_cve_id(entry.get("cve_id") or entry.get("CVEID"))
                if cid != "UNKNOWN":
                    cve_ids.add(cid)
    try:
        issues = _extract_issues_from_result_payload(payload)
    except Exception:
        return cve_ids

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        cve_id = _normalize_cve_id(issue.get("CVEID") or issue.get("cve_id"))
        if cve_id != "UNKNOWN":
            cve_ids.add(cve_id)
    return cve_ids


def _load_findings_from_result_payload(
    payload: Any,
    repo_root: Path | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues = _extract_issues_from_result_payload(payload)

    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for idx, issue in enumerate(issues, start=1):
        finding, reason = _issue_to_verification_finding(issue, idx, repo_root)
        if finding:
            findings.append(finding)
            continue
        issue_obj = issue if isinstance(issue, dict) else {}
        skipped.append(
            {
                "issue_index": idx,
                "cve_id": str(issue_obj.get("CVEID") or issue_obj.get("cve_id") or "UNKNOWN"),
                "reason": reason or "unknown",
            }
        )
    return findings, skipped


def _fallback_verified_findings(findings: list[dict[str, Any]], details: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        out.append(
            {
                **f,
                "verdict": "uncertain",
                "is_verified": False,
                "verification_method": "verify_only_fallback",
                "verification_details": details,
                "confidence": _safe_float(f.get("confidence"), 0.5),
            }
        )
    return out


def _repo_cache_key(repo_url: str) -> str:
    import hashlib

    digest = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:16]
    tail = repo_url.rstrip("/").split("/")[-1] or "repo"
    if tail.endswith(".git"):
        tail = tail[:-4]
    safe_tail = "".join(ch if ch.isalnum() or ch in {"_", "-", "."} else "_" for ch in tail)
    return f"{safe_tail}_{digest}"


def _load_cve_repo_meta(cve_ids: set[str], project_root: Path) -> dict[str, dict[str, str]]:
    """
    从 data/input 中提取 CVE -> {repo_url, checkout_ref} 元数据。
    """
    if not cve_ids:
        return {}
    input_root = project_root / "data" / "input"
    if not input_root.is_dir():
        return {}

    mapping: dict[str, dict[str, str]] = {}
    for fp in sorted(input_root.rglob("*.json")):
        try:
            constraints = parse_cve_file(fp)
        except Exception:
            continue
        for c in constraints:
            cid = str(getattr(c, "cve_id", "") or "").strip()
            if not cid or cid not in cve_ids:
                continue
            repo_url = str(getattr(c, "repo_url", "") or "").strip()
            checkout_ref = str(getattr(c, "checkout_ref", "") or "").strip()
            prev = mapping.get(cid, {})
            merged = {
                "repo_url": repo_url or str(prev.get("repo_url") or ""),
                "checkout_ref": checkout_ref or str(prev.get("checkout_ref") or ""),
            }
            mapping[cid] = merged
        if len(mapping) >= len(cve_ids):
            # 若都已命中且字段齐全，提前结束
            if all(
                str(mapping.get(cid, {}).get("repo_url") or "").strip()
                and str(mapping.get(cid, {}).get("checkout_ref") or "").strip()
                for cid in cve_ids
            ):
                break
    return mapping


def _normalize_compact_code(s: str) -> str:
    return re.sub(r"\s+", "", (s or "")).strip().lower()


def _code_tokens(s: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", s or "") if len(t) >= 2}


def _is_code_related_weak(submitted: str, real: str) -> bool:
    ns = _normalize_compact_code(submitted)
    nr = _normalize_compact_code(real)
    if not ns or not nr:
        return False
    if ns in nr or nr in ns:
        return True
    ts = _code_tokens(submitted)
    tr = _code_tokens(real)
    if ts and tr:
        inter = len(ts & tr)
        union = len(ts | tr)
        if union > 0 and (inter / union) >= 0.2:
            return True
        if inter >= 2:
            return True
    return False


def _read_repo_range_fast(repo_root: Path, file_path: str, start_line: int, end_line: int) -> str:
    try:
        full = (repo_root / file_path).resolve()
        if not str(full).startswith(str(repo_root.resolve())) or not full.is_file():
            return ""
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(1, int(start_line))
        e = min(len(lines), int(end_line))
        if s > e:
            return ""
        return "\n".join(lines[s - 1:e]).strip()
    except Exception:
        return ""


def _resolve_repo_from_cache_by_nodes(
    finding: dict[str, Any],
    repo_cache_root: Path,
) -> tuple[Path | None, str | None]:
    nodes = finding.get("source_to_sink_path")
    if not isinstance(nodes, list):
        return None, None
    probe_file = ""
    for n in nodes:
        if not isinstance(n, dict):
            continue
        probe_file = str(n.get("file_path") or n.get("File") or "").strip()
        if probe_file:
            break
    if not probe_file:
        probe_file = str(finding.get("file_path") or "").strip()
    if not probe_file:
        return None, None

    candidates: list[Path] = []
    for d in repo_cache_root.iterdir():
        if not d.is_dir():
            continue
        if (d / probe_file).is_file():
            candidates.append(d)

    if not candidates:
        return None, None
    if len(candidates) == 1:
        return candidates[0], "cache_path_unique"

    scored: list[tuple[int, Path]] = []
    sample_nodes = [n for n in nodes if isinstance(n, dict)][:4]
    for repo_dir in candidates:
        score = 0
        for n in sample_nodes:
            fp = str(n.get("file_path") or n.get("File") or probe_file).strip()
            if not fp:
                continue
            full = repo_dir / fp
            if not full.is_file():
                continue
            score += 1
            sl = _safe_int(n.get("start_line", n.get("StartLine")))
            if sl is None:
                sl = _safe_int(n.get("line"))
            el = _safe_int(n.get("end_line", n.get("EndLine")))
            if el is None:
                el = sl
            code = str(n.get("code") or "").strip()
            if sl and el and code:
                real = _read_repo_range_fast(repo_dir, fp, sl, el)
                if real and _is_code_related_weak(code, real):
                    score += 3
        scored.append((score, repo_dir))

    scored.sort(key=lambda x: x[0], reverse=True)
    if not scored or scored[0][0] <= 0:
        return None, None
    if len(scored) >= 2 and scored[0][0] == scored[1][0]:
        return None, None
    return scored[0][1], "cache_path_scored"


def _resolve_cached_repo_for_finding(
    finding: dict[str, Any],
    repo_cache_root: Path,
    cve_repo_urls: dict[str, str],
) -> tuple[Path | None, str]:
    cve_id = str(finding.get("cve_id") or "").strip()
    if cve_id and cve_id in cve_repo_urls:
        repo_url = cve_repo_urls[cve_id]
        candidate = repo_cache_root / _repo_cache_key(repo_url)
        if candidate.is_dir() and (candidate / ".git").exists():
            return candidate, "cve_repo_url_cache_key"
        if candidate.is_dir():
            return candidate, "cve_repo_url_cache_key_no_git"

    auto_repo, reason = _resolve_repo_from_cache_by_nodes(finding, repo_cache_root)
    if auto_repo:
        return auto_repo, reason or "cache_path_auto"
    return None, "repo_not_found_in_cache"


def _trim_text(value: Any, max_len: int = 2000) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    overflow = len(text) - max_len
    return text[:max_len] + f"...(truncated {overflow} chars)"


def _collect_path_check_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    # NOTE:
    # source_to_sink_path 的严格代码/行号校验已在主流程提交阶段完成。
    # evidence 聚合阶段不再重复读取仓库做二次对齐，以避免 cache/workspace 差异导致噪声漂移。
    nodes = finding.get("source_to_sink_path")
    total_nodes = len([n for n in (nodes or []) if isinstance(n, dict)]) if isinstance(nodes, list) else 0
    return {
        "result": "skipped_prevalidated",
        "reason": "path node checks are skipped in evidence stage; upstream submission validation is authoritative",
        "node_check_summary": {
            "total_nodes": total_nodes,
            "matched_nodes": 0,
            "mismatched_nodes": 0,
            "missing_file_nodes": 0,
            "unreadable_nodes": 0,
            "skipped_nodes": total_nodes,
        },
        "checks": [],
    }


def _collect_verifier_proof(finding: dict[str, Any]) -> dict[str, Any]:
    method = _trim_text(finding.get("verification_method"), max_len=400)
    ai_explanation = _trim_text(finding.get("ai_explanation"), max_len=8000)
    verifier_details = _trim_text(finding.get("verification_details"), max_len=4000)
    analysis = ai_explanation or verifier_details
    if ai_explanation:
        if not method:
            method = "analysis_ai_explanation"
    poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
    poc_description = _trim_text(poc.get("description"), max_len=400)
    poc_payload = _trim_text(poc.get("payload"), max_len=2500)
    harness_code = _trim_text(poc.get("harness_code"), max_len=2500)
    poc_steps = [
        _trim_text(step, max_len=300)
        for step in (poc.get("steps") if isinstance(poc.get("steps"), list) else [])
        if str(step or "").strip()
    ][:10]

    has_dynamic = bool(poc_payload or harness_code or poc_steps)
    has_static = bool(method or analysis)
    if has_dynamic and has_static:
        proof_type = "mixed"
    elif has_dynamic:
        proof_type = "dynamic"
    elif has_static:
        proof_type = "static_analysis"
    else:
        proof_type = "none"

    poc_out: dict[str, Any] = {}
    if poc_description:
        poc_out["description"] = poc_description
    if poc_steps:
        poc_out["steps"] = poc_steps
    if poc_payload:
        poc_out["payload"] = poc_payload
    if harness_code:
        poc_out["harness_code"] = harness_code

    out = {
        "proof_type": proof_type,
        "analysis": analysis,
        "method": method,
        "poc": poc_out,
    }
    return out


def _derive_path_claim_status(
    verifier_verdict: str,
    path_check_result: str,
    proof_type: str,
) -> tuple[str, str]:
    verdict = str(verifier_verdict or "uncertain").strip().lower()
    path_result = str(path_check_result or "inconclusive").strip().lower()
    ptype = str(proof_type or "none").strip().lower()

    if verdict == "false_positive":
        return "false", "verifier verdict is false_positive"
    if path_result == "refuted":
        return "false", "repository node checks refute the submitted source-to-sink path"
    if path_result in {"supported", "skipped_prevalidated"} and verdict in {"confirmed", "likely"}:
        if path_result == "supported":
            return "true", "verifier verdict and repository node checks both support the path"
        return "true", "verifier supports a path that was already validated during mainflow submission"
    if verdict in {"confirmed", "likely"} and ptype in {"dynamic", "mixed"}:
        return "true", "verifier provided dynamic evidence (PoC/harness/payload)"
    if verdict == "uncertain":
        return "inconclusive", "verifier verdict is uncertain"
    if path_result in {"partial", "supported", "skipped_prevalidated"}:
        return "inconclusive", "path checks are not strong enough to conclude true/false"
    return "inconclusive", "insufficient or conflicting evidence"


def _build_evidence_item(finding: dict[str, Any]) -> dict[str, Any]:
    verifier_verdict = str(finding.get("verdict") or "uncertain")
    verifier_confidence = _safe_float(finding.get("confidence"), 0.5)
    is_verified = bool(finding.get("is_verified")) or verifier_verdict in {"confirmed", "likely"}

    path_checks = _collect_path_check_evidence(finding)
    verifier_proof = _collect_verifier_proof(finding)
    claim_status, claim_reason = _derive_path_claim_status(
        verifier_verdict=verifier_verdict,
        path_check_result=str(path_checks.get("result") or "inconclusive"),
        proof_type=str(verifier_proof.get("proof_type") or "none"),
    )

    evidence = {
        "type": verifier_proof.get("proof_type"),
        "analysis": verifier_proof.get("analysis"),
    }
    method = _trim_text(verifier_proof.get("method"), max_len=400)
    if method and method != evidence.get("analysis"):
        evidence["method"] = method
    poc = verifier_proof.get("poc")
    if isinstance(poc, dict) and poc:
        evidence["poc"] = poc
    if not evidence.get("analysis"):
        evidence.pop("analysis", None)

    return {
        "issue_index": _safe_int(finding.get("_origin_issue_index")),
        "source_to_sink_claim": {
            "status": claim_status,  # true / false / inconclusive
            "reason": claim_reason,
        },
        "verifier_judgement": {
            "verdict": verifier_verdict,
            "confidence": verifier_confidence,
            "is_verified": is_verified,
            "verified_at": finding.get("verified_at"),
        },
        "evidence": evidence,
    }


def _sanitize_evidence_item(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    out = dict(item)
    proof = out.get("proof") if isinstance(out.get("proof"), dict) else {}
    evidence_in = out.get("evidence") if isinstance(out.get("evidence"), dict) else {}
    artifacts = proof.get("artifacts") if isinstance(proof.get("artifacts"), dict) else {}
    poc_in = evidence_in.get("poc")
    if not isinstance(poc_in, dict):
        poc_in = proof.get("poc")
    if not isinstance(poc_in, dict):
        poc_in = {}

    analysis = _trim_text(
        evidence_in.get("analysis")
        or evidence_in.get("primary_evidence")
        or evidence_in.get("details")
        or out.get("ai_explanation")
        or proof.get("analysis")
        or proof.get("primary_evidence")
        or proof.get("details")
        or artifacts.get("ai_explanation")
        or artifacts.get("verification_details"),
        max_len=8000,
    )
    method = _trim_text(
        evidence_in.get("method") or proof.get("method"),
        max_len=400,
    )
    evidence_type = str(
        evidence_in.get("type")
        or proof.get("type")
        or proof.get("proof_type")
        or "none"
    ).strip() or "none"

    poc_description = _trim_text(
        poc_in.get("description") or artifacts.get("poc_description"),
        max_len=400,
    )
    poc_payload = _trim_text(
        poc_in.get("payload") or artifacts.get("poc_payload"),
        max_len=2500,
    )
    harness_code = _trim_text(
        poc_in.get("harness_code") or artifacts.get("harness_code"),
        max_len=2500,
    )
    raw_steps = poc_in.get("steps")
    if not isinstance(raw_steps, list):
        raw_steps = artifacts.get("poc_steps")
    poc_steps = [
        _trim_text(step, max_len=300)
        for step in (raw_steps if isinstance(raw_steps, list) else [])
        if str(step or "").strip()
    ][:10]

    evidence_out: dict[str, Any] = {"type": evidence_type}
    if analysis:
        evidence_out["analysis"] = analysis
    if method and method != analysis:
        evidence_out["method"] = method
    poc_out: dict[str, Any] = {}
    if poc_description:
        poc_out["description"] = poc_description
    if poc_steps:
        poc_out["steps"] = poc_steps
    if poc_payload:
        poc_out["payload"] = poc_payload
    if harness_code:
        poc_out["harness_code"] = harness_code
    if poc_out:
        evidence_out["poc"] = poc_out

    # 不在结果文件中持久化 path_checks 与重复字段。
    out["evidence"] = evidence_out
    out.pop("ai_explanation", None)
    out.pop("proof", None)
    return out


def _new_evidence_summary() -> dict[str, Any]:
    return {
        "source_to_sink_claims": {"true": 0, "false": 0, "inconclusive": 0},
        "verifier_verdicts": {"confirmed": 0, "likely": 0, "uncertain": 0, "false_positive": 0},
        "total_evidence_items": 0,
    }


def _accumulate_evidence_summary(summary: dict[str, Any], evidence_item: dict[str, Any]) -> None:
    claim = evidence_item.get("source_to_sink_claim") if isinstance(evidence_item, dict) else {}
    status = str((claim or {}).get("status") or "inconclusive")
    if status not in summary["source_to_sink_claims"]:
        status = "inconclusive"
    summary["source_to_sink_claims"][status] += 1

    judgement = evidence_item.get("verifier_judgement") if isinstance(evidence_item, dict) else {}
    verdict = str((judgement or {}).get("verdict") or "uncertain")
    if verdict not in summary["verifier_verdicts"]:
        verdict = "uncertain"
    summary["verifier_verdicts"][verdict] += 1
    summary["total_evidence_items"] += 1


def _build_evidence_payload_from_groups(
    *,
    input_file: str,
    evidence_groups: list[dict[str, Any]],
    skipped_inputs: list[dict[str, Any]],
    batch_errors: list[str],
) -> dict[str, Any]:
    normalized_groups: list[dict[str, Any]] = []
    overall_summary = _new_evidence_summary()

    for group in evidence_groups:
        if not isinstance(group, dict):
            continue
        cve_id = _normalize_cve_id(group.get("cve_id"))
        raw_items = group.get("evidence_items")
        if not isinstance(raw_items, list):
            raw_items = []
        items = []
        for i in raw_items:
            normalized = _sanitize_evidence_item(i)
            if normalized is not None:
                items.append(normalized)
        items.sort(key=lambda x: (_safe_int(x.get("issue_index")) or 10**9))

        group_summary = _new_evidence_summary()
        for item in items:
            _accumulate_evidence_summary(group_summary, item)
            _accumulate_evidence_summary(overall_summary, item)

        normalized_groups.append(
            {
                "cve_id": cve_id,
                "summary": group_summary,
                "evidence_items": items,
            }
        )

    normalized_groups.sort(key=lambda x: x["cve_id"])
    total_processed = overall_summary["total_evidence_items"]
    return {
        "meta": {
            "mode": "verify_evidence_only",
            "generated_at": datetime.now().isoformat(),
            "input_result_file": input_file,
            "input_issues": total_processed + len(skipped_inputs),
            "processed_issues": total_processed,
            "skipped_issues": len(skipped_inputs),
            "errors": len(batch_errors),
        },
        "summary": {
            **overall_summary,
            "total_cves": len(normalized_groups),
        },
        "evidence": normalized_groups,
        "skipped_inputs": skipped_inputs,
        "batch_errors": batch_errors,
    }


def _extract_evidence_groups_from_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    grouped: dict[str, list[dict[str, Any]]] = {}

    # 兼容旧结构：顶层 evidence
    evidence = payload.get("evidence")
    if isinstance(evidence, list):
        for entry in evidence:
            if not isinstance(entry, dict):
                continue

            if isinstance(entry.get("evidence_items"), list):
                cve_id = _normalize_cve_id(entry.get("cve_id"))
                grouped.setdefault(cve_id, []).extend(
                    [i for i in (_sanitize_evidence_item(x) for x in entry.get("evidence_items", [])) if isinstance(i, dict)]
                )
                continue

            # 兼容旧格式：evidence 是扁平 item 列表，item 内包含 cve_id
            if "source_to_sink_claim" in entry and "verifier_judgement" in entry:
                cve_id = _normalize_cve_id(entry.get("cve_id"))
                normalized = _sanitize_evidence_item(entry)
                if normalized is not None:
                    grouped.setdefault(cve_id, []).append(normalized)

    # 新结构：issues[].evidence_result
    issues = payload.get("issues")
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            cve_id = _normalize_cve_id(issue.get("cve_id") or issue.get("CVEID"))
            e = issue.get("evidence_result")
            if not isinstance(e, dict):
                continue
            raw_items = e.get("items")
            if isinstance(raw_items, list):
                grouped.setdefault(cve_id, []).extend(
                    [i for i in (_sanitize_evidence_item(x) for x in raw_items) if isinstance(i, dict)]
                )
            else:
                raw_items2 = e.get("evidence_items")
                if isinstance(raw_items2, list):
                    grouped.setdefault(cve_id, []).extend(
                        [i for i in (_sanitize_evidence_item(x) for x in raw_items2) if isinstance(i, dict)]
                    )

    out: list[dict[str, Any]] = []
    for cve_id, items in grouped.items():
        out.append(
            {
                "cve_id": cve_id,
                "evidence_items": items,
            }
        )
    return out


def _collect_completed_verify_cveids(payload: Any) -> set[str]:
    done: set[str] = set()
    for group in _extract_evidence_groups_from_payload(payload):
        cve_id = _normalize_cve_id(group.get("cve_id"))
        items = group.get("evidence_items")
        if cve_id != "UNKNOWN" and isinstance(items, list) and items:
            done.add(cve_id)
    return done


def _merge_skipped_inputs(old_items: Any, new_items: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None, str]] = set()
    for src in ((old_items or []), (new_items or [])):
        if not isinstance(src, list):
            continue
        for item in src:
            if not isinstance(item, dict):
                continue
            key = (
                _normalize_cve_id(item.get("cve_id")),
                _safe_int(item.get("issue_index")),
                str(item.get("reason") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "issue_index": _safe_int(item.get("issue_index")),
                    "cve_id": _normalize_cve_id(item.get("cve_id")),
                    "reason": str(item.get("reason") or ""),
                }
            )
    return out


def _merge_batch_errors(old_errors: Any, new_errors: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for src in ((old_errors or []), (new_errors or [])):
        if not isinstance(src, list):
            continue
        for e in src:
            msg = str(e or "").strip()
            if not msg or msg in seen:
                continue
            seen.add(msg)
            out.append(msg)
    return out


def _merge_verify_evidence_payloads(
    existing_payload: Any,
    new_payload: Any,
    *,
    input_file: str,
) -> dict[str, Any]:
    existing_groups = _extract_evidence_groups_from_payload(existing_payload)
    new_groups = _extract_evidence_groups_from_payload(new_payload)

    merged_by_cve: dict[str, dict[str, Any]] = {}
    for g in existing_groups:
        if not isinstance(g, dict):
            continue
        cid = _normalize_cve_id(g.get("cve_id"))
        merged_by_cve[cid] = {
            "cve_id": cid,
            "evidence_items": [
                i for i in (_sanitize_evidence_item(x) for x in g.get("evidence_items", []))
                if isinstance(i, dict)
            ],
        }
    for g in new_groups:
        if not isinstance(g, dict):
            continue
        cid = _normalize_cve_id(g.get("cve_id"))
        merged_by_cve[cid] = {
            "cve_id": cid,
            "evidence_items": [
                i for i in (_sanitize_evidence_item(x) for x in g.get("evidence_items", []))
                if isinstance(i, dict)
            ],
        }

    merged_groups = list(merged_by_cve.values())
    merged_skipped = _merge_skipped_inputs(
        existing_payload.get("skipped_inputs") if isinstance(existing_payload, dict) else [],
        new_payload.get("skipped_inputs") if isinstance(new_payload, dict) else [],
    )
    merged_errors = _merge_batch_errors(
        existing_payload.get("batch_errors") if isinstance(existing_payload, dict) else [],
        new_payload.get("batch_errors") if isinstance(new_payload, dict) else [],
    )
    return _build_evidence_payload_from_groups(
        input_file=input_file,
        evidence_groups=merged_groups,
        skipped_inputs=merged_skipped,
        batch_errors=merged_errors,
    )


def _build_evidence_payload(
    *,
    input_file: str,
    verified_findings: list[dict[str, Any]],
    skipped_inputs: list[dict[str, Any]],
    batch_errors: list[str],
) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}

    for finding in verified_findings:
        if not isinstance(finding, dict):
            continue
        cve_id = str(finding.get("cve_id") or finding.get("CVEID") or "UNKNOWN").strip() or "UNKNOWN"
        g = groups.get(cve_id)
        if g is None:
            g = {
                "cve_id": cve_id,
                "evidence_items": [],
            }
            groups[cve_id] = g

        item = _build_evidence_item(finding)
        g["evidence_items"].append(item)
    evidence_groups = list(groups.values())
    return _build_evidence_payload_from_groups(
        input_file=input_file,
        evidence_groups=evidence_groups,
        skipped_inputs=skipped_inputs,
        batch_errors=batch_errors,
    )


def _severity_rank(value: Any) -> int:
    sev = str(value or "").strip().lower()
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(sev, 0)


def _normalize_result_payload_for_merge(payload: Any) -> dict[str, Any]:
    """
    规范化结果载荷，确保至少包含 issues/summary。
    """
    if isinstance(payload, dict):
        base = dict(payload)
    elif isinstance(payload, list):
        base = {"issues": [x for x in payload if isinstance(x, dict)]}
    else:
        base = {}
    if not isinstance(base.get("issues"), list):
        base["issues"] = []
    if not isinstance(base.get("summary"), dict):
        base["summary"] = {}
    return base


def _collect_declared_cve_ids(payload: Any) -> set[str]:
    out: set[str] = set()
    if not isinstance(payload, dict):
        return out
    issues = payload.get("issues")
    if not isinstance(issues, list):
        return out
    for item in issues:
        if not isinstance(item, dict):
            continue
        cid = _normalize_cve_id(item.get("cve_id") or item.get("CVEID"))
        if cid != "UNKNOWN":
            out.add(cid)
    return out


def _collect_evidence_by_cve(payload: Any) -> dict[str, dict[str, Any]]:
    evidence_by_cve: dict[str, dict[str, Any]] = {}
    if not isinstance(payload, dict):
        return evidence_by_cve

    # 旧结构：顶层 evidence
    raw_evidence = payload.get("evidence")
    if isinstance(raw_evidence, list):
        for entry in raw_evidence:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("evidence_items"), list):
                cid = _normalize_cve_id(entry.get("cve_id"))
                evidence_by_cve[cid] = {
                    "summary": entry.get("summary") if isinstance(entry.get("summary"), dict) else {},
                    "items": [
                        i
                        for i in (_sanitize_evidence_item(x) for x in entry.get("evidence_items", []))
                        if isinstance(i, dict)
                    ],
                }
                continue
            if "source_to_sink_claim" in entry and "verifier_judgement" in entry:
                cid = _normalize_cve_id(entry.get("cve_id"))
                bucket = evidence_by_cve.setdefault(cid, {"summary": {}, "items": []})
                normalized = _sanitize_evidence_item(entry)
                if isinstance(normalized, dict):
                    bucket["items"].append(normalized)

    # 新结构：issues[].evidence_result
    issues = payload.get("issues")
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            cid = _normalize_cve_id(issue.get("cve_id") or issue.get("CVEID"))
            e = issue.get("evidence_result")
            if not isinstance(e, dict):
                continue
            raw_items = e.get("items")
            if not isinstance(raw_items, list):
                raw_items = e.get("evidence_items")
            items = [
                i
                for i in (_sanitize_evidence_item(x) for x in (raw_items or []))
                if isinstance(i, dict)
            ]
            if not items and not isinstance(e.get("summary"), dict):
                continue
            bucket = evidence_by_cve.setdefault(cid, {"summary": {}, "items": []})
            if items:
                bucket["items"] = items
            if isinstance(e.get("summary"), dict):
                bucket["summary"] = dict(e.get("summary"))

    # 回填每个 CVE 的 evidence summary
    for cid, data in evidence_by_cve.items():
        summary = data.get("summary")
        if isinstance(summary, dict) and summary:
            continue
        s = _new_evidence_summary()
        for item in data.get("items", []):
            if isinstance(item, dict):
                _accumulate_evidence_summary(s, item)
        data["summary"] = s
        evidence_by_cve[cid] = data
    return evidence_by_cve


def _build_basic_info(path_findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not path_findings:
        return {
            "vulnerability_type": "",
            "severity": "unknown",
            "title": "",
            "description": "",
        }
    best = max(path_findings, key=lambda x: (_severity_rank(x.get("severity")), _safe_float(x.get("confidence"), 0.0)))
    return {
        "vulnerability_type": str(best.get("type") or best.get("vulnerability_type") or ""),
        "severity": str(best.get("severity") or "unknown"),
        "title": str(best.get("title") or ""),
        "description": str(best.get("description") or ""),
    }


PATH_FINDING_EVIDENCE_KEYS = {
    "ai_explanation",
    "verification_method",
    "verification_details",
    "poc",
    "proof",
    "evidence",
    "source_to_sink_claim",
    "verifier_judgement",
    "needs_verification",
    "verified_at",
    "verdict",
    "is_verified",
}


def _sanitize_path_finding_for_output(
    finding: dict[str, Any],
    *,
    issue_index: int,
    strip_path_evidence: bool,
) -> dict[str, Any]:
    out = dict(finding)
    # 统一节点字段，结果里只保留 Nodes，减少冗余。
    if not isinstance(out.get("Nodes"), list):
        stsp = out.get("source_to_sink_path")
        if isinstance(stsp, list):
            out["Nodes"] = stsp
    out.pop("source_to_sink_path", None)

    # 在路径结果中显式携带索引，和 evidence_result.items[*].issue_index 对应。
    out["issue_index"] = issue_index

    if strip_path_evidence:
        for k in PATH_FINDING_EVIDENCE_KEYS:
            out.pop(k, None)
    return out


def _build_compact_payload(
    *,
    result_payload: Any,
    evidence_payload: dict[str, Any] | None,
    strip_path_evidence: bool = True,
) -> dict[str, Any]:
    base = _normalize_result_payload_for_merge(result_payload)
    raw_path_findings = _extract_issues_from_result_payload(base)
    issues_by_cve: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for global_idx, issue in enumerate(raw_path_findings, start=1):
        if not isinstance(issue, dict):
            continue
        cid = _normalize_cve_id(issue.get("CVEID") or issue.get("cve_id"))
        issues_by_cve.setdefault(cid, []).append((global_idx, issue))

    evidence_by_cve = _collect_evidence_by_cve(evidence_payload or base)

    cve_ids = sorted(
        set(issues_by_cve.keys())
        | set(evidence_by_cve.keys())
        | _collect_declared_cve_ids(base)
    )
    compact_issues: list[dict[str, Any]] = []
    path_findings: list[dict[str, Any]] = []
    for cid in cve_ids:
        raw_pairs = issues_by_cve.get(cid, [])
        index_map: dict[int, int] = {}
        p: list[dict[str, Any]] = []
        for local_idx, (global_idx, finding) in enumerate(raw_pairs, start=1):
            index_map[global_idx] = local_idx
            p.append(
                _sanitize_path_finding_for_output(
                    finding,
                    issue_index=local_idx,
                    strip_path_evidence=strip_path_evidence,
                )
            )
        path_findings.extend(p)

        e = evidence_by_cve.get(cid, {"summary": _new_evidence_summary(), "items": []})
        raw_e_items = e.get("items", []) if isinstance(e, dict) else []
        e_items: list[dict[str, Any]] = []
        if isinstance(raw_e_items, list):
            for item in raw_e_items:
                if not isinstance(item, dict):
                    continue
                one = dict(item)
                src_idx = _safe_int(one.get("issue_index"))
                if src_idx is not None and src_idx in index_map:
                    one["issue_index"] = index_map[src_idx]
                e_items.append(one)
        compact_issues.append(
            {
                "cve_id": cid,
                "basic_info": _build_basic_info(p),
                "path_result": {
                    "findings": p,
                },
                "evidence_result": {
                    "summary": e.get("summary", {}),
                    "items": e_items,
                },
            }
        )

    # 汇总：路径严重度统计
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in path_findings:
        if not isinstance(issue, dict):
            continue
        sev = str(issue.get("severity") or "low").strip().lower()
        if sev not in severity_summary:
            sev = "low"
        severity_summary[sev] += 1

    # 汇总：evidence 统计
    evidence_overall = _new_evidence_summary()
    for entry in compact_issues:
        e = entry.get("evidence_result")
        items = e.get("items") if isinstance(e, dict) else []
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                _accumulate_evidence_summary(evidence_overall, item)

    raw_summary = base.get("summary") if isinstance(base.get("summary"), dict) else {}
    if isinstance(raw_summary, dict) and isinstance(raw_summary.get("run"), dict):
        run_summary = dict(raw_summary.get("run") or {})
    else:
        run_summary = dict(raw_summary or {})

    evidence_skipped_inputs = len(evidence_payload.get("skipped_inputs", [])) if isinstance(evidence_payload, dict) and isinstance(evidence_payload.get("skipped_inputs"), list) else 0
    evidence_errors = len(evidence_payload.get("batch_errors", [])) if isinstance(evidence_payload, dict) and isinstance(evidence_payload.get("batch_errors"), list) else 0
    prev_overview = raw_summary.get("overview") if isinstance(raw_summary, dict) and isinstance(raw_summary.get("overview"), dict) else {}
    if evidence_skipped_inputs == 0 and isinstance(prev_overview, dict):
        evidence_skipped_inputs = int(prev_overview.get("evidence_skipped_inputs") or 0)
    if evidence_errors == 0 and isinstance(prev_overview, dict):
        evidence_errors = int(prev_overview.get("evidence_errors") or 0)
    compact_summary = {
        "run": run_summary,
        "overview": {
            "total_cves": len(compact_issues),
            "path_findings": len(path_findings),
            "evidence_items": evidence_overall.get("total_evidence_items", 0),
            "evidence_skipped_inputs": evidence_skipped_inputs,
            "evidence_errors": evidence_errors,
            "severity_summary": severity_summary,
            "source_to_sink_claims": evidence_overall.get("source_to_sink_claims", {}),
            "verifier_verdicts": evidence_overall.get("verifier_verdicts", {}),
        },
    }
    return {
        "issues": compact_issues,
        "summary": compact_summary,
    }


def _attach_evidence_to_result_payload(
    *,
    result_payload: Any,
    evidence_payload: dict[str, Any],
) -> dict[str, Any]:
    """
    产出紧凑结果结构：仅包含 issues + summary。
    """
    return _build_compact_payload(
        result_payload=result_payload,
        evidence_payload=evidence_payload,
    )


def _build_verify_tasks_by_cve(
    resolved_findings: list[dict[str, Any]],
    skipped_inputs: list[dict[str, Any]],
    cve_checkout_refs: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    grouped_by_cve: dict[str, list[dict[str, Any]]] = {}
    for finding in resolved_findings:
        if not isinstance(finding, dict):
            continue
        cve_id = str(finding.get("cve_id") or finding.get("CVEID") or "UNKNOWN").strip() or "UNKNOWN"
        grouped_by_cve.setdefault(cve_id, []).append(finding)

    tasks: list[dict[str, Any]] = []
    for cve_id, findings in sorted(grouped_by_cve.items(), key=lambda x: x[0]):
        repo_buckets: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            repo_path = str(f.get("_resolved_repo") or "").strip()
            if repo_path:
                repo_buckets.setdefault(repo_path, []).append(f)

        if not repo_buckets:
            for f in findings:
                skipped_inputs.append(
                    {
                        "issue_index": _safe_int(f.get("_origin_issue_index")),
                        "cve_id": cve_id,
                        "reason": "missing resolved repository for CVE",
                    }
                )
            continue

        ordered_repo_buckets = sorted(
            repo_buckets.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        selected_repo, selected_findings = ordered_repo_buckets[0]

        if len(ordered_repo_buckets) > 1:
            selected_repo_name = Path(selected_repo).name
            for _repo, others in ordered_repo_buckets[1:]:
                for f in others:
                    skipped_inputs.append(
                        {
                            "issue_index": _safe_int(f.get("_origin_issue_index")),
                            "cve_id": cve_id,
                            "reason": f"multiple resolved repos for one CVE; selected primary repo {selected_repo_name}",
                        }
                    )

        tasks.append(
            {
                "cve_id": cve_id,
                "repo_path": selected_repo,
                "checkout_ref": str((cve_checkout_refs or {}).get(cve_id) or "").strip(),
                "findings": selected_findings,
            }
        )
    return tasks


def _run_git_cmd(repo_dir: Path, args: list[str]) -> tuple[bool, str]:
    import subprocess

    proc = subprocess.run(
        ["git", "-C", str(repo_dir)] + list(args),
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True, (proc.stdout or "").strip()
    err = (proc.stderr or proc.stdout or "").strip()
    return False, err[-800:]


def _prepare_verify_workspace_repo(
    *,
    cached_repo_path: str,
    cve_id: str,
    checkout_ref: str,
    workspace_root: str | None,
) -> tuple[Path | None, Path | None, str]:
    """
    将缓存仓库复制到临时工作目录，并 checkout 到指定漏洞版本。
    返回: (workspace_repo_path, workspace_dir, error_message)
    """
    import shutil
    import tempfile

    cached_repo = Path(cached_repo_path).resolve()
    if not cached_repo.is_dir():
        return None, None, f"cached repo not found: {cached_repo}"

    ref = str(checkout_ref or "").strip()
    if not ref:
        return None, None, "missing checkout_ref"

    try:
        if workspace_root:
            ws_base = Path(workspace_root).resolve()
            ws_base.mkdir(parents=True, exist_ok=True)
            ws_dir = Path(tempfile.mkdtemp(prefix=f"secagent_verify_{cve_id}_", dir=str(ws_base)))
        else:
            ws_dir = Path(tempfile.mkdtemp(prefix=f"secagent_verify_{cve_id}_"))
    except Exception as exc:
        return None, None, f"create temp workspace failed: {exc}"

    repo_dir = ws_dir / "repo"
    try:
        shutil.copytree(cached_repo, repo_dir, symlinks=True)
    except Exception as exc:
        shutil.rmtree(ws_dir, ignore_errors=True)
        return None, None, f"copy cached repo failed: {exc}"

    ok, err = _run_git_cmd(repo_dir, ["reset", "--hard"])
    if not ok:
        shutil.rmtree(ws_dir, ignore_errors=True)
        return None, None, f"git reset --hard failed: {err}"
    ok, err = _run_git_cmd(repo_dir, ["clean", "-fdx"])
    if not ok:
        shutil.rmtree(ws_dir, ignore_errors=True)
        return None, None, f"git clean -fdx failed: {err}"
    ok, err = _run_git_cmd(repo_dir, ["checkout", "-f", ref])
    if not ok:
        shutil.rmtree(ws_dir, ignore_errors=True)
        return None, None, f"git checkout {ref} failed: {err}"

    return repo_dir, ws_dir, ""


async def _run_verify_tasks_parallel(
    tasks: list[dict[str, Any]],
    workers: int,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    workspace_root: str | None = None,
    keep_workspace: bool = False,
) -> list[dict[str, Any]]:
    if not tasks:
        return []

    max_workers = max(1, int(workers))
    semaphore = asyncio.Semaphore(max_workers)
    total = len(tasks)

    async def _run_one(task_index: int, task: dict[str, Any]) -> dict[str, Any]:
        import shutil

        cve_id = str(task.get("cve_id") or "UNKNOWN").strip() or "UNKNOWN"
        cached_repo_path = str(task.get("repo_path") or "").strip()
        checkout_ref = str(task.get("checkout_ref") or "").strip()
        findings = [f for f in (task.get("findings") or []) if isinstance(f, dict)]
        print(
            f"[SecAgent] verify-evidence cve {task_index}/{total} "
            f"(cve={cve_id}, items={len(findings)}, repo={Path(cached_repo_path).name if cached_repo_path else '-'}, "
            f"checkout={'yes' if checkout_ref else 'no'})",
            flush=True,
        )

        async with semaphore:
            error: str | None = None
            out_findings: list[dict[str, Any]] = []
            workspace_repo: Path | None = None
            workspace_dir: Path | None = None

            try:
                workspace_repo, workspace_dir, prep_err = _prepare_verify_workspace_repo(
                    cached_repo_path=cached_repo_path,
                    cve_id=cve_id,
                    checkout_ref=checkout_ref,
                    workspace_root=workspace_root,
                )
                if not workspace_repo:
                    error = f"cve {cve_id}: workspace prepare failed ({cached_repo_path}) {prep_err}"
                    out_findings = _fallback_verified_findings(findings, error)
                else:
                    result = await run_verifier_only(
                        repo_path=str(workspace_repo),
                        findings=findings,
                        cve_id=cve_id,
                        verification_level="standard",
                    )
                    data = result.get("data", {}) if isinstance(result, dict) else {}
                    out_findings = data.get("findings", []) if isinstance(data, dict) else []
                    if not isinstance(out_findings, list) or not out_findings:
                        error = f"cve {cve_id}: verifier returned empty findings"
                        out_findings = _fallback_verified_findings(findings, error)
            except Exception as exc:
                error = f"cve {cve_id} failed: {exc}"
                out_findings = _fallback_verified_findings(findings, error)
            finally:
                if workspace_dir and workspace_dir.exists():
                    if keep_workspace:
                        print(f"[SecAgent] keep verify workspace: {workspace_dir}", flush=True)
                    else:
                        shutil.rmtree(workspace_dir, ignore_errors=True)

            normalized_findings: list[dict[str, Any]] = []
            for item in out_findings:
                if not isinstance(item, dict):
                    continue
                normalized = dict(item)
                if not str(normalized.get("cve_id") or "").strip():
                    normalized["cve_id"] = cve_id
                normalized_findings.append(normalized)

            return {
                "cve_id": cve_id,
                "findings": normalized_findings,
                "error": error,
            }

    running = [asyncio.create_task(_run_one(i + 1, task)) for i, task in enumerate(tasks)]
    outputs: list[dict[str, Any]] = []
    done = 0
    for fut in asyncio.as_completed(running):
        item = await fut
        outputs.append(item if isinstance(item, dict) else {})
        done += 1
        if progress_callback:
            try:
                progress_callback(
                    {
                        "done": done,
                        "total": total,
                        "cve_id": item.get("cve_id") if isinstance(item, dict) else None,
                        "error": item.get("error") if isinstance(item, dict) else None,
                        "findings": item.get("findings") if isinstance(item, dict) else [],
                    }
                )
            except Exception as exc:
                print(f"[SecAgent] verify-evidence progress callback failed: {exc}", flush=True)
    return outputs


def _build_fullflow_evidence_payload(
    *,
    input_file: str,
    result_payload: dict[str, Any],
    project_root: Path,
    repo_cache_root: Path,
) -> dict[str, Any]:
    """
    主流程 evidence 生成（不触发 verifier-only 二次执行）：
    - 输入来源：主流程最终 result payload（issues）
    - repo 仅用于节点可读性/path-check 辅助，不改变主流程编排与判定来源
    """
    findings, skipped = _load_findings_from_result_payload(result_payload, repo_root=None)
    if not findings:
        return _build_evidence_payload(
            input_file=input_file,
            verified_findings=[],
            skipped_inputs=skipped,
            batch_errors=[],
        )

    cve_ids = {
        str(f.get("cve_id") or f.get("CVEID") or "").strip()
        for f in findings
        if str(f.get("cve_id") or f.get("CVEID") or "").strip()
    }
    cve_repo_meta = _load_cve_repo_meta(cve_ids, project_root=project_root)
    cve_repo_urls = {
        cid: str(meta.get("repo_url") or "").strip()
        for cid, meta in cve_repo_meta.items()
        if str(meta.get("repo_url") or "").strip()
    }

    resolved_findings: list[dict[str, Any]] = []
    for f in findings:
        ff = dict(f)
        # 优先将路径结果里的 ai_explanation 用作 evidence 主证据
        ai_exp = str(ff.get("ai_explanation") or "").strip()
        if ai_exp and not str(ff.get("verification_details") or "").strip():
            ff["verification_details"] = ai_exp
        if ai_exp and not str(ff.get("verification_method") or "").strip():
            ff["verification_method"] = "mainflow_result_explanation"

        repo_dir, reason = _resolve_cached_repo_for_finding(ff, repo_cache_root, cve_repo_urls)
        if repo_dir:
            ff["_resolved_repo"] = str(repo_dir)
            ff["_resolved_repo_source"] = reason
        else:
            skipped.append(
                {
                    "issue_index": _safe_int(ff.get("_origin_issue_index")),
                    "cve_id": _normalize_cve_id(ff.get("cve_id") or ff.get("CVEID")),
                    "reason": reason,
                }
            )
        resolved_findings.append(ff)

    return _build_evidence_payload(
        input_file=input_file,
        verified_findings=resolved_findings,
        skipped_inputs=skipped,
        batch_errors=[],
    )


def _run_verify_evidence_on_payload(
    *,
    input_file: str,
    input_payload: Any,
    project_root: Path,
    repo_cache_root: Path,
    workers: int,
    workspace_root: str | None = None,
    keep_workspace: bool = False,
    skip_cve_ids: set[str] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """
    统一的 evidence 生成入口：
    - --verify-evidence 模式
    - 默认主流程结束后的 evidence 附加
    两者共享同一输入转换、repo 解析、checkout 与 verifier 执行逻辑。
    """
    findings, skipped = _load_findings_from_result_payload(input_payload, repo_root=None)
    skip_set = {_normalize_cve_id(x) for x in (skip_cve_ids or set()) if _normalize_cve_id(x) != "UNKNOWN"}
    if skip_set:
        findings = [
            f for f in findings
            if _normalize_cve_id(f.get("cve_id") or f.get("CVEID")) not in skip_set
        ]
        skipped = [
            s for s in skipped
            if _normalize_cve_id(s.get("cve_id")) not in skip_set
        ]

    if not findings:
        return _build_evidence_payload(
            input_file=input_file,
            verified_findings=[],
            skipped_inputs=skipped,
            batch_errors=["no valid issues with resolvable source-to-sink nodes"],
        )

    cve_ids = {str(f.get("cve_id") or "").strip() for f in findings if str(f.get("cve_id") or "").strip()}
    cve_repo_meta = _load_cve_repo_meta(cve_ids, project_root=project_root)
    cve_repo_urls = {
        cid: str(meta.get("repo_url") or "").strip()
        for cid, meta in cve_repo_meta.items()
        if str(meta.get("repo_url") or "").strip()
    }
    cve_checkout_refs = {
        cid: str(meta.get("checkout_ref") or "").strip()
        for cid, meta in cve_repo_meta.items()
        if str(meta.get("checkout_ref") or "").strip()
    }

    resolved_findings: list[dict[str, Any]] = []
    for f in findings:
        idx = _safe_int(f.get("_origin_issue_index"))
        cve_id = str(f.get("cve_id") or f.get("CVEID") or "UNKNOWN").strip() or "UNKNOWN"
        repo_dir, reason = _resolve_cached_repo_for_finding(f, repo_cache_root, cve_repo_urls)
        if repo_dir:
            ff = dict(f)
            ff["_resolved_repo"] = str(repo_dir)
            ff["_resolved_repo_source"] = reason
            resolved_findings.append(ff)
        else:
            skipped.append(
                {
                    "issue_index": idx,
                    "cve_id": cve_id,
                    "reason": reason,
                }
            )

    if not resolved_findings:
        return _build_evidence_payload(
            input_file=input_file,
            verified_findings=[],
            skipped_inputs=skipped,
            batch_errors=["all findings failed to resolve cached repository"],
        )

    verify_tasks = _build_verify_tasks_by_cve(
        resolved_findings,
        skipped,
        cve_checkout_refs=cve_checkout_refs,
    )
    if not verify_tasks:
        return _build_evidence_payload(
            input_file=input_file,
            verified_findings=[],
            skipped_inputs=skipped,
            batch_errors=["all CVE groups were skipped before verifier execution"],
        )

    print(
        f"[SecAgent] verify-evidence cve groups: {len(verify_tasks)} "
        f"(resolved={len(resolved_findings)}, skipped={len(skipped)}, workers={workers})",
        flush=True,
    )

    task_outputs = asyncio.run(
        _run_verify_tasks_parallel(
            verify_tasks,
            workers=max(1, int(workers)),
            progress_callback=progress_callback,
            workspace_root=workspace_root,
            keep_workspace=keep_workspace,
        )
    )

    verified_findings: list[dict[str, Any]] = []
    batch_errors: list[str] = []
    for item in task_outputs:
        if not isinstance(item, dict):
            continue
        err = str(item.get("error") or "").strip()
        if err:
            batch_errors.append(err)
        out_findings = item.get("findings", [])
        if isinstance(out_findings, list):
            verified_findings.extend([f for f in out_findings if isinstance(f, dict)])

    def _order_key(item: dict[str, Any]) -> int:
        idx = _safe_int(item.get("_origin_issue_index"))
        return idx if idx is not None else 10**9

    verified_findings.sort(key=_order_key)
    return _build_evidence_payload(
        input_file=input_file,
        verified_findings=verified_findings,
        skipped_inputs=skipped,
        batch_errors=batch_errors,
    )


def _run_verify_evidence_mode(
    args,
    *,
    skip_cve_ids: set[str] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    project_root = Path(__file__).resolve().parents[2]
    repo_cache_root = (
        Path(args.repo_cache_root).resolve()
        if args.repo_cache_root
        else (project_root / "data" / "repos").resolve()
    )
    if not repo_cache_root.is_dir():
        raise ValueError(f"repo cache root 不存在或不是目录: {repo_cache_root}")

    input_path = Path(args.cve)
    if not input_path.is_file():
        raise ValueError(f"结果文件不存在: {input_path}")
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    return _run_verify_evidence_on_payload(
        input_file=str(input_path),
        input_payload=raw,
        project_root=project_root,
        repo_cache_root=repo_cache_root,
        workers=max(1, int(getattr(args, "workers", 1) or 1)),
        workspace_root=args.workspace_root,
        keep_workspace=bool(getattr(args, "keep_workspace", False)),
        skip_cve_ids=skip_cve_ids,
        progress_callback=progress_callback,
    )


def main() -> int:
    args = build_parser().parse_args()
    if args.verify_evidence and args.out == DEFAULT_RESULT_OUT:
        # verify-evidence 默认回写到输入结果文件，产出“路径+evidence”一体化结果
        args.out = args.cve

    soft_fd, hard_fd = _raise_fd_limit(8192)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"run_{ts}.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_fp = log_path.open("w", encoding="utf-8")
    grouped = GroupedThoughtLog() if not args.log_full else None
    tee_out = TeeStream(original_stdout, log_fp, thought_only=not args.log_full, grouped=grouped)
    tee_err = TeeStream(original_stderr, log_fp, thought_only=not args.log_full, grouped=grouped)
    sys.stdout = tee_out
    sys.stderr = tee_err

    print(f"[SecAgent] Run log: {log_path}")
    if soft_fd is not None and hard_fd is not None:
        print(f"[SecAgent] FD limit: soft={soft_fd}, hard={hard_fd}")

    try:
        if args.verify_evidence:
            resume_enabled = (not args.no_resume) and (args.out != "-")
            existing_payload: dict[str, Any] = {}
            completed_cveids: set[str] = set()
            input_path = Path(args.cve)
            out_path = Path(args.out) if args.out != "-" else None

            if not input_path.exists():
                print(f"[SecAgent] verify-evidence failed: 结果文件不存在: {input_path}")
                return 2
            try:
                base_result_payload: Any = json.loads(input_path.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"[SecAgent] verify-evidence failed: 读取输入结果文件失败: {exc}")
                return 2
            input_cveids: set[str] = _collect_cveids_from_result_payload(base_result_payload)

            if resume_enabled and out_path and out_path.exists():
                try:
                    existing_payload = json.loads(out_path.read_text(encoding="utf-8"))
                    completed_cveids = _collect_completed_verify_cveids(existing_payload)
                    if completed_cveids:
                        print(f"[SecAgent] Resume detected: {len(completed_cveids)} CVE(s) already completed")
                except Exception as exc:
                    print(f"[SecAgent] Warning: failed to read existing evidence for resume: {exc}")
                    existing_payload = {}
                    completed_cveids = set()

            pending_cveids = input_cveids - completed_cveids if input_cveids else set()
            if resume_enabled and input_cveids and not pending_cveids:
                # 即使无需继续执行，也确保输出是“路径+evidence”的合并结构
                merged_payload = _attach_evidence_to_result_payload(
                    result_payload=base_result_payload,
                    evidence_payload=(existing_payload if isinstance(existing_payload, dict) else {}),
                )
                if args.out == "-":
                    print(json.dumps(merged_payload, ensure_ascii=False, indent=2))
                elif out_path is not None:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(
                        json.dumps(merged_payload, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    print("[SecAgent] All CVEs are already processed. Wrote merged result without re-run.")
                else:
                    print("[SecAgent] All CVEs are already processed. Exit without overwriting output.")
                return 0

            if resume_enabled and input_cveids and len(pending_cveids) != len(input_cveids):
                print(f"[SecAgent] Pending CVEs: {len(pending_cveids)} / {len(input_cveids)}")

            incremental_findings: list[dict[str, Any]] = []
            incremental_errors: list[str] = []

            def _flush_verify_progress(evt: dict[str, Any]) -> None:
                if args.out == "-":
                    return
                findings = evt.get("findings")
                if isinstance(findings, list):
                    incremental_findings.extend([f for f in findings if isinstance(f, dict)])
                err = str(evt.get("error") or "").strip()
                if err:
                    incremental_errors.append(err)

                partial_payload = _build_evidence_payload(
                    input_file=str(input_path),
                    verified_findings=incremental_findings,
                    skipped_inputs=[],
                    batch_errors=incremental_errors,
                )
                if resume_enabled and existing_payload:
                    checkpoint_evidence = _merge_verify_evidence_payloads(
                        existing_payload,
                        partial_payload,
                        input_file=str(input_path),
                    )
                else:
                    checkpoint_evidence = partial_payload

                checkpoint_payload = _attach_evidence_to_result_payload(
                    result_payload=base_result_payload,
                    evidence_payload=checkpoint_evidence,
                )

                checkpoint_out = Path(args.out)
                checkpoint_out.parent.mkdir(parents=True, exist_ok=True)
                checkpoint_out.write_text(
                    json.dumps(checkpoint_payload, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                print(
                    f"[SecAgent] verify-evidence checkpoint saved: {evt.get('done')}/{evt.get('total')} "
                    f"(last={evt.get('cve_id')}, accumulated_items={len(incremental_findings)})"
                )

            try:
                evidence_payload_new = _run_verify_evidence_mode(
                    args,
                    skip_cve_ids=completed_cveids if resume_enabled else None,
                    progress_callback=_flush_verify_progress if args.out != "-" else None,
                )
            except Exception as exc:
                print(f"[SecAgent] verify-evidence failed: {exc}")
                return 2

            if resume_enabled and existing_payload:
                evidence_payload = _merge_verify_evidence_payloads(
                    existing_payload,
                    evidence_payload_new,
                    input_file=str(input_path),
                )
            else:
                evidence_payload = evidence_payload_new

            merged_payload = _attach_evidence_to_result_payload(
                result_payload=base_result_payload,
                evidence_payload=evidence_payload,
            )
            text = json.dumps(merged_payload, ensure_ascii=False, indent=2)
            if args.out == "-":
                print(text)
            else:
                out_path_final = Path(args.out)
                out_path_final.parent.mkdir(parents=True, exist_ok=True)
                out_path_final.write_text(text, encoding="utf-8")
                print(f"Wrote merged result to {args.out}")
            return 0

        resume_enabled = (not args.no_resume) and (args.out != "-")
        existing_payload: dict = {}
        out_path = Path(args.out) if args.out != "-" else None
        completed_cveids: set[str] = set()
        constraints = parse_cve_file(args.cve)
        if grouped:
            grouped.set_order([str(c.cve_id) for c in constraints])

        if resume_enabled and out_path and out_path.exists():
            try:
                existing_payload = json.loads(out_path.read_text(encoding="utf-8"))
                completed_cveids = _collect_completed_cveids(existing_payload)
                if completed_cveids:
                    print(f"[SecAgent] Resume detected: {len(completed_cveids)} CVE(s) already completed")
            except Exception as exc:
                print(f"[SecAgent] Warning: failed to read existing output for resume: {exc}")
                existing_payload = {}
                completed_cveids = set()

        pending = [c for c in constraints if c.cve_id not in completed_cveids]
        if resume_enabled and not pending:
            # 若历史结果已完成但尚未包含 evidence 附加结构，则补写一次，避免用户必须 --no-resume 重跑
            try:
                needs_attach = False
                if isinstance(existing_payload, dict):
                    existing_issues = existing_payload.get("issues")
                    if not isinstance(existing_issues, list):
                        needs_attach = True
                    elif not existing_issues:
                        needs_attach = False
                    else:
                        for item in existing_issues:
                            if not isinstance(item, dict) or not isinstance(item.get("evidence_result"), dict):
                                needs_attach = True
                                break
                if needs_attach:
                    project_root = Path(__file__).resolve().parents[2]
                    repo_cache_root = (
                        Path(args.repo_cache_root).resolve()
                        if args.repo_cache_root
                        else (project_root / "data" / "repos").resolve()
                    )
                    evidence_payload = _build_fullflow_evidence_payload(
                        input_file=str(out_path) if out_path is not None else args.out,
                        result_payload=existing_payload,
                        project_root=project_root,
                        repo_cache_root=repo_cache_root,
                    )
                    existing_payload = _attach_evidence_to_result_payload(
                        result_payload=existing_payload,
                        evidence_payload=evidence_payload,
                    )
                    if out_path is not None:
                        out_path.write_text(
                            json.dumps(existing_payload, ensure_ascii=False, indent=2),
                            encoding="utf-8",
                        )
                        print("[SecAgent] Attached evidence to existing completed output.")
            except Exception as exc:
                print(f"[SecAgent] Warning: failed to attach evidence on resume-complete output: {exc}")
            print("[SecAgent] All CVEs are already processed. Exit without overwriting output.")
            return 0

        if pending and len(pending) != len(constraints):
            print(f"[SecAgent] Pending CVEs: {len(pending)} / {len(constraints)}")

        if pending:
            max_auto_restarts = 3
            restart_count = 0
            final_result = None
            final_pending = pending
            while True:
                incremental_new_issues: list[dict] = []
                incremental_failures: list[str] = []

                def _flush_progress(evt: dict) -> None:
                    if args.out == "-":
                        return
                    item = evt.get("item")
                    err = evt.get("error")
                    if item:
                        issue = _issue_from_finding(item)
                        if issue:
                            incremental_new_issues.append(issue)
                    if err:
                        incremental_failures.append(str(err))

                    merged_issues = _merge_issues(
                        existing_payload.get("issues", []) if isinstance(existing_payload, dict) else [],
                        incremental_new_issues,
                    )
                    merged_summary = {
                        "resume": True,
                        "total_cves": len(constraints),
                        "completed_before": len(completed_cveids),
                        "processed_this_run": int(evt.get("done") or 0),
                        "new_issues": len(incremental_new_issues),
                        "total_issues": len(merged_issues),
                        "current_run": {
                            "done": int(evt.get("done") or 0),
                            "total": int(evt.get("total") or 0),
                            "matched": int(evt.get("matched") or 0),
                            "failed": int(evt.get("failed") or 0),
                            "last_cve": evt.get("cve_id"),
                            "recent_failures": incremental_failures[-10:],
                        },
                    }
                    payload = _build_payload_from_issues(merged_issues, merged_summary)
                    out_path = Path(args.out)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                    print(
                        f"[SecAgent] checkpoint saved: {evt.get('done')}/{evt.get('total')} "
                        f"(last={evt.get('cve_id')}, total_issues={len(merged_issues)})"
                    )

                try:
                    final_result = run_pipeline_from_constraints(
                        constraints=final_pending,
                        workers=args.workers,
                        workspace_root=args.workspace_root,
                        repo_cache_root=args.repo_cache_root,
                        keep_workspace=args.keep_workspace,
                        progress_callback=_flush_progress if args.out != "-" else None,
                    )
                    break
                except Exception as exc:
                    restart_count += 1
                    if args.out != "-" and out_path and out_path.exists():
                        try:
                            existing_payload = json.loads(out_path.read_text(encoding="utf-8"))
                            completed_cveids = _collect_completed_cveids(existing_payload)
                        except Exception:
                            pass
                    final_pending = [c for c in constraints if c.cve_id not in completed_cveids]
                    print(
                        f"[SecAgent] batch interrupted: {exc} | auto-restart {restart_count}/{max_auto_restarts} "
                        f"| remaining={len(final_pending)}"
                    )
                    if not final_pending:
                        break
                    if restart_count >= max_auto_restarts:
                        raise
                    time.sleep(2.0)
            if final_result is not None:
                result = final_result
            else:
                result = PipelineResult(findings=[], summary={"interrupted": True, "remaining": len(final_pending)})
        else:
            result = run_pipeline(
                cve_input_file=args.cve,
                workers=args.workers,
                workspace_root=args.workspace_root,
                repo_cache_root=args.repo_cache_root,
                keep_workspace=args.keep_workspace,
            )

        new_payload = result_to_deepaudit_dict(result)

        if resume_enabled and existing_payload:
            merged_issues = _merge_issues(
                existing_payload.get("issues", []),
                new_payload.get("issues", []),
            )
            merged_summary = {
                "resume": True,
                "total_cves": len(constraints),
                "completed_before": len(completed_cveids),
                "processed_this_run": len(pending),
                "new_issues": len(new_payload.get("issues", [])),
                "total_issues": len(merged_issues),
                "current_run": new_payload.get("summary", {}),
            }
            payload = _build_payload_from_issues(merged_issues, merged_summary)
        else:
            payload = new_payload

        # 无论是否附加 evidence，结果文件都统一为紧凑结构（仅 issues + summary）
        payload = _build_compact_payload(
            result_payload=payload,
            evidence_payload=None,
            # 主流程证据抽取依赖 finding 内的 verification_* / ai_explanation 字段；
            # 先保留，待 attach evidence 后再做最终瘦身输出。
            strip_path_evidence=False,
        )

        # 默认全流程也输出 evidence 结果（基于主流程结果，不额外触发 verifier-only 执行）
        try:
            project_root = Path(__file__).resolve().parents[2]
            repo_cache_root = (
                Path(args.repo_cache_root).resolve()
                if args.repo_cache_root
                else (project_root / "data" / "repos").resolve()
            )
            evidence_payload = _build_fullflow_evidence_payload(
                input_file=str(args.out) if args.out != "-" else "<stdout>",
                result_payload=(payload if isinstance(payload, dict) else {}),
                project_root=project_root,
                repo_cache_root=repo_cache_root,
            )
            payload = _attach_evidence_to_result_payload(
                result_payload=payload,
                evidence_payload=evidence_payload,
            )
        except Exception as exc:
            print(f"[SecAgent] Warning: failed to attach fullflow evidence payload: {exc}")

        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out == "-":
            print(text)
        else:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
            print(f"Wrote result to {args.out}")

        return 0
    finally:
        try:
            tee_out.flush()
            tee_err.flush()
            if grouped:
                grouped.dump(log_fp)
                log_fp.flush()
        except Exception:
            pass
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_fp.close()


if __name__ == "__main__":
    raise SystemExit(main())
