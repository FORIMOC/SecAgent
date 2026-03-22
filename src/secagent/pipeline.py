from __future__ import annotations

import asyncio
import hashlib
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .agent_runner import run_cve_directed_audit
from .cve_parser import parse_cve_file
from .models import DirectedFinding, PipelineResult


def _score_finding(finding: dict[str, Any], target_files: list[str], expected_vuln: str) -> float:
    score = float(finding.get("confidence", 0.5) or 0.5)
    fpath = str(finding.get("file_path", "") or "")
    if fpath and fpath in target_files:
        score += 0.2
    if expected_vuln and finding.get("vulnerability_type") == expected_vuln:
        score += 0.15
    if finding.get("is_verified") is True or finding.get("verdict") in {"confirmed", "likely"}:
        score += 0.1
    return min(score, 0.99)


def _pick_top1(findings: list[dict[str, Any]], target_files: list[str], expected_vuln: str) -> dict[str, Any] | None:
    if not findings:
        return None
    ranked = sorted(findings, key=lambda f: _score_finding(f, target_files, expected_vuln), reverse=True)
    top = ranked[0]
    top["confidence"] = round(_score_finding(top, target_files, expected_vuln), 3)
    return top


def _pick_best_actionable(findings: list[dict[str, Any]], target_files: list[str], expected_vuln: str) -> dict[str, Any] | None:
    if not findings:
        return None
    ranked = sorted(findings, key=lambda f: _score_finding(f, target_files, expected_vuln), reverse=True)
    for item in ranked:
        if _is_actionable_finding(item):
            item["confidence"] = round(_score_finding(item, target_files, expected_vuln), 3)
            return item
    return None


def _normalized_path_nodes(f: dict[str, Any]) -> list[dict[str, Any]]:
    raw = f.get("source_to_sink_path")
    if not raw and isinstance(f.get("evidence"), dict):
        raw = f["evidence"].get("source_to_sink_path")
    if not raw:
        return []
    if not isinstance(raw, list):
        return []

    nodes: list[dict[str, Any]] = []
    fallback_file = str(f.get("file_path") or f.get("file") or "").strip()
    for node in raw:
        if not isinstance(node, dict):
            continue
        line = node.get("line")
        start_line = node.get("start_line", node.get("StartLine"))
        end_line = node.get("end_line", node.get("EndLine"))
        if line is None:
            line = node.get("StartLine")
        try:
            line = int(line) if line is not None else None
        except Exception:
            line = None
        try:
            start_line = int(start_line) if start_line is not None else None
        except Exception:
            start_line = None
        try:
            end_line = int(end_line) if end_line is not None else None
        except Exception:
            end_line = None
        code = str(node.get("code") or "").strip()
        if line is None and start_line is None and end_line is None and not code:
            continue
        kind = str(node.get("kind") or "").strip().lower()
        if not kind:
            t = str(node.get("Type") or "").strip().lower()
            if t == "source":
                kind = "source"
            elif t == "sink":
                kind = "sink"
            elif t == "propagation":
                kind = "propagation"
            else:
                kind = "propagation"
        node_file = str(node.get("file_path") or node.get("File") or fallback_file).strip()
        base_line = start_line or line
        nodes.append(
            {
                "kind": kind,
                "file_path": node_file or None,
                "line": base_line,
                "start_line": start_line or line,
                "end_line": end_line or start_line or line,
                "code": code,
            }
        )
    return nodes


def _synthesize_path_nodes(f: dict[str, Any]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    line_start = f.get("line_start")
    line_end = f.get("line_end")
    source = str(f.get("source") or "").strip()
    sink = str(f.get("sink") or "").strip()

    try:
        line_start = int(line_start) if line_start is not None else None
    except Exception:
        line_start = None
    try:
        line_end = int(line_end) if line_end is not None else None
    except Exception:
        line_end = None

    if line_start and source:
        nodes.append(
            {
                "kind": "source",
                "line": line_start,
                "start_line": line_start,
                "end_line": line_start,
                "code": source,
            }
        )
    sink_line = line_end or line_start
    if sink_line and sink:
        if not nodes or line_end != nodes[0]["line"] or sink != nodes[0]["code"]:
            nodes.append(
                {
                    "kind": "sink",
                    "line": sink_line,
                    "start_line": sink_line,
                    "end_line": sink_line,
                    "code": sink,
                }
            )
    return nodes


def _read_code_range(repo_root: str, file_path: str, start_line: int, end_line: int) -> str:
    if not file_path or start_line <= 0 or end_line <= 0 or end_line < start_line:
        return ""
    try:
        root = Path(repo_root).resolve()
        target = (root / file_path).resolve()
        if not str(target).startswith(str(root)):
            return ""
        if not target.is_file():
            return ""
        with target.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        s = max(1, start_line)
        e = min(len(lines), end_line)
        if s > e:
            return ""
        snippet = "".join(lines[s - 1:e]).strip()
        return snippet[:2000]
    except Exception:
        return ""


def _load_file_lines(repo_root: str, file_path: str) -> list[str]:
    try:
        root = Path(repo_root).resolve()
        target = (root / file_path).resolve()
        if not str(target).startswith(str(root)) or not target.is_file():
            return []
        return target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []


def _hint_candidates(text: str) -> list[str]:
    raw = (text or "").strip()
    if not raw:
        return []
    cands = [raw]
    if " - " in raw:
        cands.append(raw.split(" - ", 1)[0].strip())
    # Remove very common NL tails like "(第82行)".
    cands.append(re.sub(r"[（(]\s*第\s*\d+\s*行\s*[）)]", "", raw).strip())
    out: list[str] = []
    seen: set[str] = set()
    for c in cands:
        if not c:
            continue
        c = c.strip("`\"' ")
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _find_line_by_hint(
    repo_root: str,
    file_path: str,
    hint: str,
    preferred_line: int | None = None,
    avoid_line: int | None = None,
) -> int | None:
    lines = _load_file_lines(repo_root, file_path)
    if not lines:
        return preferred_line

    # 1) Exact/contains match using progressively relaxed hints
    for cand in _hint_candidates(hint):
        for idx, line in enumerate(lines, start=1):
            if avoid_line and idx == avoid_line:
                continue
            if cand and cand in line:
                return idx

    # 2) Token-overlap fallback for partially natural-language hints
    tokens = [
        t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_:$()'\".\-]*", hint or "")
        if len(t) >= 4
    ]
    if tokens:
        best_idx = None
        best_score = 0
        for idx, line in enumerate(lines, start=1):
            if avoid_line and idx == avoid_line:
                continue
            score = sum(1 for t in tokens if t in line)
            if score > best_score:
                best_score = score
                best_idx = idx
        if best_idx and best_score >= 2:
            return best_idx

    return preferred_line


def _hydrate_finding_code(repo_root: str, finding: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return finding
    f = dict(finding)
    file_path = str(f.get("file_path") or f.get("file") or "").strip()

    raw_nodes = f.get("source_to_sink_path")
    if isinstance(raw_nodes, list) and raw_nodes:
        if not file_path:
            for n0 in raw_nodes:
                if isinstance(n0, dict):
                    fp = str(n0.get("file_path") or n0.get("File") or "").strip()
                    if fp:
                        file_path = fp
                        f["file_path"] = fp
                        break
        if not file_path:
            return f
        # Try to resolve distinct source/sink lines when model returned same/default line.
        source_hint = str(f.get("source") or "").strip()
        sink_hint = str(f.get("sink") or "").strip()
        source_line_guess = None
        sink_line_guess = None
        if source_hint:
            try:
                pref = int(f.get("line_start")) if f.get("line_start") is not None else None
            except Exception:
                pref = None
            source_line_guess = _find_line_by_hint(repo_root, file_path, source_hint, preferred_line=pref)
        if sink_hint:
            try:
                pref_sink = int(f.get("line_end")) if f.get("line_end") is not None else None
            except Exception:
                pref_sink = None
            sink_line_guess = _find_line_by_hint(
                repo_root, file_path, sink_hint, preferred_line=pref_sink, avoid_line=source_line_guess
            )

        hydrated_nodes: list[dict[str, Any]] = []
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            n = dict(node)
            line = n.get("line")
            start = n.get("start_line")
            end = n.get("end_line")
            try:
                line = int(line) if line is not None else None
            except Exception:
                line = None
            try:
                start = int(start) if start is not None else None
            except Exception:
                start = None
            try:
                end = int(end) if end is not None else None
            except Exception:
                end = None
            start = start or line
            end = end or start

            kind = str(n.get("kind") or "").lower().strip()
            if not kind:
                t = str(n.get("Type") or "").strip().lower()
                kind = "source" if t == "source" else ("sink" if t == "sink" else "propagation")
            node_file = str(n.get("file_path") or n.get("File") or file_path).strip()
            if kind == "source" and source_line_guess:
                start = source_line_guess
                end = source_line_guess
            elif kind == "sink" and sink_line_guess:
                start = sink_line_guess
                end = sink_line_guess

            if start and end:
                real_code = _read_code_range(repo_root, node_file, start, end)
                if real_code:
                    if not str(n.get("code") or "").strip():
                        n["code"] = real_code
                    n["line"] = start
                    n["start_line"] = start
                    n["end_line"] = end
                    n["file_path"] = node_file
                    n["File"] = node_file
            hydrated_nodes.append(n)
        if hydrated_nodes:
            f["source_to_sink_path"] = hydrated_nodes
            return f

    # Fallback: synthesize minimal path from line_start/line_end using real code
    try:
        line_start = int(f.get("line_start")) if f.get("line_start") is not None else None
    except Exception:
        line_start = None
    try:
        line_end = int(f.get("line_end")) if f.get("line_end") is not None else None
    except Exception:
        line_end = None
    source_hint = str(f.get("source") or "").strip()
    sink_hint = str(f.get("sink") or "").strip()
    source_line = _find_line_by_hint(repo_root, file_path, source_hint, preferred_line=line_start)
    sink_line = _find_line_by_hint(repo_root, file_path, sink_hint, preferred_line=(line_end or line_start), avoid_line=source_line)
    nodes: list[dict[str, Any]] = []
    if source_line:
        source_code = _read_code_range(repo_root, file_path, source_line, source_line)
        if source_code:
            nodes.append(
                {
                    "kind": "source",
                    "line": source_line,
                    "start_line": source_line,
                    "end_line": source_line,
                    "code": source_code,
                }
            )
    if sink_line:
        sink_code = _read_code_range(repo_root, file_path, sink_line, sink_line)
        if sink_code:
            if not nodes or nodes[0].get("line") != sink_line or nodes[0].get("code") != sink_code:
                nodes.append(
                    {
                        "kind": "sink",
                        "line": sink_line,
                        "start_line": sink_line,
                        "end_line": sink_line,
                        "code": sink_code,
                    }
                )
    if nodes:
        f["source_to_sink_path"] = nodes
    return f


def _normalize_finding(cve_id: str, f: dict[str, Any], default_vuln: str) -> DirectedFinding:
    path_nodes = _normalized_path_nodes(f) or _synthesize_path_nodes(f)
    file_path = str(f.get("file_path") or f.get("file") or "").strip()
    if not file_path:
        for n in path_nodes:
            fp = str(n.get("file_path") or "").strip()
            if fp:
                file_path = fp
                break
    sink_line = None
    source_line = None
    for n in path_nodes:
        k = str(n.get("kind") or "").lower()
        if k == "source" and source_line is None:
            source_line = n.get("start_line") or n.get("line")
        if k == "sink":
            sink_line = n.get("start_line") or n.get("line")
    return DirectedFinding(
        cve_id=cve_id,
        vulnerability_type=str(f.get("vulnerability_type") or default_vuln or "generic"),
        severity=str(f.get("severity") or "medium"),
        title=str(f.get("title") or f"{cve_id} directed finding"),
        description=str(f.get("description") or "CVE-directed finding"),
        file_path=file_path or None,
        line_start=f.get("line_start") or source_line,
        line_end=f.get("line_end") or sink_line,
        code_snippet=f.get("code_snippet"),
        source=f.get("source"),
        sink=f.get("sink"),
        source_to_sink_path=path_nodes or None,
        suggestion=str(f.get("suggestion") or f.get("recommendation") or "参考CVE补丁进行修复。"),
        confidence=float(f.get("confidence") or 0.5),
        verdict=str(f.get("verdict") or ("confirmed" if f.get("is_verified") else "likely")),
        evidence={
            "verification_method": f.get("verification_method"),
            "verification_details": f.get("verification_details"),
            "cwe_ids": f.get("cwe_ids"),
            "source_to_sink_path": path_nodes or None,
            "raw": f,
        },
    )


def _is_actionable_finding(f: dict[str, Any]) -> bool:
    if not isinstance(f, dict):
        return False
    if (f.get("vulnerability_type") or "").strip().lower() in {"potential_issue", "generic"}:
        return False
    if str(f.get("source") or "").strip().lower() in {"recon_high_risk"}:
        return False
    source_text = str(f.get("source") or "").strip().lower()
    sink_text = str(f.get("sink") or "").strip().lower()
    snippet_text = str(f.get("code_snippet") or "").strip().lower()
    placeholder_tokens = {
        "user-controlled input",
        "security-sensitive sink",
        "cve-guided candidate dataflow evidence",
        "verified candidate",
    }
    if source_text in placeholder_tokens or sink_text in placeholder_tokens:
        return False
    if snippet_text in placeholder_tokens:
        return False
    # 新结构中不再强依赖顶层 sink/code_snippet，改为以路径节点为准。
    path_nodes = _normalized_path_nodes(f) or _synthesize_path_nodes(f)
    if len(path_nodes) < 1:
        return False
    # 至少要有可落地的节点信息
    has_located_code_node = False
    for n in path_nodes:
        if not isinstance(n, dict):
            continue
        fp = str(n.get("file_path") or "").strip()
        sl = n.get("start_line", n.get("line"))
        code = str(n.get("code") or "").strip()
        if fp and sl and code:
            has_located_code_node = True
            break
    if not has_located_code_node:
        return False
    kinds = {str(n.get("kind") or "").lower() for n in path_nodes if isinstance(n, dict)}
    if "sink" not in kinds:
        return False
    return True


async def _run_single(repo_path: str, constraint) -> DirectedFinding | None:
    result = await run_cve_directed_audit(repo_path, constraint)
    if not isinstance(result, dict):
        return None
    data = result.get("data") or {}
    findings = data.get("findings", []) if isinstance(data, dict) else []

    top = _pick_best_actionable(findings, constraint.target_files, constraint.vulnerability_hint)
    if not top:
        return None
    top = _hydrate_finding_code(repo_path, top)
    return _normalize_finding(constraint.cve_id, top, constraint.vulnerability_hint)


def _make_repo_dirname(cve_id: str, repo_url: str) -> str:
    digest = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:10]
    safe_id = cve_id.replace("/", "_").replace("\\", "_")
    return f"{safe_id}_{digest}"


def _repo_cache_key(repo_url: str) -> str:
    digest = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:16]
    tail = repo_url.rstrip("/").split("/")[-1] or "repo"
    if tail.endswith(".git"):
        tail = tail[:-4]
    safe_tail = "".join(ch if ch.isalnum() or ch in {"_", "-", "."} else "_" for ch in tail)
    return f"{safe_tail}_{digest}"


def _clone_repo(repo_url: str, dst_repo_dir: Path) -> tuple[bool, str]:
    # Full clone is required for reliable historical checkout.
    cmd = ["git", "clone", repo_url, str(dst_repo_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return False, f"spawn git clone failed: {exc}"
    if proc.returncode == 0:
        return True, ""
    err = (proc.stderr or proc.stdout or "").strip()
    return False, err[-800:]


def _ensure_cached_repo(repo_url: str, repo_cache_root: Path) -> tuple[Path | None, str]:
    repo_cache_root.mkdir(parents=True, exist_ok=True)
    cached_repo = repo_cache_root / _repo_cache_key(repo_url)

    if cached_repo.exists() and (cached_repo / ".git").exists():
        return cached_repo, ""

    if cached_repo.exists():
        shutil.rmtree(cached_repo, ignore_errors=True)

    ok, err = _clone_repo(repo_url, cached_repo)
    if not ok:
        return None, err
    return cached_repo, ""


def _copy_cached_repo_to_workspace(cached_repo: Path, workspace_repo: Path) -> tuple[bool, str]:
    try:
        if workspace_repo.exists():
            shutil.rmtree(workspace_repo, ignore_errors=True)
        workspace_repo.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(cached_repo, workspace_repo, symlinks=True)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _run_git(repo_dir: Path, args: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir)] + args,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True, (proc.stdout or "").strip()
    err = (proc.stderr or proc.stdout or "").strip()
    return False, err[-800:]


def _prepare_workspace_repo(repo_dir: Path, checkout_ref: str) -> tuple[bool, str]:
    # Clean copy workspace to deterministic state.
    ok, err = _run_git(repo_dir, ["reset", "--hard"])
    if not ok:
        return False, f"git reset --hard failed: {err}"
    ok, err = _run_git(repo_dir, ["clean", "-fdx"])
    if not ok:
        return False, f"git clean -fdx failed: {err}"

    ref = (checkout_ref or "").strip()
    if not ref:
        return False, "missing ParentHash checkout_ref"

    ok, err = _run_git(repo_dir, ["checkout", "-f", ref])
    if not ok:
        return False, f"git checkout {ref} failed: {err}"
    return True, ""


def _run_one_with_clone(
    constraint,
    workspace_root: Path,
    repo_cache_root: Path,
    keep_workspace: bool,
) -> tuple[DirectedFinding | None, str | None]:
    repo_url = (constraint.repo_url or "").strip()
    if not repo_url:
        return None, f"{constraint.cve_id}: missing repo_url in CVE info"

    cve_ws = workspace_root / _make_repo_dirname(constraint.cve_id, repo_url)
    repo_dir = cve_ws / "repo"
    cve_ws.mkdir(parents=True, exist_ok=True)

    cached_repo, err = _ensure_cached_repo(repo_url, repo_cache_root)
    if not cached_repo:
        if not keep_workspace:
            shutil.rmtree(cve_ws, ignore_errors=True)
        return None, f"{constraint.cve_id}: cache clone failed ({repo_url}) {err}"

    ok, cp_err = _copy_cached_repo_to_workspace(cached_repo, repo_dir)
    if not ok:
        if not keep_workspace:
            shutil.rmtree(cve_ws, ignore_errors=True)
        return None, f"{constraint.cve_id}: copy cached repo failed ({cached_repo}) {cp_err}"

    ok, prep_err = _prepare_workspace_repo(repo_dir, getattr(constraint, "checkout_ref", ""))
    if not ok:
        if not keep_workspace:
            shutil.rmtree(cve_ws, ignore_errors=True)
        return None, f"{constraint.cve_id}: workspace prepare failed ({repo_dir}) {prep_err}"

    try:
        item = asyncio.run(_run_single(str(repo_dir), constraint))
        return item, None
    except Exception as exc:
        return None, f"{constraint.cve_id}: analysis failed: {exc}"
    finally:
        if not keep_workspace:
            shutil.rmtree(cve_ws, ignore_errors=True)


def run_pipeline(
    cve_input_file: str | Path,
    workers: int = 4,
    workspace_root: str | Path | None = None,
    repo_cache_root: str | Path | None = None,
    keep_workspace: bool = False,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> PipelineResult:
    constraints = parse_cve_file(cve_input_file)
    return run_pipeline_from_constraints(
        constraints=constraints,
        workers=workers,
        workspace_root=workspace_root,
        repo_cache_root=repo_cache_root,
        keep_workspace=keep_workspace,
        progress_callback=progress_callback,
    )


def run_pipeline_from_constraints(
    constraints: list,
    workers: int = 4,
    workspace_root: str | Path | None = None,
    repo_cache_root: str | Path | None = None,
    keep_workspace: bool = False,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> PipelineResult:
    findings: list[DirectedFinding] = []
    failures: list[str] = []

    total = len(constraints)
    done = 0

    def _emit_progress(constraint, item: DirectedFinding | None, err: str | None) -> None:
        if not progress_callback:
            return
        nonlocal done
        done += 1
        try:
            progress_callback(
                {
                    "cve_id": getattr(constraint, "cve_id", ""),
                    "done": done,
                    "total": total,
                    "item": item,
                    "error": err,
                    "matched": len(findings),
                    "failed": len(failures),
                }
            )
        except Exception:
            pass

    project_root = Path(__file__).resolve().parents[2]
    cache_root = (
        Path(repo_cache_root)
        if repo_cache_root
        else project_root / "data" / "repos"
    )
    ws_root = (
        Path(workspace_root)
        if workspace_root
        else Path(tempfile.mkdtemp(prefix="secagent_workspace_"))
    )
    ws_root.mkdir(parents=True, exist_ok=True)

    max_workers = max(1, int(workers))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                _run_one_with_clone,
                constraint,
                ws_root,
                cache_root,
                keep_workspace,
            ): constraint
            for constraint in constraints
        }
        for future in as_completed(future_map):
            constraint = future_map[future]
            try:
                item, err = future.result()
            except Exception as exc:
                item, err = None, f"{constraint.cve_id}: worker crashed: {exc}"
            if item:
                findings.append(item)
            if err:
                failures.append(err)
            _emit_progress(constraint, item, err)

    if not keep_workspace and workspace_root is None:
        shutil.rmtree(ws_root, ignore_errors=True)

    summary = {
        "total_cves": len(constraints),
        "matched": len(findings),
        "unmatched": len(constraints) - len(findings),
        "failed": len(failures),
        "mode": "migrated_deepaudit_multi_agent_with_cve_constraints",
        "workers": max(1, int(workers)),
        "clone_mode": True,
        "failures": failures[:50],
    }
    return PipelineResult(findings=findings, summary=summary)
