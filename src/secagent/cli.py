from __future__ import annotations

import argparse
import json
import re
import time
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .deepaudit_adapter import result_to_deepaudit_dict
from .pipeline import run_pipeline, run_pipeline_from_constraints
from .cve_parser import parse_cve_file
from .models import PipelineResult


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
    p.add_argument("--repo", required=False, help="Optional local repository path (compatibility mode)")
    p.add_argument("--cve", required=True, help="Path to CVE semantic JSON file")
    p.add_argument("--out", default="data/result/result.json", help="Output JSON file path, '-' for stdout")
    p.add_argument("--workers", type=int, default=4, help="Parallel workers for batch CVE processing")
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
    return p


def _collect_completed_cveids(payload: dict) -> set[str]:
    done: set[str] = set()
    for issue in payload.get("issues", []) if isinstance(payload, dict) else []:
        if not isinstance(issue, dict):
            continue
        cve = str(issue.get("CVEID") or "").strip()
        if cve:
            done.add(cve)
    return done


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

    for src in (old_issues or []) + (new_issues or []):
        if not isinstance(src, dict):
            continue
        k = _key(src)
        if k in seen:
            continue
        seen.add(k)
        merged.append(src)
    return merged


def _build_payload_from_issues(issues: list[dict], summary: dict) -> dict:
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
        "summary": summary,
    }


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


def main() -> int:
    args = build_parser().parse_args()
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
                        repo_path=args.repo,
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
                repo_path=args.repo,
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
