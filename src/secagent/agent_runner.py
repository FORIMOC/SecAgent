from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.services.agent.agents import OrchestratorAgent, ReconAgent, AnalysisAgent, VerificationAgent
from app.services.agent.tools import (
    FileReadTool,
    FileSearchTool,
    ListFilesTool,
    PatternMatchTool,
    CodeAnalysisTool,
    DataFlowAnalysisTool,
    VulnerabilityValidationTool,
    SmartScanTool,
    QuickAuditTool,
    RunCodeTool,
    ExtractFunctionTool,
)
from app.services.agent.tools.sandbox_tool import (
    SandboxTool,
    SandboxHttpTool,
    VulnerabilityVerifyTool,
    PhpTestTool,
    CommandInjectionTestTool,
)

from .models import CVEConstraint


LANG_EXTS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".ts", ".tsx"},
    "php": {".php"},
    "java": {".java"},
    "go": {".go"},
    "rust": {".rs"},
}
DEFAULT_CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rs", ".rb", ".c", ".cpp", ".h", ".cs"}

EXCLUDE_DIRS = {".git", "node_modules", "dist", "build", "vendor", "__pycache__", ".venv", "venv"}


def _safe_add_tool(tools: dict[str, Any], name: str, factory) -> None:
    """Best-effort registration for optional tools; never break core flow."""
    try:
        tools[name] = factory()
    except Exception as exc:
        print(f"[SecAgent] optional tool disabled: {name} ({exc})", flush=True)


def _count_files(repo_path: str) -> int:
    count = 0
    for _root, _dirs, files in os.walk(repo_path):
        count += len(files)
    return count


def _iter_repo_files(repo_path: str, exts: set[str], limit: int = 500) -> list[str]:
    root = Path(repo_path)
    out: list[str] = []
    for p in root.rglob("*"):
        if len(out) >= limit:
            break
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        out.append(str(p.relative_to(root)))
    return out


def _pick_by_path_similarity(candidates: list[str], target_files: list[str], max_files: int) -> list[str]:
    if not candidates or not target_files:
        return []
    scored: list[tuple[int, str]] = []
    target_meta = []
    for t in target_files:
        parts = [p.lower() for p in t.split("/") if p]
        base = parts[-1] if parts else ""
        stem = base.rsplit(".", 1)[0] if "." in base else base
        target_meta.append((parts, base, stem))

    for c in candidates:
        cparts = [p.lower() for p in c.split("/") if p]
        cbase = cparts[-1] if cparts else ""
        cstem = cbase.rsplit(".", 1)[0] if "." in cbase else cbase
        best = 0
        for tparts, tbase, tstem in target_meta:
            score = 0
            if tbase and cbase == tbase:
                score += 6
            if tstem and cstem == tstem:
                score += 4
            shared = set(cparts[:-1]) & set(tparts[:-1])
            score += min(3, len(shared))
            if cparts and tparts and cparts[-1] == tparts[-1]:
                score += 1
            if score > best:
                best = score
        if best > 0:
            scored.append((best, c))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [c for _s, c in scored[:max_files]]


def _pick_target_files(repo_path: str, constraint: CVEConstraint, max_files: int = 50) -> list[str]:
    root = Path(repo_path)
    existing_patch_files = [f for f in constraint.target_files if (root / f).is_file()]
    if existing_patch_files:
        return existing_patch_files[:max_files]

    # No keyword/rule-based ranking here: only language + deterministic file order.
    lang_exts = LANG_EXTS.get((constraint.language or "").lower(), DEFAULT_CODE_EXTS)
    candidates = _iter_repo_files(repo_path, lang_exts, limit=max(200, max_files * 4))
    if not candidates:
        # If CVE language doesn't exist in current repo, fallback to generic code files.
        candidates = _iter_repo_files(repo_path, DEFAULT_CODE_EXTS, limit=max(200, max_files * 4))

    # When patch files don't exist in this repo, map by path/name similarity first.
    similar = _pick_by_path_similarity(candidates, constraint.target_files or [], max_files=max_files)
    if similar:
        return similar
    return sorted(candidates)[:max_files]


def _build_llm_service() -> Any:
    """
    Build real LLM service.
    If LLM_PROVIDER is not set, infer provider from available API keys.
    """
    try:
        from app.services.llm.service import LLMService
        from app.services.llm.types import LLMProvider
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Real LLM dependencies are missing. Please install required packages (e.g. httpx, litellm). "
            "SecAgent no longer includes mock LLM fallback."
        ) from exc

    inferred_provider = None
    user_llm_config: dict[str, Any] = {}
    if not os.getenv("LLM_PROVIDER"):
        if os.getenv("DEEPSEEK_API_KEY"):
            inferred_provider = "deepseek"
            user_llm_config["llmApiKey"] = os.getenv("DEEPSEEK_API_KEY")
            # Avoid invalid generic/default models when provider is inferred from key.
            user_llm_config["llmModel"] = os.getenv("LLM_MODEL") or "deepseek-chat"
        elif os.getenv("OPENAI_API_KEY"):
            inferred_provider = "openai"
            user_llm_config["llmApiKey"] = os.getenv("OPENAI_API_KEY")
        elif os.getenv("QWEN_API_KEY"):
            inferred_provider = "qwen"
            user_llm_config["llmApiKey"] = os.getenv("QWEN_API_KEY")
        elif os.getenv("CLAUDE_API_KEY"):
            inferred_provider = "claude"
            user_llm_config["llmApiKey"] = os.getenv("CLAUDE_API_KEY")
        elif os.getenv("GEMINI_API_KEY"):
            inferred_provider = "gemini"
            user_llm_config["llmApiKey"] = os.getenv("GEMINI_API_KEY")
        if inferred_provider:
            user_llm_config["llmProvider"] = inferred_provider

    user_config = {"llmConfig": user_llm_config} if user_llm_config else {}
    llm = LLMService(user_config=user_config)
    cfg = llm.config
    if cfg.provider != LLMProvider.OLLAMA and not (cfg.api_key or "").strip():
        raise RuntimeError(
            "Real LLM is enabled but API key is missing. "
            "Please set LLM_PROVIDER plus matching API key, or at least set one provider-specific key "
            "(e.g. DEEPSEEK_API_KEY) so SecAgent can infer the provider."
        )
    return llm


def _build_tools(repo_path: str, llm_service: Any, target_files: list[str] | None = None) -> dict[str, Any]:
    tools = {
        # Core file tools (hard requirement)
        "list_files": ListFilesTool(project_root=repo_path, target_files=target_files or None),
        "read_file": FileReadTool(project_root=repo_path, target_files=target_files or None),
        "search_code": FileSearchTool(project_root=repo_path, target_files=target_files or None),
        # Non-SAST analysis helpers
        "pattern_match": PatternMatchTool(project_root=repo_path),
        "code_analysis": CodeAnalysisTool(llm_service=llm_service, project_root=repo_path),
        "dataflow_analysis": DataFlowAnalysisTool(llm_service=llm_service),
        "vulnerability_validation": VulnerabilityValidationTool(llm_service=llm_service),
        "smart_scan": SmartScanTool(project_root=repo_path),
        "quick_audit": QuickAuditTool(project_root=repo_path),
        "extract_function": ExtractFunctionTool(project_root=repo_path),
    }

    # Optional runtime verification tools (Docker/sandbox dependent)
    _safe_add_tool(tools, "run_code", lambda: RunCodeTool(project_root=repo_path))
    _safe_add_tool(tools, "sandbox_exec", lambda: SandboxTool())
    _safe_add_tool(tools, "sandbox_http", lambda: SandboxHttpTool())
    _safe_add_tool(tools, "verify_vulnerability", lambda: VulnerabilityVerifyTool())
    _safe_add_tool(tools, "php_test", lambda: PhpTestTool(project_root=repo_path))
    _safe_add_tool(tools, "test_command_injection", lambda: CommandInjectionTestTool(project_root=repo_path))
    return tools


def _extract_target_files_from_findings(findings: list[dict[str, Any]], max_files: int = 80) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def _add(path: str) -> None:
        p = str(path or "").strip()
        if not p:
            return
        if p.startswith("./"):
            p = p[2:]
        if p in seen:
            return
        seen.add(p)
        out.append(p)

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        _add(str(f.get("file_path") or f.get("file") or ""))
        nodes = f.get("source_to_sink_path")
        if isinstance(nodes, list):
            for n in nodes:
                if not isinstance(n, dict):
                    continue
                _add(str(n.get("file_path") or n.get("File") or ""))
                if len(out) >= max_files:
                    return out
        if len(out) >= max_files:
            return out
    return out


async def run_verifier_only(
    repo_path: str,
    findings: list[dict[str, Any]],
    cve_id: str = "verify-only",
    verification_level: str = "standard",
) -> dict[str, Any]:
    llm_service = _build_llm_service()
    target_files = _extract_target_files_from_findings(findings)
    tools = _build_tools(repo_path, llm_service, target_files=target_files)

    verification = VerificationAgent(llm_service=llm_service, tools=tools)
    if hasattr(verification, "set_log_context"):
        verification.set_log_context(cve_id)

    result = await verification.run(
        {
            "previous_results": {"findings": findings},
            "config": {
                "verification_level": verification_level,
                "target_files": target_files,
            },
            "project_root": repo_path,
            "task": f"Verify existing findings only ({cve_id})",
            "task_context": "Validate provided source-to-sink evidence path",
        }
    )
    return result.to_dict()


async def run_cve_directed_audit(repo_path: str, constraint: CVEConstraint) -> dict[str, Any]:
    llm_service = _build_llm_service()

    target_files = _pick_target_files(repo_path, constraint)
    tools = _build_tools(repo_path, llm_service, target_files=target_files)

    recon = ReconAgent(llm_service=llm_service, tools=tools)
    analysis = AnalysisAgent(llm_service=llm_service, tools=tools)
    verification = VerificationAgent(llm_service=llm_service, tools=tools)

    orchestrator = OrchestratorAgent(
        llm_service=llm_service,
        tools=tools,
        sub_agents={
            "recon": recon,
            "analysis": analysis,
            "verification": verification,
        },
    )
    for agent in (recon, analysis, verification, orchestrator):
        if hasattr(agent, "set_log_context"):
            agent.set_log_context(constraint.cve_id)

    scope_details = {
        "cve_id": constraint.cve_id,
        "cwe_ids": constraint.cwe_ids,
        "title": constraint.title,
        "description": constraint.description,
        "patch_files": constraint.target_files[:30],
        "patch_focus_variables": constraint.patch_focus_variables[:20],
        # Avoid injecting full raw patch old lines into prompt context.
        # Keep only compact semantic hints derived from patch diffs.
        "patch_semantic_snippet_count": len(constraint.patch_focus_semantic_snippets or []),
        "patch_semantic_reasons": [
            str(x.get("reason") or "semantic_change")
            for x in (constraint.patch_focus_semantic_snippets or [])[:8]
            if isinstance(x, dict)
        ],
        "advisory_summary": constraint.advisory_summary[:2000] if constraint.advisory_summary else "",
        "advisory_refs": constraint.advisory_refs[:8],
        "effective_target_files": target_files[:30],
    }

    project_info = {
        "name": Path(repo_path).name,
        "root": repo_path,
        "file_count": _count_files(repo_path),
        "structure": {
            "scope_limited": True,
            "scope_message": f"CVE定向审计: {constraint.cve_id} | 语义约束: {scope_details}",
        },
    }

    config = {
        "target_files": target_files,
        "exclude_patterns": [".git", "node_modules", "dist", "build", "__pycache__"],
        "target_vulnerabilities": [constraint.vulnerability_hint],
        "patch_focus_variables": constraint.patch_focus_variables[:20],
        "patch_focus_semantic_snippets": (constraint.patch_focus_semantic_snippets or [])[:8],
        "cve_advisory_summary": constraint.advisory_summary[:2000] if constraint.advisory_summary else "",
        "cve_advisory_refs": constraint.advisory_refs[:8],
        "verification_level": "standard",
    }

    result = await orchestrator.run(
        {
            "project_info": project_info,
            "config": config,
            "project_root": repo_path,
            "task_id": f"{constraint.cve_id}-task",
        }
    )

    return result.to_dict()
