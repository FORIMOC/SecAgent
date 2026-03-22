from __future__ import annotations

import re
from typing import Any

from .models import DirectedFinding, PipelineResult


_GENERIC_DESC_MARKERS = (
    "用户可控数据在此进入",
    "危险操作在此触发",
    "污点在此传播/转换",
    "该节点的污点传递语义描述",
    "source node",
    "sink node",
    "propagation node",
)

_CALL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "echo",
    "print",
    "isset",
    "empty",
    "array",
}

_SOURCE_CALL_HINTS = (
    "getpost",
    "get",
    "post",
    "request",
    "param",
    "input",
    "query",
    "cookie",
    "header",
    "argv",
    "getenv",
)

_SINK_CALL_ACTIONS = {
    "query": "SQL 执行",
    "execute": "SQL 执行",
    "exec": "命令/SQL 执行",
    "mysqli_query": "SQL 执行",
    "rawquery": "SQL 执行",
    "system": "系统命令执行",
    "shell_exec": "系统命令执行",
    "passthru": "系统命令执行",
    "popen": "系统命令执行",
    "eval": "动态代码执行",
    "unserialize": "反序列化",
    "render": "模板/内容渲染",
    "include": "文件包含",
    "require": "文件包含",
}

_PROPAGATION_PREFERRED_CALLS = (
    "implode",
    "join",
    "sprintf",
    "format",
    "concat",
    "sanitize",
    "escape",
    "encode",
    "decode",
    "replace",
    "trim",
    "intval",
    "strval",
)


def _short_code(code: str, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", str(code or "").strip())
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _is_generic_desc(text: str) -> bool:
    t = str(text or "").strip().lower()
    if not t:
        return True
    for marker in _GENERIC_DESC_MARKERS:
        if marker.lower() in t:
            return True
    return False


def _dedupe_keep_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        k = str(x or "").strip()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


def _extract_variables(code: str) -> list[str]:
    text = str(code or "")
    vars_php = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*(?:->\w+)?(?:\[[^\]]+\])?", text)
    vars_common = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text)
    candidates: list[str] = list(vars_php)
    for v in vars_common:
        lv = v.lower()
        if lv in _CALL_KEYWORDS:
            continue
        if lv in {"true", "false", "null"}:
            continue
        if re.fullmatch(r"[A-Z_]{3,}", v):
            # 常量类标识一般不作为污点变量描述重点
            continue
        candidates.append(v)
    return _dedupe_keep_order(candidates)


def _extract_call_names(code: str) -> list[str]:
    text = str(code or "")
    names = re.findall(r"(?:->|::)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    out: list[str] = []
    for n in names:
        ln = n.lower()
        if ln in _CALL_KEYWORDS:
            continue
        out.append(n)
    return _dedupe_keep_order(out)


def _extract_assignment_target(code: str) -> str:
    text = re.sub(r"\s+", " ", str(code or "").strip())
    if not text:
        return ""
    php_like = re.search(r"(\$[A-Za-z_][A-Za-z0-9_]*(?:->\w+)?(?:\[[^\]]+\])?)\s*(?:\.?=)", text)
    if php_like:
        return str(php_like.group(1))
    js_like = re.search(r"(?:var|let|const)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", text)
    if js_like:
        return str(js_like.group(1))
    py_like = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", text)
    if py_like:
        return str(py_like.group(1))
    return ""


def _pick_source_call(calls: list[str], code: str) -> str:
    if re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b", str(code or ""), re.IGNORECASE):
        return "$_REQUEST"
    for c in calls:
        lc = c.lower()
        if any(h in lc for h in _SOURCE_CALL_HINTS):
            return c
    return calls[0] if calls else ""


def _pick_sink_call(calls: list[str]) -> str:
    for c in calls:
        if c.lower() in _SINK_CALL_ACTIONS:
            return c
    return calls[0] if calls else ""


def _pick_propagation_call(calls: list[str]) -> str:
    for c in calls:
        lc = c.lower()
        if any(h in lc for h in _PROPAGATION_PREFERRED_CALLS):
            return c
    for c in calls:
        if c.lower() not in {"empty", "isset", "count"}:
            return c
    return calls[0] if calls else ""


def _extract_first_call_arg_var(code: str, call_name: str) -> str:
    if not call_name:
        return ""
    text = str(code or "")
    m = re.search(rf"{re.escape(call_name)}\s*\(([^)]*)\)", text)
    if not m:
        return ""
    arg_text = m.group(1).strip()
    if not arg_text:
        return ""
    vars_in_arg = _extract_variables(arg_text)
    if vars_in_arg:
        return vars_in_arg[0]
    return _short_code(arg_text, limit=40)


def _desc_for_node(node_type: str, code: str, raw_desc: str = "") -> str:
    code_text = str(code or "").strip()
    raw_desc_text = str(raw_desc or "").strip()
    if raw_desc_text and not _is_generic_desc(raw_desc_text):
        return raw_desc_text[:320]
    if not code_text:
        if node_type == "Source":
            return "源点：可控输入在此进入数据流。"
        if node_type == "Sink":
            return "汇点：污点数据在此进入危险操作。"
        return "传播点：污点在此继续传递。"

    calls = _extract_call_names(code_text)
    variables = _extract_variables(code_text)
    target = _extract_assignment_target(code_text)
    short = _short_code(code_text)

    if node_type == "Source":
        src_call = _pick_source_call(calls, code_text)
        if target and src_call:
            return f"源点：变量 `{target}` 通过 `{src_call}()` 接收外部输入并成为污点源。代码: `{short}`"
        if target:
            return f"源点：变量 `{target}` 在此接收可控数据并进入污点传播链。代码: `{short}`"
        if src_call:
            return f"源点：通过 `{src_call}()` 读取外部输入，污点从此进入。代码: `{short}`"
        key_vars = ", ".join(variables[:2]) if variables else "关键变量"
        return f"源点：可控数据在此进入，影响 {key_vars}。代码: `{short}`"

    if node_type == "Sink":
        sink_call = _pick_sink_call(calls)
        sink_arg = _extract_first_call_arg_var(code_text, sink_call)
        sink_action = _SINK_CALL_ACTIONS.get(str(sink_call).lower(), "危险操作")
        if sink_call and sink_arg and target:
            return (
                f"汇点：调用 `{sink_call}({sink_arg})` 触发{sink_action}，污点参数被消费（结果写入 `{target}`）。"
                f" 代码: `{short}`"
            )
        if sink_call and sink_arg:
            return f"汇点：调用 `{sink_call}({sink_arg})` 触发{sink_action}，污点在此触达危险 API。代码: `{short}`"
        if sink_call:
            return f"汇点：调用 `{sink_call}()` 触发{sink_action}，污点在此被利用。代码: `{short}`"
        return f"汇点：污点数据在此进入危险执行路径。代码: `{short}`"

    prop_call = _pick_propagation_call(calls)
    upstream_var = ""
    for v in variables:
        if target and v == target:
            continue
        upstream_var = v
        break
    if target and prop_call and upstream_var:
        return (
            f"传播点：`{upstream_var}` 经 `{prop_call}()` 处理后并入 `{target}`，污点继续向下游传播。"
            f" 代码: `{short}`"
        )
    if target and prop_call:
        return f"传播点：通过 `{prop_call}()` 对数据处理后写入 `{target}`，保持污点可达。代码: `{short}`"
    if target and upstream_var:
        return f"传播点：`{upstream_var}` 的值在此参与赋值到 `{target}`，污点继续传递。代码: `{short}`"
    if prop_call:
        return f"传播点：数据在 `{prop_call}()` 调用链中继续传递/变换。代码: `{short}`"
    if variables:
        return f"传播点：与变量 `{', '.join(variables[:2])}` 相关的逻辑保持污点可达性。代码: `{short}`"
    return f"传播点：此处连接上游输入与下游危险调用。代码: `{short}`"


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
        raw_desc = str(n.get("Desc") or n.get("desc") or n.get("description") or "").strip()
        node_file = str(n.get("file_path") or n.get("File") or file_path).strip()
        nodes.append(
            {
                "Type": ntype,
                "File": node_file,
                "StartLine": start_line,
                "EndLine": end_line,
                "Desc": _desc_for_node(ntype, code, raw_desc),
                "code": code,
            }
        )
    return nodes


def _to_issue(f: DirectedFinding) -> dict[str, Any]:
    evidence = f.evidence if isinstance(f.evidence, dict) else {}
    raw = evidence.get("raw") if isinstance(evidence.get("raw"), dict) else {}
    verification_method = (
        evidence.get("verification_method")
        or raw.get("verification_method")
        or ""
    )
    verification_details = (
        evidence.get("verification_details")
        or raw.get("verification_details")
        or ""
    )
    poc = raw.get("poc") if isinstance(raw.get("poc"), dict) else {}
    is_verified = bool(raw.get("is_verified")) or str(f.verdict).lower() in {"confirmed", "likely"}
    ai_explanation = (
        str(raw.get("ai_explanation") or "").strip()
        or str(verification_details or "").strip()
        or "CVE定向审计生成的 source->sink 证据路径。"
    )
    return {
        "CVEID": f.cve_id,
        "type": f.vulnerability_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "Nodes": _to_nodes(f),
        "confidence": f.confidence,
        "verdict": f.verdict,
        "is_verified": is_verified,
        "ai_explanation": ai_explanation,
        "verification_method": verification_method,
        "verification_details": verification_details,
        "poc": poc,
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
