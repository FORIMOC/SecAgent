"""
Verification Agent (漏洞验证层) - LLM 驱动版

LLM 是验证的大脑！
- LLM 决定如何验证每个漏洞
- LLM 构造验证策略
- LLM 分析验证结果
- LLM 判断是否为真实漏洞

类型: ReAct (真正的!)
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone

from .base import BaseAgent, AgentConfig, AgentResult, AgentType, AgentPattern, TaskHandoff
from ..json_parser import AgentJsonParser
from ..prompts import CORE_SECURITY_PRINCIPLES, VULNERABILITY_PRIORITIES

logger = logging.getLogger(__name__)


def _normalize_code(s: str) -> str:
    return re.sub(r"\s+", "", (s or "")).strip().lower()


def _code_tokens(s: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", s or "") if len(t) >= 2}


def _is_code_related(submitted: str, real: str) -> bool:
    """Weak relation check: only reject obviously unrelated code."""
    ns = _normalize_code(submitted)
    nr = _normalize_code(real)
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


def _build_brief_handoff_context(handoff: TaskHandoff | None) -> str:
    """Build lightweight context to avoid duplicating full handoff payload in prompt."""
    if not handoff:
        return ""
    lines: list[str] = ["## 上下文摘要", str(handoff.summary or "")[:240]]
    if handoff.attention_points:
        lines.append("### 重点关注")
        for p in handoff.attention_points[:6]:
            lines.append(f"- {str(p)[:140]}")
    if handoff.priority_areas:
        lines.append("### 优先文件")
        for a in handoff.priority_areas[:6]:
            lines.append(f"- {str(a)[:180]}")
    ctx = handoff.context_data if isinstance(handoff.context_data, dict) else {}
    evidence = ctx.get("analysis_tool_evidence")
    if isinstance(evidence, list) and evidence:
        lines.append("### Analysis 已有工具证据（可复用）")
        for item in evidence[:6]:
            if not isinstance(item, dict):
                continue
            tn = str(item.get("tool_name") or "")
            out = str(item.get("output_excerpt") or "")[:140]
            lines.append(f"- [{tn}] {out}")
    return "\n".join(lines)


def _read_file_range(project_root: str, file_path: str, start_line: int, end_line: int) -> str:
    try:
        root = Path(project_root).resolve()
        fp = (root / file_path).resolve()
        if not str(fp).startswith(str(root)) or not fp.is_file():
            return ""
        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(1, int(start_line))
        e = min(len(lines), int(end_line))
        if s > e:
            return ""
        return "\n".join(lines[s - 1:e]).strip()
    except Exception:
        return ""


def _validate_path_nodes(finding: Dict[str, Any], project_root: str) -> tuple[bool, str]:
    nodes = finding.get("source_to_sink_path")
    if not isinstance(nodes, list) or not nodes:
        return False, "missing source_to_sink_path"
    file_path = str(finding.get("file_path") or finding.get("file") or "").strip()
    if not file_path:
        for n in nodes:
            if isinstance(n, dict):
                fp = str(n.get("file_path") or n.get("File") or "").strip()
                if fp:
                    file_path = fp
                    break
    if not file_path:
        return False, "missing file_path"
    normalized_nodes: list[tuple[str, str, int, int, str]] = []
    for i, node in enumerate(nodes, start=1):
        if not isinstance(node, dict):
            return False, f"node#{i} not object"
        # 仅强制字段完整性，不强制 kind 类型和值。
        kind = str(node.get("kind") or node.get("Type") or "").strip()
        if not kind:
            return False, f"node#{i} missing kind"

        start_line = node.get("start_line", node.get("StartLine"))
        if start_line is None:
            start_line = node.get("line")
        end_line = node.get("end_line", node.get("EndLine"))
        if end_line is None:
            end_line = start_line
        try:
            start_line = int(start_line)
            end_line = int(end_line)
        except Exception:
            return False, f"node#{i} missing or invalid line"
        if start_line <= 0 or end_line < start_line:
            return False, f"node#{i} unreadable line range"

        code = str(node.get("code") or "").strip()
        if not code:
            return False, f"node#{i} missing code"

        node_file = str(node.get("file_path") or node.get("File") or file_path).strip()
        real = _read_file_range(project_root, node_file, start_line, end_line)
        if not real:
            return False, f"node#{i} file/range unreadable"
        # 弱约束：仅拒绝明显无关的 code，允许轻微字符缺失/差异。
        if not _is_code_related(code, real):
            return False, f"node#{i} code unrelated to file range"
        kind_norm = kind.strip().lower()
        if kind_norm in {"source", "sink", "propagation"}:
            normalized_nodes.append((kind_norm, node_file, start_line, end_line, _normalize_code(code)))

    # 退化路径检查：source/sink（以及 propagation）不能全部落在同一节点签名上。
    source_nodes = [n for n in normalized_nodes if n[0] == "source"]
    sink_nodes = [n for n in normalized_nodes if n[0] == "sink"]
    prop_nodes = [n for n in normalized_nodes if n[0] == "propagation"]
    if source_nodes and sink_nodes:
        source_sig = {(f, s, e, c) for _, f, s, e, c in source_nodes}
        sink_sig = {(f, s, e, c) for _, f, s, e, c in sink_nodes}
        if source_sig & sink_sig:
            if not prop_nodes:
                return False, "degenerate path: source and sink are identical"
            prop_sig = {(f, s, e, c) for _, f, s, e, c in prop_nodes}
            if (source_sig & sink_sig & prop_sig):
                return False, "degenerate path: source/propagation/sink are identical"
    return True, ""


def _collect_code_mismatch_details(findings: list[Dict[str, Any]], project_root: str, limit: int = 6) -> list[str]:
    details: list[str] = []
    for fidx, finding in enumerate(findings or [], start=1):
        if not isinstance(finding, dict):
            continue
        fallback_file = str(finding.get("file_path") or finding.get("file") or "").strip()
        nodes = finding.get("source_to_sink_path")
        if not isinstance(nodes, list):
            continue
        for nidx, node in enumerate(nodes, start=1):
            if not isinstance(node, dict):
                continue
            code = str(node.get("code") or "").strip()
            if not code:
                continue
            node_file = str(node.get("file_path") or node.get("File") or fallback_file).strip()
            start_line = node.get("start_line", node.get("StartLine"))
            if start_line is None:
                start_line = node.get("line")
            end_line = node.get("end_line", node.get("EndLine"))
            if end_line is None:
                end_line = start_line
            try:
                start_line = int(start_line)
                end_line = int(end_line)
            except Exception:
                continue
            real = _read_file_range(project_root, node_file, start_line, end_line)
            if not real:
                kind = str(node.get("kind") or node.get("Type") or "unknown").strip()
                details.append(
                    f"finding#{fidx} node#{nidx} ({kind}) @ {node_file}:{start_line}-{end_line}\n"
                    "提交code: "
                    + code[:220]
                    + "\n文件代码: <unreadable: file/range not readable>"
                )
                if len(details) >= limit:
                    return details
                continue
            if _normalize_code(code) in _normalize_code(real):
                continue
            kind = str(node.get("kind") or node.get("Type") or "unknown").strip()
            details.append(
                f"finding#{fidx} node#{nidx} ({kind}) @ {node_file}:{start_line}-{end_line}\n"
                f"提交code: {code[:220]}\n"
                f"文件代码: {real[:220]}"
            )
            if len(details) >= limit:
                return details
    return details


def _load_file_text(project_root: str, file_path: str) -> str:
    try:
        root = Path(project_root).resolve()
        fp = (root / file_path).resolve()
        if not str(fp).startswith(str(root)) or not fp.is_file():
            return ""
        return fp.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _locate_code_range_in_file(project_root: str, file_path: str, code: str) -> tuple[int, int] | None:
    text = _load_file_text(project_root, file_path)
    if not text or not (code or "").strip():
        return None
    code = code.strip()

    idx = text.find(code)
    if idx >= 0:
        start = text[:idx].count("\n") + 1
        end = start + code.count("\n")
        return start, end

    tokens = re.findall(r"\S+", code)
    if tokens:
        pattern = r"\s*".join(re.escape(t) for t in tokens)
        m = re.search(pattern, text, re.DOTALL)
        if m:
            start = text[: m.start()].count("\n") + 1
            segment = text[m.start() : m.end()]
            end = start + segment.count("\n")
            return start, end

    # 3) single-line fallback by strict normalized containment
    target = _normalize_code(code)
    if target:
        for i, line in enumerate(text.splitlines(), start=1):
            nline = _normalize_code(line)
            if nline and target in nline:
                return i, i

    # 4) conservative token-overlap fallback (avoid drifting to weakly-related lines)
    tokens = _code_tokens(code)
    if tokens:
        best_line = None
        best_overlap = 0
        for i, line in enumerate(text.splitlines(), start=1):
            lt = _code_tokens(line)
            if not lt:
                continue
            overlap = len(tokens & lt)
            if overlap > best_overlap:
                best_overlap = overlap
                best_line = i
        min_overlap = max(2, min(4, len(tokens) // 2))
        if best_line and best_overlap >= min_overlap:
            return best_line, best_line
    return None


def _set_node_location(node: Dict[str, Any], file_path: str, start_line: int, end_line: int) -> None:
    node["file_path"] = file_path
    node["File"] = file_path
    node["line"] = start_line
    node["start_line"] = start_line
    node["end_line"] = end_line
    node["StartLine"] = start_line
    node["EndLine"] = end_line


def _auto_repair_code_line_mismatch(findings: list[Dict[str, Any]], project_root: str) -> tuple[list[Dict[str, Any]], int]:
    repaired: list[Dict[str, Any]] = []
    fixed = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        f = dict(finding)
        nodes = f.get("source_to_sink_path")
        if not isinstance(nodes, list):
            repaired.append(f)
            continue
        fallback_file = str(f.get("file_path") or f.get("file") or "").strip()
        if not fallback_file:
            for n in nodes:
                if isinstance(n, dict):
                    fp = str(n.get("file_path") or n.get("File") or "").strip()
                    if fp:
                        fallback_file = fp
                        break
        new_nodes: list[Dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            n = dict(node)
            code = str(n.get("code") or "").strip()
            node_file = str(n.get("file_path") or n.get("File") or fallback_file).strip()
            start_line = n.get("start_line", n.get("StartLine"))
            if start_line is None:
                start_line = n.get("line")
            end_line = n.get("end_line", n.get("EndLine"))
            if end_line is None:
                end_line = start_line
            try:
                start_line = int(start_line)
                end_line = int(end_line)
            except Exception:
                start_line = None
                end_line = None

            if code and node_file and start_line and end_line and end_line >= start_line:
                real = _read_file_range(project_root, node_file, start_line, end_line)
                if real and _normalize_code(code) in _normalize_code(real):
                    _set_node_location(n, node_file, start_line, end_line)
                else:
                    located = _locate_code_range_in_file(project_root, node_file, code)
                    if located:
                        s, e = located
                        _set_node_location(n, node_file, s, e)
                        fixed += 1
            new_nodes.append(n)

        if fallback_file and not str(f.get("file_path") or "").strip():
            f["file_path"] = fallback_file
        f["source_to_sink_path"] = new_nodes
        repaired.append(f)
    return repaired, fixed


def _force_align_node_code_to_ranges(findings: list[Dict[str, Any]], project_root: str) -> tuple[list[Dict[str, Any]], int]:
    aligned: list[Dict[str, Any]] = []
    changed = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        f = dict(finding)
        nodes = f.get("source_to_sink_path")
        if not isinstance(nodes, list):
            aligned.append(f)
            continue
        fallback_file = str(f.get("file_path") or f.get("file") or "").strip()
        new_nodes: list[Dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            n = dict(node)
            node_file = str(n.get("file_path") or n.get("File") or fallback_file).strip()
            start_line = n.get("start_line", n.get("StartLine"))
            if start_line is None:
                start_line = n.get("line")
            end_line = n.get("end_line", n.get("EndLine"))
            if end_line is None:
                end_line = start_line
            try:
                start_line = int(start_line)
                end_line = int(end_line)
            except Exception:
                new_nodes.append(n)
                continue
            real = _read_file_range(project_root, node_file, start_line, end_line)
            if real:
                old = str(n.get("code") or "")
                if _normalize_code(old) != _normalize_code(real):
                    n["code"] = real
                    changed += 1
            new_nodes.append(n)
        f["source_to_sink_path"] = new_nodes
        aligned.append(f)
    return aligned, changed


def _overwrite_node_code_with_real_ranges(findings: list[Dict[str, Any]], project_root: str) -> list[Dict[str, Any]]:
    out: list[Dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        f = dict(finding)
        nodes = f.get("source_to_sink_path")
        if not isinstance(nodes, list):
            out.append(f)
            continue
        fallback_file = str(f.get("file_path") or f.get("file") or "").strip()
        new_nodes: list[Dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            n = dict(node)
            node_file = str(n.get("file_path") or n.get("File") or fallback_file).strip()
            start_line = n.get("start_line", n.get("StartLine"))
            if start_line is None:
                start_line = n.get("line")
            end_line = n.get("end_line", n.get("EndLine"))
            if end_line is None:
                end_line = start_line
            try:
                s = int(start_line)
                e = int(end_line)
            except Exception:
                new_nodes.append(n)
                continue
            real = _read_file_range(project_root, node_file, s, e)
            if real:
                n["code"] = real
            new_nodes.append(n)
        f["source_to_sink_path"] = new_nodes
        out.append(f)
    return out



VERIFICATION_SYSTEM_PROMPT = """你是 DeepAudit 的漏洞验证 Agent，一个**自主**的安全验证专家。

## 你的角色
你是漏洞验证的**大脑**，不是机械验证器。你需要：
1. 理解每个漏洞的上下文
2. 设计合适的验证策略
3. **编写测试代码进行动态验证**
4. 判断漏洞是否真实存在
5. 评估实际影响并生成 PoC

## 核心理念：Fuzzing Harness
即使整个项目无法运行，你也应该能够验证漏洞！方法是：
1. **提取目标函数** - 从代码中提取存在漏洞的函数
2. **构建 Mock** - 模拟函数依赖（数据库、HTTP、文件系统等）
3. **编写测试脚本** - 构造各种恶意输入测试函数
4. **分析执行结果** - 判断是否触发漏洞

## 你可以使用的工具

### 🔥 核心验证工具（优先使用）
- **run_code**: 执行你编写的测试代码（支持 Python/PHP/JS/Ruby/Go/Java/Bash）
  - 用于运行 Fuzzing Harness、PoC 脚本
  - 你可以完全控制测试逻辑
  - 参数: code (str), language (str), runtime_version (str, 可选), docker_image (str, 可选), timeout (int), description (str)
  - 镜像选择: 默认按 language+version 自动选镜像；如果环境需要，优先传 docker_image 指定镜像

- **extract_function**: 从源文件提取指定函数代码
  - 用于获取目标函数，构建 Fuzzing Harness
  - 参数: file_path (str), function_name (str), include_imports (bool)

### 文件操作
- **read_file**: 读取代码文件获取上下文
  参数: file_path (str), start_line (int, 可选), end_line (int, 可选)

### 沙箱工具
- **sandbox_exec**: 在沙箱中执行命令（用于验证命令执行类漏洞）
- **sandbox_http**: 发送 HTTP 请求（如果有运行的服务）

## 🔥 Fuzzing Harness 编写指南

### 原则
1. **你是大脑** - 你决定测试策略、payload、检测方法
2. **不依赖完整项目** - 提取函数，mock 依赖，隔离测试
3. **多种 payload** - 设计多种恶意输入，不要只测一个
4. **检测漏洞特征** - 根据漏洞类型设计检测逻辑

### 命令注入 Fuzzing Harness 示例 (Python)
```python
import os
import subprocess

# === Mock 危险函数来检测调用 ===
executed_commands = []
original_system = os.system

def mock_system(cmd):
    print(f"[DETECTED] os.system called: {cmd}")
    executed_commands.append(cmd)
    return 0

os.system = mock_system

# === 目标函数（从项目代码复制） ===
def vulnerable_function(user_input):
    os.system(f"echo {user_input}")

# === Fuzzing 测试 ===
payloads = [
    "test",           # 正常输入
    "; id",           # 命令连接符
    "| whoami",       # 管道
    "$(cat /etc/passwd)",  # 命令替换
    "`id`",           # 反引号
    "&& ls -la",      # AND 连接
]

print("=== Fuzzing Start ===")
for payload in payloads:
    print(f"\\nPayload: {payload}")
    executed_commands.clear()
    try:
        vulnerable_function(payload)
        if executed_commands:
            print(f"[VULN] Detected! Commands: {executed_commands}")
    except Exception as e:
        print(f"[ERROR] {e}")
```

### SQL 注入 Fuzzing Harness 示例 (Python)
```python
# === Mock 数据库 ===
class MockCursor:
    def __init__(self):
        self.queries = []

    def execute(self, query, params=None):
        print(f"[SQL] Query: {query}")
        print(f"[SQL] Params: {params}")
        self.queries.append((query, params))

        # 检测 SQL 注入特征
        if params is None and ("'" in query or "OR" in query.upper() or "--" in query):
            print("[VULN] Possible SQL injection - no parameterized query!")

class MockDB:
    def cursor(self):
        return MockCursor()

# === 目标函数 ===
def get_user(db, user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")  # 漏洞！

# === Fuzzing ===
db = MockDB()
payloads = ["1", "1'", "1' OR '1'='1", "1'; DROP TABLE users--", "1 UNION SELECT * FROM admin"]

for p in payloads:
    print(f"\\n=== Testing: {p} ===")
    get_user(db, p)
```

### PHP 命令注入 Fuzzing Harness 示例
```php
// 注意：php -r 不需要 <?php 标签

// Mock $_GET
$_GET['cmd'] = '; id';
$_POST['cmd'] = '; id';
$_REQUEST['cmd'] = '; id';

// 目标代码（从项目复制）
$output = shell_exec($_GET['cmd']);
echo "Output: " . $output;

// 如果有输出，说明命令被执行
if ($output) {
    echo "\\n[VULN] Command executed!";
}
```

### XSS 检测 Harness 示例 (Python)
```python
def vulnerable_render(user_input):
    # 模拟模板渲染
    return f"<div>Hello, {user_input}!</div>"

payloads = [
    "test",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",  # SSTI
]

for p in payloads:
    output = vulnerable_render(p)
    print(f"Input: {p}")
    print(f"Output: {output}")
    # 检测：payload 是否原样出现在输出中
    if p in output and ("<" in p or "{{" in p):
        print("[VULN] XSS - input not escaped!")
```

## 验证策略

### 对于可执行的漏洞（命令注入、代码注入等）
1. 使用 `extract_function` 或 `read_file` 获取目标代码
2. 编写 Fuzzing Harness，mock 危险函数来检测调用
3. 使用 `run_code` 执行 Harness
4. 分析输出，确认漏洞是否触发

### 对于数据泄露型漏洞（SQL注入、路径遍历等）
1. 获取目标代码
2. 编写 Harness，mock 数据库/文件系统
3. 检查是否能构造恶意查询/路径
4. 分析输出

### 对于配置类漏洞（硬编码密钥等）
1. 使用 `read_file` 直接读取配置文件
2. 验证敏感信息是否存在
3. 评估影响（密钥是否有效、权限范围等）

## 工作流程
你将收到一批待验证的漏洞发现。对于每个发现：

```
Thought: [分析漏洞类型，设计验证策略]
Action: [工具名称]
Action Input: [参数]
```

验证完所有发现后，输出：

```
Thought: [总结验证结果]
Final Answer: [JSON 格式的验证报告]
```

## ⚠️ 输出格式要求（严格遵守）

**禁止使用 Markdown 格式标记！** 你的输出必须是纯文本格式：

✅ 正确格式：
```
Thought: 我需要读取 search.php 文件来验证 SQL 注入漏洞。
Action: read_file
Action Input: {"file_path": "search.php"}
```

❌ 错误格式（禁止使用）：
```
**Thought:** 我需要读取文件
**Action:** read_file
**Action Input:** {"file_path": "search.php"}
```

规则：
1. 不要在 Thought:、Action:、Action Input:、Final Answer: 前后添加 `**`
2. 不要使用其他 Markdown 格式（如 `###`、`*斜体*` 等）
3. Action Input 必须是完整的 JSON 对象，不能为空或截断
4. 单轮输出必须二选一：`Thought+Action+Action Input` 或 `Thought+Final Answer`
5. 禁止在同一轮里同时输出 `Action` 和 `Final Answer`

## Final Answer 格式
```json
{
    "findings": [
        {
            ...原始发现字段...,
            "source_to_sink_path": [
                {"Type": "Source|Propagation|Sink", "File": "...", "StartLine": 0, "EndLine": 0, "Desc": "...", "code": "..."},
                {"Type": "Source|Propagation|Sink", "File": "...", "StartLine": 0, "EndLine": 0, "Desc": "...", "code": "..."}
            ],
            "verdict": "confirmed/likely/uncertain/false_positive",
            "confidence": 0.0-1.0,
            "is_verified": true/false,
            "verification_method": "描述验证方法",
            "verification_details": "验证过程和结果详情",
            "poc": {
                "description": "PoC 描述",
                "steps": ["步骤1", "步骤2"],
                "payload": "完整可执行的 PoC 代码或命令",
                "harness_code": "Fuzzing Harness 代码（如果使用）"
            },
            "impact": "实际影响分析",
            "recommendation": "修复建议"
        }
    ],
    "summary": {
        "total": 数量,
        "confirmed": 数量,
        "likely": 数量,
        "false_positive": 数量
    }
}
```

## Final Answer 一次性 JSON 硬约束
1. 当你决定结束时，必须只输出一个完整结果：`Final Answer: { ... }`
2. `Final Answer:` 后面必须是可被 `json.loads` 直接解析的单个 JSON 对象
3. 禁止输出 Markdown 代码块（```json）、注释、`...`、尾随解释文本
4. 不要分多次补充字段；缺失字段也要给空值（`[]`、`""`、`null`）
5. 提交 Final Answer 的这一轮，不要再输出 Action 或 Action Input

## 验证判定标准
- **confirmed**: 漏洞确认存在且可利用，有明确证据（如 Harness 成功触发）
- **likely**: 高度可能存在漏洞，代码分析明确但无法动态验证
- **uncertain**: 需要更多信息才能判断
- **false_positive**: 确认是误报，有明确理由

## 🚨 防止幻觉验证（关键！）

**Analysis Agent 可能报告不存在的文件！** 你必须验证：

1. **文件必须存在** - 使用 read_file 读取发现中指定的文件
   - 如果 read_file 返回"文件不存在"，该发现是 **false_positive**
   - 不要尝试"猜测"正确的文件路径

2. **代码必须匹配** - 路径节点中的 `code` 必须在对应文件行号范围内真实存在
   - 如果文件内容与描述不符，该发现是 **false_positive**

3. **不要"填补"缺失信息** - 如果发现缺少关键信息（如文件路径为空），标记为 uncertain

❌ 错误做法：
```
发现: "SQL注入在 api/database.py:45"
read_file 返回: "文件不存在"
判定: confirmed  <- 这是错误的！
```

✅ 正确做法：
```
发现: "SQL注入在 api/database.py:45"
read_file 返回: "文件不存在"
判定: false_positive，理由: "文件 api/database.py 不存在"
```

## ⚠️ 关键约束
1. **必须先调用工具验证** - 不允许仅凭已知信息直接判断
2. **优先静态证据** - 先用 read_file/search_code/dataflow_analysis 确认证据链；仅在环境可用且必要时再用 run_code
3. **PoC 必须完整可执行** - poc.payload 应该是可直接运行的代码
4. **不要假设环境** - 沙箱中没有运行的服务，需要 mock
5. **节点顺序要求** - 如果给出 `source_to_sink_path`，必须严格按 `source -> propagation -> sink` 顺序提交
6. **Final Answer 前逐节点自检** - 对每个节点执行 `read_file(file_path=File, start_line=StartLine, end_line=EndLine)`，确认返回内容包含该节点 code；不满足则先修正行号或 code 再提交
7. **Desc 必须语义化** - `source_to_sink_path[].Desc` 必须明确说明该节点如何传播污点，并包含真实变量名 + 函数/操作名，禁止模板化空泛描述

## 重要原则
1. **你是验证的大脑** - 你决定如何测试，工具只提供执行能力
2. **动态验证优先** - 能运行代码验证的就不要仅靠静态分析
3. **质量优先** - 宁可漏报也不要误报太多
4. **证据支撑** - 每个判定都需要有依据

现在开始验证漏洞发现！"""


@dataclass
class VerificationStep:
    """验证步骤"""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict] = None


class VerificationAgent(BaseAgent):
    """
    漏洞验证 Agent - LLM 驱动版
    
    LLM 全程参与，自主决定：
    1. 如何验证每个漏洞
    2. 使用什么工具
    3. 判断真假
    """
    
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        # 组合增强的系统提示词
        full_system_prompt = f"{VERIFICATION_SYSTEM_PROMPT}\n\n{CORE_SECURITY_PRINCIPLES}\n\n{VULNERABILITY_PRIORITIES}"
        
        config = AgentConfig(
            name="Verification",
            agent_type=AgentType.VERIFICATION,
            pattern=AgentPattern.REACT,
            max_iterations=25,
            system_prompt=full_system_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[VerificationStep] = []
        self._code_mismatch_retries: int = 0
        self._runtime_tool_failures: Dict[str, int] = {}
        self._blocked_runtime_tools: set[str] = set()



    
    def _parse_llm_response(self, response: str) -> VerificationStep:
        """解析 LLM 响应 - 增强版，更健壮地提取思考内容"""
        step = VerificationStep(thought="")

        # 🔥 v2.1: 预处理 - 移除 Markdown 格式标记（LLM 有时会输出 **Action:** 而非 Action:）
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action\s*[:：]\s*\*\*', 'Action:', cleaned_response, flags=re.IGNORECASE)
        cleaned_response = re.sub(r'\*\*Action Input\s*[:：]\s*\*\*', 'Action Input:', cleaned_response, flags=re.IGNORECASE)
        cleaned_response = re.sub(r'\*\*Thought\s*[:：]\s*\*\*', 'Thought:', cleaned_response, flags=re.IGNORECASE)
        cleaned_response = re.sub(r'\*\*Final Answer\s*[:：]\s*\*\*', 'Final Answer:', cleaned_response, flags=re.IGNORECASE)
        cleaned_response = re.sub(r'\*\*Observation\s*[:：]\s*\*\*', 'Observation:', cleaned_response, flags=re.IGNORECASE)
        # 兼容中文冒号与行首前缀变体
        cleaned_response = re.sub(r'(?im)^\s*Thought\s*[：]\s*', 'Thought: ', cleaned_response)
        cleaned_response = re.sub(r'(?im)^\s*Action Input\s*[：]\s*', 'Action Input: ', cleaned_response)
        cleaned_response = re.sub(r'(?im)^\s*Action\s*[：]\s*', 'Action: ', cleaned_response)
        cleaned_response = re.sub(r'(?im)^\s*Final Answer\s*[：]\s*', 'Final Answer: ', cleaned_response)
        cleaned_response = re.sub(r'(?im)^\s*Observation\s*[：]\s*', 'Observation: ', cleaned_response)

        # 🔥 首先尝试提取明确的 Thought 标记
        thought_match = re.search(r'(?is)(?:^|\n)\s*Thought:\s*(.*?)(?=(?:\n\s*(?:Action|Final Answer)\s*:)|\Z)', cleaned_response)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # 先解析 Action/Final 的位置，避免同时出现时误判为 Final
        action_match = re.search(r'(?im)(?:^|\n)\s*Action:\s*`?([A-Za-z_][A-Za-z0-9_-]*)`?', cleaned_response)
        final_match = re.search(r'(?is)(?:^|\n)\s*Final Answer:\s*(.*)$', cleaned_response)
        action_pos = action_match.start() if action_match else -1
        final_pos = final_match.start() if final_match else -1
        should_parse_final = bool(
            final_match and (
                not action_match or (final_pos >= 0 and final_pos < action_pos)
            )
        )

        # 🔥 检查是否是最终答案（仅当 Final 先于 Action 或无 Action）
        if should_parse_final:
            step.is_final = True
            answer_text = final_match.group(1).strip()
            answer_text = re.sub(r'```json\s*', '', answer_text)
            answer_text = re.sub(r'```\s*', '', answer_text)
            # 使用增强的 JSON 解析器
            step.final_answer = AgentJsonParser.parse(
                answer_text,
                default={"findings": [], "raw_answer": answer_text}
            )
            # 确保 findings 格式正确
            if "findings" in step.final_answer:
                step.final_answer["findings"] = [
                    f for f in step.final_answer["findings"]
                    if isinstance(f, dict)
                ]

            # 🔥 如果没有提取到 thought，使用 Final Answer 前的内容作为思考
            if not step.thought:
                before_final = cleaned_response[:cleaned_response.find('Final Answer:')].strip()
                if before_final:
                    before_final = re.sub(r'^Thought:\s*', '', before_final)
                    step.thought = before_final[:500] if len(before_final) > 500 else before_final

            return step

        # 🔥 提取 Action
        if action_match:
            step.action = action_match.group(1).strip()

            # 🔥 如果没有提取到 thought，提取 Action 之前的内容作为思考
            if not step.thought:
                if action_pos > 0:
                    before_action = cleaned_response[:action_pos].strip()
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # 🔥 提取 Action Input - 增强版，处理多种格式
        input_match = re.search(
            r'(?is)(?:^|\n)\s*Action Input:\s*(.*?)(?=(?:\n\s*(?:Thought|Action|Observation|Final Answer)\s*:)|\Z)',
            cleaned_response,
        )
        if input_match:
            input_text = input_match.group(1).strip()
            input_text = re.sub(r'```json\s*', '', input_text)
            input_text = re.sub(r'```\s*', '', input_text)

            # 🔥 v2.1: 如果 Action Input 为空或只有 **，记录警告
            if not input_text or input_text == '**' or input_text.strip() == '':
                logger.warning(f"[Verification] Action Input is empty or malformed: '{input_text}'")
                step.action_input = {}
            else:
                # 使用增强的 JSON 解析器
                step.action_input = AgentJsonParser.parse(
                    input_text,
                    default={"raw_input": input_text}
                )
        elif step.action:
            # 🔥 v2.1: 有 Action 但没有 Action Input，记录警告
            logger.warning(f"[Verification] Action '{step.action}' found but no Action Input")
            step.action_input = {}

        # 🔥 最后的 fallback：如果整个响应没有任何标记，整体作为思考
        if not step.thought and not step.action and not step.is_final:
            if response.strip():
                step.thought = response.strip()[:500]

        return step
    
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """
        执行漏洞验证 - LLM 全程参与！
        """
        import time
        start_time = time.time()
        
        previous_results = input_data.get("previous_results", {})
        config = input_data.get("config", {})
        project_root = input_data.get("project_root", ".")
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        
        # 🔥 处理交接信息
        handoff = input_data.get("handoff")
        if handoff:
            from .base import TaskHandoff
            if isinstance(handoff, dict):
                handoff = TaskHandoff.from_dict(handoff)
            self.receive_handoff(handoff)

        # 从 previous_results 中补充加载 Analysis 的共享工具缓存（handoff 不可用时兜底）
        shared_cache_before = len(self._shared_tool_cache)
        try:
            if isinstance(previous_results, dict):
                # 常见格式: previous_results["analysis"] = {"data": {...}}
                analysis_entry = previous_results.get("analysis")
                if isinstance(analysis_entry, dict):
                    analysis_data = analysis_entry.get("data", analysis_entry)
                    if isinstance(analysis_data, dict):
                        for cache_key in ("shared_tool_cache", "tool_cache"):
                            cache_blob = analysis_data.get(cache_key)
                            if cache_blob:
                                self.load_shared_tool_cache(cache_blob)
                # 兼容直接挂在 previous_results 顶层
                for cache_key in ("shared_tool_cache", "tool_cache"):
                    cache_blob = previous_results.get(cache_key)
                    if cache_blob:
                        self.load_shared_tool_cache(cache_blob)
        except Exception as e:
            logger.debug(f"[Verification] Failed loading shared cache from previous_results: {e}")
        shared_cache_loaded = max(0, len(self._shared_tool_cache) - shared_cache_before)
        
        # 收集所有待验证的发现
        findings_to_verify = []
        
        # 🔥 优先从交接信息获取发现
        if self._incoming_handoff and self._incoming_handoff.key_findings:
            findings_to_verify = self._incoming_handoff.key_findings.copy()
            logger.info(f"[Verification] 从交接信息获取 {len(findings_to_verify)} 个发现")
        else:
            # 🔥 修复：处理 Orchestrator 传递的多种数据格式
            
            # 格式1: Orchestrator 直接传递 {"findings": [...]}
            if isinstance(previous_results, dict) and "findings" in previous_results:
                direct_findings = previous_results.get("findings", [])
                if isinstance(direct_findings, list):
                    for f in direct_findings:
                        if isinstance(f, dict):
                            # 🔥 Always verify Critical/High findings to generate PoC, even if Analysis sets needs_verification=False
                            severity = str(f.get("severity", "")).lower()
                            needs_verify = f.get("needs_verification", True)
                            
                            if needs_verify or severity in ["critical", "high"]:
                                findings_to_verify.append(f)
                    logger.info(f"[Verification] 从 previous_results.findings 获取 {len(findings_to_verify)} 个发现")
            
            # 格式2: 传统格式 {"phase_name": {"data": {"findings": [...]}}}
            if not findings_to_verify:
                for phase_name, result in previous_results.items():
                    if phase_name == "findings":
                        continue  # 已处理
                    
                    if isinstance(result, dict):
                        data = result.get("data", {})
                    else:
                        data = result.data if hasattr(result, 'data') else {}
                    
                    if isinstance(data, dict):
                        phase_findings = data.get("findings", [])
                        for f in phase_findings:
                            if isinstance(f, dict):
                                severity = str(f.get("severity", "")).lower()
                                needs_verify = f.get("needs_verification", True)
                                
                                if needs_verify or severity in ["critical", "high"]:
                                    findings_to_verify.append(f)
                
                if findings_to_verify:
                    logger.info(f"[Verification] 从传统格式获取 {len(findings_to_verify)} 个发现")
        
        # 🔥 如果仍然没有发现，尝试从 input_data 的其他字段提取
        if not findings_to_verify:
            # 尝试从 task 或 task_context 中提取描述的漏洞
            if task and ("发现" in task or "漏洞" in task or "findings" in task.lower()):
                logger.warning(f"[Verification] 无法从结构化数据获取发现，任务描述: {task[:200]}")
                # 创建一个提示 LLM 从任务描述中理解漏洞的特殊处理
                await self.emit_event("warning", f"无法从结构化数据获取发现列表，将基于任务描述进行验证")
        
        # 去重
        findings_to_verify = self._deduplicate(findings_to_verify)

        # 🔥 FIX: 优先处理有明确文件路径的发现，将没有文件路径的发现放到后面
        # 这确保 Analysis 的具体发现优先于 Recon 的泛化描述
        def has_valid_file_path(finding: Dict) -> bool:
            file_path = finding.get("file_path", "")
            return bool(file_path and file_path.strip() and file_path.lower() not in ["unknown", "n/a", ""])

        findings_with_path = [f for f in findings_to_verify if has_valid_file_path(f)]
        findings_without_path = [f for f in findings_to_verify if not has_valid_file_path(f)]

        # 合并：有路径的在前，没路径的在后
        findings_to_verify = findings_with_path + findings_without_path

        if findings_with_path:
            logger.info(f"[Verification] 优先处理 {len(findings_with_path)} 个有明确文件路径的发现")
        if findings_without_path:
            logger.info(f"[Verification] 还有 {len(findings_without_path)} 个发现需要自行定位文件")

        if not findings_to_verify:
            logger.warning(f"[Verification] 没有需要验证的发现! previous_results keys: {list(previous_results.keys()) if isinstance(previous_results, dict) else 'not dict'}")
            await self.emit_event("warning", "没有需要验证的发现 - 可能是数据格式问题")
            return AgentResult(
                success=True,
                data={"findings": [], "verified_count": 0, "note": "未收到待验证的发现"},
            )
        
        # 限制数量
        findings_to_verify = findings_to_verify[:8]
        
        await self.emit_event(
            "info",
            f"开始验证 {len(findings_to_verify)} 个发现"
        )
        
        # 🔥 记录工作开始
        self.record_work(f"开始验证 {len(findings_to_verify)} 个漏洞发现")
        
        # 🔥 构建包含交接上下文的初始消息
        handoff_context = _build_brief_handoff_context(self._incoming_handoff)
        shared_evidence = self.get_shared_tool_cache_digest(max_items=8)
        shared_evidence_text = ""
        if shared_evidence:
            lines = ["## 可复用的前序工具证据（Analysis -> Verification）"]
            for idx, item in enumerate(shared_evidence, 1):
                if not isinstance(item, dict):
                    continue
                tn = str(item.get("tool_name") or "tool")
                excerpt = str(item.get("output_excerpt") or "").replace("\n", " ").strip()[:180]
                lines.append(f"{idx}. [{tn}] {excerpt}")
            lines.append("说明: 对完全相同的工具+参数调用会自动命中共享缓存，避免重复执行。")
            shared_evidence_text = "\n".join(lines)
        if shared_cache_loaded > 0:
            await self.emit_event(
                "info",
                f"已从前序结果加载 {shared_cache_loaded} 条可复用工具证据缓存"
            )
        
        findings_summary = []
        for i, f in enumerate(findings_to_verify):
            # 🔥 FIX: 正确处理 file_path 格式，可能包含行号 (如 "app.py:36")
            file_path = f.get('file_path', 'unknown')
            line_start = f.get('line_start', 0)

            # 如果 file_path 已包含行号，提取出来
            if isinstance(file_path, str) and ':' in file_path:
                parts = file_path.split(':', 1)
                if len(parts) == 2 and parts[1].split()[0].isdigit():
                    file_path = parts[0]
                    try:
                        line_start = int(parts[1].split()[0])
                    except ValueError:
                        pass

            display_code = ""
            path_nodes = f.get("source_to_sink_path")
            if isinstance(path_nodes, list):
                for n in path_nodes:
                    if isinstance(n, dict):
                        c = str(n.get("code") or "").strip()
                        if c:
                            display_code = c
                            break
            if not display_code:
                display_code = str(f.get("code_snippet") or "")[:220]

            findings_summary.append(f"""
### 发现 {i+1}: {f.get('title', 'Unknown')}
- 类型: {f.get('vulnerability_type', 'unknown')}
- 严重度: {f.get('severity', 'medium')}
- 文件: {file_path} (行 {line_start})
- 代码:
```
{(display_code or 'N/A')[:220]}
```
- 描述: {f.get('description', 'N/A')[:300]}
""")
        
        initial_message = f"""请验证以下 {len(findings_to_verify)} 个安全发现。

{handoff_context if handoff_context else ''}
{shared_evidence_text if shared_evidence_text else ''}

## 待验证发现
{''.join(findings_summary)}

## ⚠️ 重要验证指南
1. **直接使用上面列出的文件路径** - 不要猜测或搜索其他路径
2. **如果文件路径包含冒号和行号** (如 "app.py:36"), 请提取文件名 "app.py" 并使用 read_file 读取
3. **先读取文件内容，再判断漏洞是否存在**
4. **不要假设文件在子目录中** - 使用发现中提供的精确路径
5. **优先复用前序证据** - 若上方已有 Analysis 工具结果，先基于这些证据推进；仅在缺少关键证据时再调用新工具

## 验证要求
- 验证级别: {config.get('verification_level', 'standard')}

## 可用工具
{self.get_tools_description()}

请开始验证。对于每个发现：
1. 首先使用 read_file 读取发现中指定的文件（使用精确路径）
2. 分析代码上下文
3. 判断是否为真实漏洞
{f"特别注意 Analysis Agent 提到的关注点。" if handoff_context else ""}"""

        # 初始化对话历史
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]
        
        self._steps = []
        self._runtime_tool_failures = {}
        self._blocked_runtime_tools = set()
        final_result = None
        
        await self.emit_thinking("🔐 Verification Agent 启动，LLM 开始自主验证漏洞...")
        
        try:
            for iteration in range(self.config.max_iterations):
                if self.is_cancelled:
                    break
                
                self._iteration = iteration + 1
                
                # 🔥 再次检查取消标志（在LLM调用之前）
                if self.is_cancelled:
                    await self.emit_thinking("🛑 任务已取消，停止执行")
                    break
                
                # 调用 LLM 进行思考和决策（流式输出）
                try:
                    llm_output, tokens_this_round = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                except asyncio.CancelledError:
                    logger.info(f"[{self.name}] LLM call cancelled")
                    break
                
                self._total_tokens += tokens_this_round

                # 🔥 Handle empty LLM response to prevent loops
                if not llm_output or not llm_output.strip():
                    logger.warning(f"[{self.name}] Empty LLM response in iteration {self._iteration}")
                    await self.emit_llm_decision("收到空响应", "LLM 返回内容为空，尝试重试通过提示")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "Received empty response. Please output your Thought and Action.",
                    })
                    continue

                # 解析 LLM 响应
                step = self._parse_llm_response(llm_output)
                self._steps.append(step)
                
                # 🔥 发射 LLM 思考内容事件 - 展示验证的思考过程
                if step.thought:
                    await self.emit_llm_thought(step.thought, iteration + 1)
                
                # 添加 LLM 响应到历史
                self._conversation_history.append({
                    "role": "assistant",
                    "content": llm_output,
                })
                
                # 检查是否完成
                if step.is_final:
                    # 🔥 强制检查：必须至少调用过一次工具才能完成
                    if self._tool_calls == 0:
                        logger.warning(f"[{self.name}] LLM tried to finish without any tool calls! Forcing tool usage.")
                        await self.emit_thinking("⚠️ 拒绝过早完成：必须先使用工具验证漏洞")
                        self._conversation_history.append({
                            "role": "user",
                            "content": (
                                "⚠️ **系统拒绝**: 你必须先使用工具验证漏洞！\n\n"
                                "不允许在没有调用任何工具的情况下直接输出 Final Answer。\n\n"
                                "请立即使用以下工具之一进行验证：\n"
                                "1. `read_file` - 读取漏洞所在文件的代码\n"
                                "2. `run_code` - 编写并执行 Fuzzing Harness 验证漏洞\n"
                                "3. `extract_function` - 提取目标函数进行分析\n\n"
                                "现在请输出 Thought 和 Action，开始验证第一个漏洞。"
                            ),
                        })
                        continue

                    if step.final_answer and "findings" in step.final_answer:
                        if self._code_mismatch_retries >= 2:
                            repaired_findings, auto_fixed = _auto_repair_code_line_mismatch(
                                step.final_answer.get("findings", []),
                                project_root,
                            )
                            if auto_fixed > 0:
                                step.final_answer["findings"] = repaired_findings
                                await self.emit_thinking(
                                    f"🛠️ 稳定性修复：已自动修正 {auto_fixed} 个 code/line 漂移节点，继续校验"
                                )
                        invalids = []
                        for idx, f in enumerate(step.final_answer.get("findings", []), start=1):
                            if not isinstance(f, dict):
                                invalids.append(f"finding#{idx} not object")
                                continue
                            ok, reason = _validate_path_nodes(f, project_root)
                            if not ok:
                                invalids.append(f"finding#{idx}: {reason}")
                        if invalids:
                            path_invalids = [
                                x for x in invalids
                                if (
                                    "code not found in file range" in x
                                    or "code unrelated to file range" in x
                                    or "file/range unreadable" in x
                                )
                            ]
                            if path_invalids:
                                self._code_mismatch_retries += 1
                            else:
                                self._code_mismatch_retries = 0
                            # 稳定性兜底：连续多次因路径节点不可对齐失败时，直接按行号范围回填 code 再验证，避免长时间循环。
                            if self._code_mismatch_retries >= 6 and len(path_invalids) == len(invalids):
                                aligned_findings, aligned_count = _force_align_node_code_to_ranges(
                                    step.final_answer.get("findings", []),
                                    project_root,
                                )
                                if aligned_count > 0:
                                    second_invalids = []
                                    for idx2, f2 in enumerate(aligned_findings, start=1):
                                        ok2, reason2 = _validate_path_nodes(f2, project_root)
                                        if not ok2:
                                            second_invalids.append(f"finding#{idx2}: {reason2}")
                                    if not second_invalids:
                                        step.final_answer["findings"] = aligned_findings
                                        invalids = []
                                        await self.emit_thinking(
                                            f"🧯 稳定性兜底：连续重提后已自动按行号回填 {aligned_count} 个节点 code，并通过校验"
                                        )
                                    else:
                                        invalids = second_invalids
                                        path_invalids = [
                                            x for x in invalids
                                            if (
                                                "code not found in file range" in x
                                                or "code unrelated to file range" in x
                                                or "file/range unreadable" in x
                                            )
                                        ]
                            if not invalids:
                                self._code_mismatch_retries = 0
                                step.final_answer["findings"] = _overwrite_node_code_with_real_ranges(
                                    step.final_answer.get("findings", []),
                                    project_root,
                                )
                                await self.emit_llm_decision("完成漏洞验证", "LLM 结果经稳定性修复后通过校验")
                                final_result = step.final_answer
                                await self.emit_llm_complete(
                                    f"验证完成",
                                    self._total_tokens
                                )
                                break
                            await self.emit_thinking("⚠️ 拒收 Final Answer：路径节点结构不满足要求")
                            await self.emit_thinking("📌 拒收原因: " + "; ".join(invalids[:8]))
                            rejected_text = json.dumps(step.final_answer, ensure_ascii=False, indent=2)
                            if len(rejected_text) > 12000:
                                rejected_text = rejected_text[:12000] + "\n... (truncated)"
                            await self.emit_thinking(f"🧾 被拒收的 Final Answer:\n{rejected_text}")
                            mismatch_detail_text = ""
                            if self._code_mismatch_retries > 2 and path_invalids:
                                details = _collect_code_mismatch_details(step.final_answer.get("findings", []), project_root)
                                if details:
                                    mismatch_detail_text = (
                                        "\n\n以下是 code 与行号范围不匹配的节点，请逐个修正后再提交：\n"
                                        + "\n\n".join(f"- {d}" for d in details)
                                    )
                                    detail_preview = mismatch_detail_text[:6000]
                                    if len(mismatch_detail_text) > 6000:
                                        detail_preview += "\n... (truncated)"
                                    await self.emit_thinking("🔎 不匹配节点文件实码对照如下：\n" + detail_preview)
                            self._conversation_history.append({
                                "role": "user",
                                "content": (
                                    "❌ 你的 Final Answer 被拒收，原因如下：\n"
                                    + "\n".join(f"- {x}" for x in invalids[:8])
                                    + "\n\n请重新提交 findings，要求：\n"
                                    "1) 每个 finding 必须包含 source_to_sink_path；\n"
                                    "2) 每个节点必须包含 kind/start_line/end_line/code（或可解析的 line）；\n"
                                    "3) file_path 与行号范围必须在仓库中可读取。\n"
                                    "4) 对于 code 不匹配的节点：必须逐个核对节点语义，判断是行号范围给错还是 code 内容给错，并修正后再提交。"
                                    + mismatch_detail_text
                                ),
                            })
                            continue

                    step.final_answer["findings"] = _overwrite_node_code_with_real_ranges(
                        step.final_answer.get("findings", []),
                        project_root,
                    )
                    await self.emit_llm_decision("完成漏洞验证", "LLM 判断验证已充分")
                    final_result = step.final_answer
                    
                    # 🔥 记录洞察和工作
                    if final_result and "findings" in final_result:
                        verified_count = len([f for f in final_result["findings"] if f.get("is_verified")])
                        fp_count = len([f for f in final_result["findings"] if f.get("verdict") == "false_positive"])
                        self.add_insight(f"验证了 {len(final_result['findings'])} 个发现，{verified_count} 个确认，{fp_count} 个误报")
                        self.record_work(f"完成漏洞验证: {verified_count} 个确认, {fp_count} 个误报")
                    
                    await self.emit_llm_complete(
                        f"验证完成",
                        self._total_tokens
                    )
                    break
                
                # 执行工具
                if step.action:
                    runtime_tools = {
                        "run_code",
                        "php_test",
                        "sandbox_exec",
                        "sandbox_http",
                        "verify_vulnerability",
                        "test_command_injection",
                    }
                    if step.action in self._blocked_runtime_tools:
                        observation = (
                            f"⚠️ 工具 {step.action} 在当前CVE中已多次失败，已自动禁用。\n"
                            "请改用 read_file/search_code/dataflow_analysis/vulnerability_validation 继续验证，"
                            "或在证据不足时给出 uncertain。"
                        )
                        step.observation = observation
                        await self.emit_llm_observation(observation)
                        self._conversation_history.append({
                            "role": "user",
                            "content": f"Observation:\n{observation}",
                        })
                        continue

                    # 🔥 发射 LLM 动作决策事件
                    await self.emit_llm_action(step.action, step.action_input or {})
                    
                    start_tool_time = time.time()
                    
                    # 🔥 智能循环检测: 追踪重复调用 (无论成功与否)
                    tool_call_key = f"{step.action}:{json.dumps(step.action_input or {}, sort_keys=True)}"
                    
                    if not hasattr(self, '_tool_call_counts'):
                        self._tool_call_counts = {}
                    
                    self._tool_call_counts[tool_call_key] = self._tool_call_counts.get(tool_call_key, 0) + 1
                    
                    # 如果同一操作重复尝试超过3次，强制干预
                    if self._tool_call_counts[tool_call_key] > 3:
                        logger.warning(f"[{self.name}] Detected repetitive tool call loop: {tool_call_key}")
                        observation = (
                            f"⚠️ **系统干预**: 你已经使用完全相同的参数调用了工具 '{step.action}' 超过3次。\n"
                            "请**不要**重复尝试相同的操作。这是无效的。\n"
                            "请尝试：\n"
                            "1. 修改参数 (例如改变 input payload)\n"
                            "2. 使用不同的工具 (例如从 sandbox_exec 换到 php_test)\n"
                            "3. 如果之前的尝试都失败了，请尝试 read_file/search_code 重新分析代码\n"
                            "4. 如果无法验证，请输出 Final Answer 并标记为 uncertain"
                        )
                        
                        # 模拟观察结果，跳过实际执行
                        step.observation = observation
                        await self.emit_llm_observation(observation)
                        self._conversation_history.append({
                            "role": "user",
                            "content": f"Observation:\n{observation}",
                        })
                        continue

                    # 🔥 循环检测：追踪工具调用失败历史 (保留原有逻辑用于错误追踪)
                    if not hasattr(self, '_failed_tool_calls'):
                        self._failed_tool_calls = {}
                    
                    observation = await self.execute_tool(
                        step.action,
                        step.action_input or {}
                    )
                    
                    # 🔥 检测工具调用失败并追踪
                    is_tool_error = (
                        "失败" in observation or 
                        "错误" in observation or 
                        "不存在" in observation or
                        "文件过大" in observation or
                        "Error" in observation
                    )
                    
                    if is_tool_error:
                        if step.action in runtime_tools:
                            self._runtime_tool_failures[step.action] = self._runtime_tool_failures.get(step.action, 0) + 1
                            if self._runtime_tool_failures[step.action] >= 1:
                                self._blocked_runtime_tools.add(step.action)
                                observation += (
                                    f"\n\n⚠️ 运行时工具 {step.action} 本次已失败，将在当前CVE中禁用该工具，"
                                    "避免无效重试和超时。"
                                )
                        self._failed_tool_calls[tool_call_key] = self._failed_tool_calls.get(tool_call_key, 0) + 1
                        fail_count = self._failed_tool_calls[tool_call_key]
                        
                        # 🔥 如果同一调用连续失败3次，添加强制跳过提示
                        if fail_count >= 3:
                            logger.warning(f"[{self.name}] Tool call failed {fail_count} times: {tool_call_key}")
                            observation += f"\n\n⚠️ **系统提示**: 此工具调用已连续失败 {fail_count} 次。请：\n"
                            observation += "1. 尝试使用不同的参数（如指定较小的行范围）\n"
                            observation += "2. 使用 search_code 工具定位关键代码片段\n"
                            observation += "3. 跳过此发现的验证，继续验证其他发现\n"
                            observation += "4. 如果已有足够验证结果，直接输出 Final Answer"
                            
                            # 重置计数器
                            self._failed_tool_calls[tool_call_key] = 0
                    else:
                        # 成功调用，重置失败计数
                        if tool_call_key in self._failed_tool_calls:
                            del self._failed_tool_calls[tool_call_key]

                    # 🔥 工具执行后检查取消状态
                    if self.is_cancelled:
                        logger.info(f"[{self.name}] Cancelled after tool execution")
                        break

                    step.observation = observation
                    
                    # 🔥 发射 LLM 观察事件
                    await self.emit_llm_observation(observation)
                    
                    # 添加观察结果到历史
                    self._conversation_history.append({
                        "role": "user",
                        "content": f"Observation:\n{observation}",
                    })
                else:
                    # LLM 没有选择工具，提示它继续
                    await self.emit_llm_decision("继续验证", "LLM 需要更多验证")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "请继续验证。你输出了 Thought 但没有输出 Action。请**立即**选择一个工具执行，或者如果验证完成，输出 Final Answer 汇总所有验证结果。",
                    })
            
            # 处理结果
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 🔥 如果被取消，返回取消结果
            if self.is_cancelled:
                await self.emit_event(
                    "info",
                    f"🛑 Verification Agent 已取消: {self._iteration} 轮迭代"
                )
                return AgentResult(
                    success=False,
                    error="任务已取消",
                    data={"findings": findings_to_verify},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 处理最终结果
            verified_findings = []

            # 🔥 Robustness: If LLM returns empty findings but we had input, fallback to original
            llm_findings = []
            if final_result and "findings" in final_result:
                llm_findings = final_result["findings"]

            if not llm_findings and findings_to_verify:
                logger.warning(f"[{self.name}] LLM returned empty findings despite {len(findings_to_verify)} inputs. Falling back to originals.")
                # Fallback to logic below (else branch)
                final_result = None

            if final_result and "findings" in final_result:
                # 🔥 DEBUG: Log what LLM returned for verdict diagnosis
                verdicts_debug = [(f.get("file_path", "?"), f.get("verdict"), f.get("confidence")) for f in final_result["findings"]]
                logger.info(f"[{self.name}] LLM returned verdicts: {verdicts_debug}")

                for f in final_result["findings"]:
                    # 🔥 FIX: Normalize verdict - handle missing/empty verdict
                    verdict = f.get("verdict")
                    if not verdict or verdict not in ["confirmed", "likely", "uncertain", "false_positive"]:
                        # Try to infer verdict from other fields
                        if f.get("is_verified") is True:
                            verdict = "confirmed"
                        elif f.get("confidence", 0) >= 0.8:
                            verdict = "likely"
                        elif f.get("confidence", 0) <= 0.3:
                            verdict = "false_positive"
                        else:
                            verdict = "uncertain"
                        logger.warning(f"[{self.name}] Missing/invalid verdict for {f.get('file_path', '?')}, inferred as: {verdict}")

                    verified = {
                        **f,
                        "verdict": verdict,  # 🔥 Ensure verdict is set
                        "is_verified": verdict == "confirmed" or (
                            verdict == "likely" and f.get("confidence", 0) >= 0.8
                        ),
                        "verified_at": datetime.now(timezone.utc).isoformat() if verdict in ["confirmed", "likely"] else None,
                    }

                    # 添加修复建议
                    if not verified.get("recommendation"):
                        verified["recommendation"] = self._get_recommendation(f.get("vulnerability_type", ""))

                    verified_findings.append(verified)
            else:
                # 如果没有最终结果，使用原始发现
                for f in findings_to_verify:
                    verified_findings.append({
                        **f,
                        "verdict": "uncertain",
                        "confidence": 0.5,
                        "is_verified": False,
                    })
            
            # 统计
            confirmed_count = len([f for f in verified_findings if f.get("verdict") == "confirmed"])
            likely_count = len([f for f in verified_findings if f.get("verdict") == "likely"])
            false_positive_count = len([f for f in verified_findings if f.get("verdict") == "false_positive"])

            await self.emit_event(
                "info",
                f"Verification Agent 完成: {confirmed_count} 确认, {likely_count} 可能, {false_positive_count} 误报"
            )

            # 🔥 CRITICAL: Log final findings count before returning
            logger.info(f"[{self.name}] Returning {len(verified_findings)} verified findings")

            # 🔥 创建 TaskHandoff - 记录验证结果，供 Orchestrator 汇总
            handoff = self._create_verification_handoff(
                verified_findings, confirmed_count, likely_count, false_positive_count
            )

            return AgentResult(
                success=True,
                data={
                    "findings": verified_findings,
                    "verified_count": confirmed_count,
                    "likely_count": likely_count,
                    "false_positive_count": false_positive_count,
                },
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,  # 🔥 添加 handoff
            )
            
        except Exception as e:
            logger.error(f"Verification Agent failed: {e}", exc_info=True)
            return AgentResult(success=False, error=str(e))
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            "sql_injection": "使用参数化查询或 ORM，避免字符串拼接构造 SQL",
            "xss": "对用户输入进行 HTML 转义，使用 CSP，避免 innerHTML",
            "command_injection": "避免使用 shell=True，使用参数列表传递命令",
            "path_traversal": "验证和规范化路径，使用白名单，避免直接使用用户输入",
            "ssrf": "验证和限制目标 URL，使用白名单，禁止内网访问",
            "deserialization": "避免反序列化不可信数据，使用 JSON 替代 pickle/yaml",
            "hardcoded_secret": "使用环境变量或密钥管理服务存储敏感信息",
            "weak_crypto": "使用强加密算法（AES-256, SHA-256+），避免 MD5/SHA1",
        }
        return recommendations.get(vuln_type, "请根据具体情况修复此安全问题")
    
    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        
        for f in findings:
            path_nodes = f.get("source_to_sink_path")
            node_file = ""
            node_line = 0
            if isinstance(path_nodes, list):
                for n in path_nodes:
                    if isinstance(n, dict):
                        node_file = str(n.get("file_path") or n.get("File") or "").strip()
                        node_line = n.get("start_line") or n.get("StartLine") or n.get("line") or 0
                        if node_file or node_line:
                            break
            key = (
                f.get("file_path", "") or node_file,
                f.get("line_start", 0) or node_line,
                f.get("vulnerability_type", ""),
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        return unique
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史"""
        return self._conversation_history

    def get_steps(self) -> List[VerificationStep]:
        """获取执行步骤"""
        return self._steps

    def _create_verification_handoff(
        self,
        verified_findings: List[Dict[str, Any]],
        confirmed_count: int,
        likely_count: int,
        false_positive_count: int,
    ) -> TaskHandoff:
        """
        创建 Verification Agent 的任务交接信息

        Args:
            verified_findings: 验证后的发现列表
            confirmed_count: 确认的漏洞数量
            likely_count: 可能的漏洞数量
            false_positive_count: 误报数量

        Returns:
            TaskHandoff 对象，供 Orchestrator 汇总
        """
        # 按验证结果分类
        confirmed = [f for f in verified_findings if f.get("verdict") == "confirmed"]
        likely = [f for f in verified_findings if f.get("verdict") == "likely"]
        false_positives = [f for f in verified_findings if f.get("verdict") == "false_positive"]

        # 提取关键发现（已确认的高危漏洞）
        key_findings = []
        for f in confirmed:
            if f.get("severity") in ["critical", "high"]:
                key_findings.append(f)
        # 如果高危不够，添加其他确认的漏洞
        if len(key_findings) < 10:
            for f in confirmed:
                if f not in key_findings:
                    key_findings.append(f)
                    if len(key_findings) >= 10:
                        break

        # 构建建议行动 - 修复建议
        suggested_actions = []
        for f in confirmed[:10]:
            suggestion = f.get("suggestion", "") or f.get("recommendation", "")
            suggested_actions.append({
                "action": "fix_vulnerability",
                "target": f.get("file_path", ""),
                "line": f.get("line_start", 0),
                "vulnerability_type": f.get("vulnerability_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "recommendation": suggestion[:200] if suggestion else "请根据漏洞类型进行修复"
            })

        # 构建洞察
        insights = [
            f"验证完成: {confirmed_count}个确认, {likely_count}个可能, {false_positive_count}个误报",
            f"验证准确率: {(confirmed_count + likely_count) / len(verified_findings) * 100:.1f}%" if verified_findings else "无数据",
        ]

        # 统计各类型漏洞
        type_counts = {}
        for f in confirmed + likely:
            vtype = f.get("vulnerability_type", "unknown")
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            insights.append(f"主要漏洞类型: {', '.join([f'{t}({c})' for t, c in top_types])}")

        # 需要关注的文件（有确认漏洞的文件）
        attention_points = []
        files_with_confirmed = {}
        for f in confirmed:
            fp = f.get("file_path", "")
            if fp:
                files_with_confirmed[fp] = files_with_confirmed.get(fp, 0) + 1
        for fp, count in sorted(files_with_confirmed.items(), key=lambda x: x[1], reverse=True)[:10]:
            attention_points.append(f"{fp} ({count}个确认漏洞)")

        # 优先修复的区域
        priority_areas = []
        for f in confirmed:
            if f.get("severity") in ["critical", "high"]:
                fp = f.get("file_path", "")
                if fp and fp not in priority_areas:
                    priority_areas.append(fp)

        # 上下文数据
        context_data = {
            "confirmed_count": confirmed_count,
            "likely_count": likely_count,
            "false_positive_count": false_positive_count,
            "vulnerability_types": type_counts,
            "files_with_confirmed": files_with_confirmed,
            "poc_generated": len([f for f in verified_findings if f.get("poc_code")]),
        }

        # 构建摘要
        summary = f"验证完成: {confirmed_count}个确认漏洞, {likely_count}个可能漏洞"
        if confirmed_count > 0:
            high_count = len([f for f in confirmed if f.get("severity") in ["critical", "high"]])
            if high_count > 0:
                summary += f", 其中{high_count}个高危"

        return self.create_handoff(
            to_agent="orchestrator",
            summary=summary,
            key_findings=key_findings,
            suggested_actions=suggested_actions,
            attention_points=attention_points,
            priority_areas=priority_areas,
            context_data=context_data,
        )
