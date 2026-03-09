"""
Analysis Agent (漏洞分析层) - LLM 驱动版

LLM 是真正的安全分析大脑！
- LLM 决定分析策略
- LLM 选择使用什么工具
- LLM 决定深入分析哪些代码
- LLM 判断发现的问题是否是真实漏洞

类型: ReAct (真正的!)
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

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

    # 1) exact substring
    idx = text.find(code)
    if idx >= 0:
        start = text[:idx].count("\n") + 1
        end = start + code.count("\n")
        return start, end

    # 2) whitespace-insensitive regex
    tokens = re.findall(r"\S+", code)
    if tokens:
        pattern = r"\s*".join(re.escape(t) for t in tokens)
        m = re.search(pattern, text, re.DOTALL)
        if m:
            start = text[: m.start()].count("\n") + 1
            segment = text[m.start() : m.end()]
            end = start + segment.count("\n")
            return start, end

    # 3) single-line fallback by normalized containment
    target = _normalize_code(code)
    if target:
        for i, line in enumerate(text.splitlines(), start=1):
            nline = _normalize_code(line)
            if target in nline or nline in target:
                return i, i
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


ANALYSIS_SYSTEM_PROMPT = """你是 DeepAudit 的漏洞分析 Agent，一个自主安全专家。

## 当前运行约束
本次运行不接入外部 SAST 工具。只能使用当前可用工具：
- list_files
- read_file
- search_code
- pattern_match
- code_analysis
- dataflow_analysis
- vulnerability_validation
- smart_scan
- quick_audit
- extract_function
- run_code / sandbox_exec / sandbox_http / verify_vulnerability / php_test / test_command_injection（若可用）

## 核心目标
基于 CVE 上下文（含 patch diff 线索、focus variables、advisory 摘要）定位最可能的漏洞触发链路，输出高质量 findings。

## 分析策略
1. 先聚焦 CVE 指向文件与变量（project_info/config 中提供）
2. 用 search_code + read_file 建立上下文
3. 用 dataflow_analysis 追踪 Source -> Propagation -> Sink
4. 用 vulnerability_validation 进行语义复核
5. 必要时用 smart_scan/quick_audit 补充覆盖

## 关键约束
1. 禁止臆测：所有结论必须可追溯到实际读取的文件与行
2. 先工具后结论：必须先有工具调用，再输出 Final Answer
3. 至少调用两个工具，且必须包含 read_file；并至少再调用一个确认类工具（search_code / dataflow_analysis / vulnerability_validation / pattern_match）
4. 优先输出可行动结果：`source_to_sink_path` 节点尽量完整（建议包含更多 propagation 节点）
5. 如果输出数据流路径，必须在 `source_to_sink_path` 中按 **Source -> Propagation -> Sink** 顺序排列，禁止在提交阶段打乱顺序
6. Sink 判定必须严格：只有“危险数据被真正执行/解释/发送到危险 API”的位置才是 Sink；中间构造、拼接、赋值都属于 Propagation
7. Final Answer 前必须逐节点自检：对每个节点执行 `read_file(File, StartLine, EndLine)`，确认返回内容包含该节点 code；不满足则先修正行号或 code 再提交

## Sink 判定补充（非常重要）
- SQL 场景中，`$sql .= ...`、`sql = "..." + user_input` 这类语句是危险传播（Propagation），不是 Sink
- SQL 真正 Sink 是执行语句，如 `db.query(sql)`、`cursor.execute(sql)`、`mysqli_query(conn, sql)`、`PDO->query(sql)`、`prepare/execute` 中实际带入危险数据的执行点
- 命令注入同理：字符串拼接命令是 Propagation，`system/exec/popen/shell_exec/subprocess(..., shell=True)` 的执行点才是 Sink
- 反序列化同理：数据准备是 Propagation，`unserialize/pickle.load/ObjectInputStream.readObject` 调用点才是 Sink

## 输出格式
Thought: [你的思考]
Action: [工具名称]
Action Input: {JSON参数}

## Final Answer 一次性 JSON 硬约束
1. 当你决定结束时，必须只输出一个完整结果：`Final Answer: { ... }`
2. `Final Answer:` 后面必须是可被 `json.loads` 直接解析的单个 JSON 对象
3. 禁止输出 Markdown 代码块（```json）、注释、`...`、尾随解释文本
4. 不要分多次补充字段；缺失字段也要给空值（`[]`、`""`、`null`）

完成后：
Final Answer: {
  "findings": [
    {
      "vulnerability_type": "...",
      "severity": "high|medium|low",
      "title": "...",
      "description": "...",
      "source_to_sink_path": [
        {"Type": "Source|Propagation|Sink", "File": "...", "StartLine": 0, "EndLine": 0, "Desc": "...", "code": "..."},
        {"Type": "Source|Propagation|Sink", "File": "...", "StartLine": 0, "EndLine": 0, "Desc": "...", "code": "..."}
      ],
      "suggestion": "...",
      "confidence": 0.0,
      "needs_verification": true
    }
  ],
  "summary": "..."
}
"""


@dataclass
class AnalysisStep:
    """分析步骤"""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict] = None


class AnalysisAgent(BaseAgent):
    """
    漏洞分析 Agent - LLM 驱动版
    
    LLM 全程参与，自主决定：
    1. 分析什么
    2. 使用什么工具
    3. 深入哪些代码
    4. 报告什么发现
    """
    
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        # 组合增强的系统提示词，注入核心安全原则和漏洞优先级
        full_system_prompt = f"{ANALYSIS_SYSTEM_PROMPT}\n\n{CORE_SECURITY_PRINCIPLES}\n\n{VULNERABILITY_PRIORITIES}"
        
        config = AgentConfig(
            name="Analysis",
            agent_type=AgentType.ANALYSIS,
            pattern=AgentPattern.REACT,
            max_iterations=30,
            system_prompt=full_system_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[AnalysisStep] = []
        self._code_mismatch_retries: int = 0
        self._tool_call_stats: Dict[str, int] = {}
    

    
    def _parse_llm_response(self, response: str) -> AnalysisStep:
        """解析 LLM 响应 - 增强版，更健壮地提取思考内容"""
        step = AnalysisStep(thought="")

        # 🔥 v2.1: 预处理 - 移除 Markdown 格式标记（LLM 有时会输出 **Action:** 而非 Action:）
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned_response)

        # 🔥 首先尝试提取明确的 Thought 标记
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|Final Answer:|$)', cleaned_response, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # 🔥 检查是否是最终答案
        final_match = re.search(r'Final Answer:\s*(.*?)$', cleaned_response, re.DOTALL)
        if final_match:
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
        action_match = re.search(r'Action:\s*(\w+)', cleaned_response)
        if action_match:
            step.action = action_match.group(1).strip()

            # 🔥 如果没有提取到 thought，提取 Action 之前的内容作为思考
            if not step.thought:
                action_pos = cleaned_response.find('Action:')
                if action_pos > 0:
                    before_action = cleaned_response[:action_pos].strip()
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # 🔥 提取 Action Input
        input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|$)', cleaned_response, re.DOTALL)
        if input_match:
            input_text = input_match.group(1).strip()
            input_text = re.sub(r'```json\s*', '', input_text)
            input_text = re.sub(r'```\s*', '', input_text)
            # 使用增强的 JSON 解析器
            step.action_input = AgentJsonParser.parse(
                input_text,
                default={"raw_input": input_text}
            )

        # 🔥 最后的 fallback：如果整个响应没有任何标记，整体作为思考
        if not step.thought and not step.action and not step.is_final:
            if response.strip():
                step.thought = response.strip()[:500]

        return step

    def _ready_to_finalize(self) -> tuple[bool, str]:
        total_actions = sum(int(v) for v in self._tool_call_stats.values())
        read_calls = int(self._tool_call_stats.get("read_file", 0))
        evidence_calls = sum(
            int(self._tool_call_stats.get(name, 0))
            for name in ("search_code", "dataflow_analysis", "vulnerability_validation", "pattern_match")
        )
        if total_actions < 2:
            return False, (
                "工具调用不足（至少需要2次）"
                f" [当前: total_actions={total_actions}, read_file={read_calls}, evidence={evidence_calls}]"
            )
        if read_calls < 1:
            return False, (
                "缺少 read_file 证据读取"
                f" [当前: total_actions={total_actions}, read_file={read_calls}, evidence={evidence_calls}]"
            )
        if evidence_calls < 1:
            return False, (
                "缺少确认类工具调用（search_code/dataflow_analysis/vulnerability_validation/pattern_match）"
                f" [当前: total_actions={total_actions}, read_file={read_calls}, evidence={evidence_calls}]"
            )
        return True, ""
    

    
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """
        执行漏洞分析 - LLM 全程参与！
        """
        import time
        start_time = time.time()
        
        project_info = input_data.get("project_info", {})
        project_root = input_data.get("project_root") or project_info.get("root", ".")
        config = input_data.get("config", {})
        plan = input_data.get("plan", {})
        previous_results = input_data.get("previous_results", {})
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        
        # 🔥 处理交接信息
        handoff = input_data.get("handoff")
        if handoff:
            from .base import TaskHandoff
            if isinstance(handoff, dict):
                handoff = TaskHandoff.from_dict(handoff)
            self.receive_handoff(handoff)
        
        # 从 Recon 结果获取上下文
        recon_data = previous_results.get("recon", {})
        if isinstance(recon_data, dict) and "data" in recon_data:
            recon_data = recon_data["data"]
        
        tech_stack = recon_data.get("tech_stack", {})
        entry_points = recon_data.get("entry_points", [])
        high_risk_areas = recon_data.get("high_risk_areas", plan.get("high_risk_areas", []))
        initial_findings = recon_data.get("initial_findings", [])
        
        # 🔥 构建包含交接上下文的初始消息
        handoff_context = self.get_handoff_context()
        
        # 🔥 获取目标文件列表
        target_files = config.get("target_files", [])
        cve_advisory_summary = str(config.get("cve_advisory_summary") or "").strip()
        
        initial_message = f"""请开始对项目进行安全漏洞分析。

## 项目信息
- 名称: {project_info.get('name', 'unknown')}
- 语言: {tech_stack.get('languages', [])}
- 框架: {tech_stack.get('frameworks', [])}

"""
        # 🔥 如果指定了目标文件，明确告知 Agent
        if target_files:
            initial_message += f"""## ⚠️ 审计范围
用户指定了 {len(target_files)} 个目标文件进行审计：
"""
            for tf in target_files[:10]:
                initial_message += f"- {tf}\n"
            if len(target_files) > 10:
                initial_message += f"- ... 还有 {len(target_files) - 10} 个文件\n"
            initial_message += """
请直接分析这些指定的文件，不要分析其他文件。

"""
        
        if cve_advisory_summary:
            initial_message += f"## CVE公告精炼信息\n{cve_advisory_summary[:1800]}\n\n"

        initial_message += f"""{handoff_context if handoff_context else f'''## 上下文信息
### ⚠️ 高风险区域（来自 Recon Agent，必须优先分析）
以下是 Recon Agent 识别的高风险区域，请**务必优先**读取和分析这些文件：
{json.dumps(high_risk_areas[:20], ensure_ascii=False)}

**重要**: 请使用 read_file 工具读取上述高风险文件，不要假设文件路径或使用其他路径。

### 入口点 (前10个)
{json.dumps(entry_points[:10], ensure_ascii=False, indent=2)}

### 初步发现 (如果有)
{json.dumps(initial_findings[:5], ensure_ascii=False, indent=2) if initial_findings else "无"}'''}

## 任务
{task_context or task or '进行全面的安全漏洞分析，发现代码中的安全问题。'}

## ⚠️ 分析策略要求
1. **首先**：使用 read_file 读取上面列出的高风险文件
2. **然后**：分析这些文件中的安全问题
3. **最后**：如果需要，使用 smart_scan 或其他工具扩展分析

**禁止**：不要跳过高风险区域直接做全局扫描

## 目标漏洞类型
{config.get('target_vulnerabilities', ['all'])}

## 可用工具
{self.get_tools_description()}

请开始你的安全分析。首先读取高风险区域的文件，然后**立即**分析其中的安全问题（输出 Action）。"""
        
        # 🔥 记录工作开始
        self.record_work("开始安全漏洞分析")

        # 初始化对话历史
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]
        
        self._steps = []
        self._tool_call_stats = {}
        all_findings = []
        error_message = None  # 🔥 跟踪错误信息
        
        await self.emit_thinking("🔬 Analysis Agent 启动，LLM 开始自主安全分析...")
        
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
                # 🔥 使用用户配置的 temperature 和 max_tokens
                try:
                    llm_output, tokens_this_round = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                except asyncio.CancelledError:
                    logger.info(f"[{self.name}] LLM call cancelled")
                    break
                
                self._total_tokens += tokens_this_round

                # 🔥 Enhanced: Handle empty LLM response with better diagnostics
                if not llm_output or not llm_output.strip():
                    empty_retry_count = getattr(self, '_empty_retry_count', 0) + 1
                    self._empty_retry_count = empty_retry_count
                    
                    # 🔥 记录更详细的诊断信息
                    logger.warning(
                        f"[{self.name}] Empty LLM response in iteration {self._iteration} "
                        f"(retry {empty_retry_count}/3, tokens_this_round={tokens_this_round})"
                    )
                    
                    if empty_retry_count >= 3:
                        logger.error(f"[{self.name}] Too many empty responses, generating fallback result")
                        error_message = "连续收到空响应，使用回退结果"
                        await self.emit_event("warning", error_message)
                        # 🔥 不是直接 break，而是尝试生成一个回退结果
                        break
                    
                    # 🔥 更有针对性的重试提示
                    retry_prompt = f"""收到空响应。请根据以下格式输出你的思考和行动：

Thought: [你对当前安全分析情况的思考]
Action: [工具名称，如 read_file, search_code, pattern_match, dataflow_analysis]
Action Input: {{"参数名": "参数值"}}

可用工具: {', '.join(self.tools.keys())}

如果你已完成分析，请输出：
Thought: [总结所有发现]
Final Answer: {{"findings": [...], "summary": "..."}}"""
                    
                    self._conversation_history.append({
                        "role": "user",
                        "content": retry_prompt,
                    })
                    continue
                
                # 重置空响应计数器
                self._empty_retry_count = 0

                # 解析 LLM 响应
                step = self._parse_llm_response(llm_output)
                self._steps.append(step)
                
                # 🔥 发射 LLM 思考内容事件 - 展示安全分析的思考过程
                if step.thought:
                    await self.emit_llm_thought(step.thought, iteration + 1)
                
                # 添加 LLM 响应到历史
                self._conversation_history.append({
                    "role": "assistant",
                    "content": llm_output,
                })
                
                # 检查是否完成
                if step.is_final:
                    ready, reason = self._ready_to_finalize()
                    if not ready:
                        await self.emit_thinking(f"⚠️ 拒绝过早完成：{reason}")
                        self._conversation_history.append({
                            "role": "user",
                            "content": (
                                "⚠️ **系统拒绝**: 你的 Final Answer 提交过早。\n\n"
                                f"原因: {reason}\n\n"
                                "请继续执行工具分析后再提交，最少要求：\n"
                                "1) 至少一次 read_file\n"
                                "2) 至少一次 search_code/dataflow_analysis/vulnerability_validation/pattern_match\n"
                                "3) 累计至少两次工具调用\n\n"
                                "现在请输出 Thought 和 Action。"
                            ),
                        })
                        continue
                    if step.final_answer and "findings" in step.final_answer:
                        # 稳定性优化：发生多次 code/line 漂移后，先尝试自动定位并修正节点行号。
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
                            mismatch_invalids = [
                                x for x in invalids
                                if ("code not found in file range" in x or "code unrelated to file range" in x)
                            ]
                            if mismatch_invalids:
                                self._code_mismatch_retries += 1
                            else:
                                self._code_mismatch_retries = 0
                            # 稳定性兜底：连续多次仅因 code/line 不匹配失败时，直接按行号范围回填 code 再验证，避免长时间循环。
                            if self._code_mismatch_retries >= 6 and len(mismatch_invalids) == len(invalids):
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
                                        mismatch_invalids = [
                                            x for x in invalids
                                            if ("code not found in file range" in x or "code unrelated to file range" in x)
                                        ]
                            if not invalids:
                                self._code_mismatch_retries = 0
                                step.final_answer["findings"] = _overwrite_node_code_with_real_ranges(
                                    step.final_answer.get("findings", []),
                                    project_root,
                                )
                                await self.emit_llm_decision("完成安全分析", "LLM 结果经稳定性修复后通过校验")
                                logger.info(f"[{self.name}] Received Final Answer (stabilized): {step.final_answer}")
                                all_findings = step.final_answer.get("findings", [])
                                await self.emit_llm_complete(
                                    f"分析完成，发现 {len(all_findings)} 个潜在漏洞",
                                    self._total_tokens
                                )
                                break
                            await self.emit_thinking("⚠️ 拒收 Final Answer：source_to_sink_path 结构不满足要求，要求重提")
                            await self.emit_thinking("📌 拒收原因: " + "; ".join(invalids[:8]))
                            rejected_text = json.dumps(step.final_answer, ensure_ascii=False, indent=2)
                            if len(rejected_text) > 12000:
                                rejected_text = rejected_text[:12000] + "\n... (truncated)"
                            await self.emit_thinking(f"🧾 被拒收的 Final Answer:\n{rejected_text}")
                            mismatch_detail_text = ""
                            if self._code_mismatch_retries > 2 and mismatch_invalids:
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
                                    + "\n\n请重新输出 findings，要求：\n"
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
                    await self.emit_llm_decision("完成安全分析", "LLM 判断分析已充分")
                    logger.info(f"[{self.name}] Received Final Answer: {step.final_answer}")
                    if step.final_answer and "findings" in step.final_answer:
                        all_findings = step.final_answer["findings"]
                        logger.info(f"[{self.name}] Final Answer contains {len(all_findings)} findings")
                        # 🔥 发射每个发现的事件
                        for finding in all_findings[:5]:  # 限制数量
                            await self.emit_finding(
                                finding.get("title", "Unknown"),
                                finding.get("severity", "medium"),
                                finding.get("vulnerability_type", "other"),
                                finding.get("file_path", "")
                            )
                            # 🔥 记录洞察
                            self.add_insight(
                                f"发现 {finding.get('severity', 'medium')} 级别漏洞: {finding.get('title', 'Unknown')}"
                            )
                    else:
                        logger.warning(f"[{self.name}] Final Answer has no 'findings' key or is None: {step.final_answer}")
                    
                    # 🔥 记录工作完成
                    self.record_work(f"完成安全分析，发现 {len(all_findings)} 个潜在漏洞")
                    
                    await self.emit_llm_complete(
                        f"分析完成，发现 {len(all_findings)} 个潜在漏洞",
                        self._total_tokens
                    )
                    break
                
                # 执行工具
                if step.action:
                    # 🔥 发射 LLM 动作决策事件
                    await self.emit_llm_action(step.action, step.action_input or {})
                    
                    # 🔥 循环检测：追踪工具调用失败历史
                    tool_call_key = f"{step.action}:{json.dumps(step.action_input or {}, sort_keys=True)}"
                    if not hasattr(self, '_failed_tool_calls'):
                        self._failed_tool_calls = {}
                    
                    observation = await self.execute_tool(
                        step.action,
                        step.action_input or {}
                    )
                    self._tool_call_stats[step.action] = self._tool_call_stats.get(step.action, 0) + 1
                    
                    # 🔥 检测工具调用失败并追踪
                    is_tool_error = (
                        "失败" in observation or 
                        "错误" in observation or 
                        "不存在" in observation or
                        "文件过大" in observation or
                        "Error" in observation
                    )
                    
                    if is_tool_error:
                        self._failed_tool_calls[tool_call_key] = self._failed_tool_calls.get(tool_call_key, 0) + 1
                        fail_count = self._failed_tool_calls[tool_call_key]
                        
                        # 🔥 如果同一调用连续失败3次，添加强制跳过提示
                        if fail_count >= 3:
                            logger.warning(f"[{self.name}] Tool call failed {fail_count} times: {tool_call_key}")
                            observation += f"\n\n⚠️ **系统提示**: 此工具调用已连续失败 {fail_count} 次。请：\n"
                            observation += "1. 尝试使用不同的参数（如指定较小的行范围）\n"
                            observation += "2. 使用 search_code 工具定位关键代码片段\n"
                            observation += "3. 跳过此文件，继续分析其他文件\n"
                            observation += "4. 如果已有足够发现，直接输出 Final Answer"
                            
                            # 重置计数器但保留记录
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
                    await self.emit_llm_decision("继续分析", "LLM 需要更多分析")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "请继续分析。你输出了 Thought 但没有输出 Action。请**立即**选择一个工具执行，或者如果分析完成，输出 Final Answer 汇总所有发现。",
                    })
            
            # 🔥 如果循环结束但没有发现，强制 LLM 总结
            if not all_findings and not self.is_cancelled and not error_message:
                await self.emit_thinking("📝 分析阶段结束，正在生成漏洞总结...")
                
                # 添加强制总结的提示
                self._conversation_history.append({
                    "role": "user",
                    "content": """分析阶段已结束。请立即输出 Final Answer，总结你发现的所有安全问题。

即使没有发现严重漏洞，也请总结你的分析过程和观察到的潜在风险点。

请按以下 JSON 格式输出：
```json
{
    "findings": [
        {
            "vulnerability_type": "sql_injection|xss|command_injection|path_traversal|ssrf|hardcoded_secret|other",
            "severity": "critical|high|medium|low",
            "title": "漏洞标题",
            "description": "详细描述",
            "source_to_sink_path": [
                {
                    "Type": "Source|Propagation|Sink",
                    "File": "相对文件路径",
                    "StartLine": 1,
                    "EndLine": 1,
                    "Desc": "该节点的污点传递语义描述",
                    "code": "该行号范围内的代码原文"
                }
            ],
            "confidence": 0.0
        }
    ],
    "summary": "分析总结"
}
```

Final Answer:""",
                })
                
                try:
                    summary_output, _ = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                    
                    if summary_output and summary_output.strip():
                        # 解析总结输出
                        import re
                        summary_text = summary_output.strip()
                        summary_text = re.sub(r'```json\s*', '', summary_text)
                        summary_text = re.sub(r'```\s*', '', summary_text)
                        parsed_result = AgentJsonParser.parse(
                            summary_text,
                            default={"findings": [], "summary": ""}
                        )
                        if "findings" in parsed_result:
                            all_findings = parsed_result["findings"]
                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to generate summary: {e}")
            
            # 处理结果
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 🔥 如果被取消，返回取消结果
            if self.is_cancelled:
                await self.emit_event(
                    "info",
                    f"🛑 Analysis Agent 已取消: {len(all_findings)} 个发现, {self._iteration} 轮迭代"
                )
                return AgentResult(
                    success=False,
                    error="任务已取消",
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 🔥 如果有错误，返回失败结果
            if error_message:
                await self.emit_event(
                    "error",
                    f"❌ Analysis Agent 失败: {error_message}"
                )
                return AgentResult(
                    success=False,
                    error=error_message,
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 标准化发现
            logger.info(f"[{self.name}] Standardizing {len(all_findings)} findings")
            standardized_findings = []
            for finding in all_findings:
                # 确保 finding 是字典
                if not isinstance(finding, dict):
                    logger.warning(f"Skipping invalid finding (not a dict): {finding}")
                    continue
                path_nodes = finding.get("source_to_sink_path", [])
                fp = finding.get("file_path", "")
                if not fp and isinstance(path_nodes, list):
                    for n in path_nodes:
                        if isinstance(n, dict):
                            fp = n.get("file_path") or n.get("File") or fp
                            if fp:
                                break
                line_start = finding.get("line_start") or finding.get("line", 0)
                if not line_start and isinstance(path_nodes, list):
                    for n in path_nodes:
                        if not isinstance(n, dict):
                            continue
                        t = str(n.get("Type") or n.get("kind") or "").strip().lower()
                        if t == "source":
                            line_start = n.get("StartLine") or n.get("start_line") or n.get("line") or line_start
                            if line_start:
                                break
                    
                standardized = {
                    "vulnerability_type": finding.get("vulnerability_type", "other"),
                    "severity": finding.get("severity", "medium"),
                    "title": finding.get("title", "Unknown Finding"),
                    "description": finding.get("description", ""),
                    "file_path": fp or "",
                    "line_start": line_start,
                    "code_snippet": finding.get("code_snippet", ""),
                    "source": finding.get("source", ""),
                    "sink": finding.get("sink", ""),
                    "source_to_sink_path": path_nodes if isinstance(path_nodes, list) else [],
                    "suggestion": finding.get("suggestion", ""),
                    "confidence": finding.get("confidence", 0.7),
                    "needs_verification": finding.get("needs_verification", True),
                }
                standardized_findings.append(standardized)
            
            await self.emit_event(
                "info",
                f"Analysis Agent 完成: {len(standardized_findings)} 个发现, {self._iteration} 轮迭代, {self._tool_calls} 次工具调用"
            )

            # 🔥 CRITICAL: Log final findings count before returning
            logger.info(f"[{self.name}] Returning {len(standardized_findings)} standardized findings")

            # 🔥 创建 TaskHandoff - 传递给 Verification Agent
            handoff = self._create_analysis_handoff(standardized_findings)

            return AgentResult(
                success=True,
                data={
                    "findings": standardized_findings,
                    "steps": [
                        {
                            "thought": s.thought,
                            "action": s.action,
                            "action_input": s.action_input,
                            "observation": s.observation[:500] if s.observation else None,
                        }
                        for s in self._steps
                    ],
                },
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,  # 🔥 添加 handoff
            )
            
        except Exception as e:
            logger.error(f"Analysis Agent failed: {e}", exc_info=True)
            return AgentResult(success=False, error=str(e))
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史"""
        return self._conversation_history

    def get_steps(self) -> List[AnalysisStep]:
        """获取执行步骤"""
        return self._steps

    def _create_analysis_handoff(self, findings: List[Dict[str, Any]]) -> TaskHandoff:
        """
        创建 Analysis Agent 的任务交接信息

        Args:
            findings: 分析发现的漏洞列表

        Returns:
            TaskHandoff 对象，供 Verification Agent 使用
        """
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "low"), 3)
        )

        # 提取关键发现（优先高危漏洞）
        key_findings = sorted_findings[:15]

        # 构建建议行动 - 哪些漏洞需要优先验证
        suggested_actions = []
        for f in sorted_findings[:10]:
            suggested_actions.append({
                "action": "verify_vulnerability",
                "target": f.get("file_path", ""),
                "line": f.get("line_start", 0),
                "vulnerability_type": f.get("vulnerability_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "priority": "high" if f.get("severity") in ["critical", "high"] else "normal",
                "reason": f.get("title", "需要验证")
            })

        # 统计漏洞类型和严重程度
        severity_counts = {}
        type_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            vtype = f.get("vulnerability_type", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        # 构建洞察
        insights = [
            f"发现 {len(findings)} 个潜在漏洞需要验证",
            f"严重程度分布: Critical={severity_counts.get('critical', 0)}, "
            f"High={severity_counts.get('high', 0)}, "
            f"Medium={severity_counts.get('medium', 0)}, "
            f"Low={severity_counts.get('low', 0)}",
        ]

        # 最常见的漏洞类型
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            insights.append(f"主要漏洞类型: {', '.join([f'{t}({c})' for t, c in top_types])}")

        # 需要关注的文件
        attention_points = []
        files_with_findings = {}
        for f in findings:
            fp = f.get("file_path", "")
            if fp:
                files_with_findings[fp] = files_with_findings.get(fp, 0) + 1

        for fp, count in sorted(files_with_findings.items(), key=lambda x: x[1], reverse=True)[:10]:
            attention_points.append(f"{fp} ({count}个漏洞)")

        # 优先验证的区域 - 高危漏洞所在文件
        priority_areas = []
        for f in sorted_findings[:10]:
            if f.get("severity") in ["critical", "high"]:
                fp = f.get("file_path", "")
                if fp and fp not in priority_areas:
                    priority_areas.append(fp)

        # 上下文数据
        context_data = {
            "severity_distribution": severity_counts,
            "vulnerability_types": type_counts,
            "files_with_findings": files_with_findings,
        }

        # 构建摘要
        high_count = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        summary = f"完成代码分析: 发现{len(findings)}个漏洞, 其中{high_count}个高危"

        return self.create_handoff(
            to_agent="verification",
            summary=summary,
            key_findings=key_findings,
            suggested_actions=suggested_actions,
            attention_points=attention_points,
            priority_areas=priority_areas,
            context_data=context_data,
        )
