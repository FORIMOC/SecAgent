"""
代码分析工具
使用 LLM 深度分析代码安全问题
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


class CodeAnalysisInput(BaseModel):
    """代码分析输入"""
    code: Optional[str] = Field(
        default=None,
        description="要分析的代码内容（可选；与 file_path 二选一）"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="文件路径（可选；与 code 二选一）"
    )
    start_line: Optional[int] = Field(default=None, description="可选，起始行号（与 file_path 配合）")
    end_line: Optional[int] = Field(default=None, description="可选，结束行号（与 file_path 配合）")
    language: str = Field(default="python", description="编程语言")
    focus: Optional[str] = Field(
        default=None,
        description="重点关注的漏洞类型，如 sql_injection, xss, command_injection"
    )
    context: Optional[str] = Field(
        default=None,
        description="额外的上下文信息，如相关的其他代码片段"
    )


class CodeAnalysisTool(AgentTool):
    """
    代码分析工具
    使用 LLM 对代码进行深度安全分析
    """
    
    def __init__(self, llm_service, project_root: Optional[str] = None):
        """
        初始化代码分析工具
        
        Args:
            llm_service: LLM 服务实例
            project_root: 项目根目录（用于仅传 file_path 时自动读取代码）
        """
        super().__init__()
        self.llm_service = llm_service
        self.project_root = project_root
    
    @property
    def name(self) -> str:
        return "code_analysis"
    
    @property
    def description(self) -> str:
        return """深度分析代码安全问题。
使用 LLM 对代码进行全面的安全审计，识别潜在漏洞。

使用场景:
- 对疑似有问题的代码进行深入分析
- 分析复杂的业务逻辑漏洞
- 追踪数据流和污点传播
- 生成详细的漏洞报告和修复建议

输入:
- code: 要分析的代码（可选；与 file_path 二选一）
- file_path: 文件路径（可选；与 code 二选一）
- start_line/end_line: 可选行范围（与 file_path 配合）
- language: 编程语言
- focus: 可选，重点关注的漏洞类型
- context: 可选，额外的上下文代码

这个工具会消耗较多的 Token，建议在确认有疑似问题后使用。"""
    
    @property
    def args_schema(self):
        return CodeAnalysisInput
    
    async def _execute(
        self,
        code: Optional[str] = None,
        file_path: Optional[str] = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        language: str = "python",
        focus: Optional[str] = None,
        context: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """执行代码分析"""
        import asyncio
        
        try:
            file_path_str = str(file_path or "").strip()
            code_text = str(code or "").strip()
            if not code_text:
                if not file_path_str:
                    return ToolResult(
                        success=False,
                        error="缺少参数：请提供 code，或提供 file_path（可选 start_line/end_line）。",
                    )
                loaded_code, load_err = self._load_code_from_file(
                    file_path=file_path_str,
                    start_line=start_line,
                    end_line=end_line,
                )
                if load_err:
                    return ToolResult(success=False, error=load_err)
                code_text = loaded_code
                if language == "python":
                    inferred = self._infer_language_from_path(file_path_str)
                    if inferred:
                        language = inferred

            # 限制代码长度，避免超时
            max_code_length = 50000  # 约 50KB
            if len(code_text) > max_code_length:
                code_text = code_text[:max_code_length] + "\n\n... (代码已截断，仅分析前 50000 字符)"
            
            # 添加超时保护（5分钟）
            try:
                analysis = await asyncio.wait_for(
                    self.llm_service.analyze_code(code_text, language),
                    timeout=300.0  # 5分钟超时
                )
            except asyncio.TimeoutError:
                return ToolResult(
                    success=False,
                    error="代码分析超时（超过5分钟）。代码可能过长或过于复杂，请尝试分析较小的代码片段。",
                )
            
            issues = analysis.get("issues", [])
            display_file_path = file_path_str or "unknown"
            
            if not issues:
                return ToolResult(
                    success=True,
                    data="代码分析完成，未发现明显的安全问题。\n\n"
                         f"质量评分: {analysis.get('quality_score', 'N/A')}\n"
                         f"文件: {display_file_path}",
                    metadata={
                        "file_path": display_file_path,
                        "issues_count": 0,
                        "quality_score": analysis.get("quality_score"),
                    }
                )
            
            # 格式化输出
            output_parts = [f"🔍 代码分析结果 - {display_file_path}\n"]
            output_parts.append(f"发现 {len(issues)} 个问题:\n")
            
            for i, issue in enumerate(issues):
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠", 
                    "medium": "🟡",
                    "low": "🟢"
                }.get(issue.get("severity", ""), "⚪")
                
                output_parts.append(f"\n{severity_icon} 问题 {i+1}: {issue.get('title', 'Unknown')}")
                output_parts.append(f"   类型: {issue.get('type', 'unknown')}")
                output_parts.append(f"   严重程度: {issue.get('severity', 'unknown')}")
                output_parts.append(f"   行号: {issue.get('line', 'N/A')}")
                output_parts.append(f"   描述: {issue.get('description', '')}")
                
                if issue.get("code_snippet"):
                    output_parts.append(f"   代码片段:\n   ```\n   {issue.get('code_snippet')}\n   ```")
                
                if issue.get("suggestion"):
                    output_parts.append(f"   修复建议: {issue.get('suggestion')}")
                
                if issue.get("ai_explanation"):
                    output_parts.append(f"   AI解释: {issue.get('ai_explanation')}")
            
            output_parts.append(f"\n质量评分: {analysis.get('quality_score', 'N/A')}/100")
            
            return ToolResult(
                success=True,
                data="\n".join(output_parts),
                metadata={
                    "file_path": display_file_path,
                    "issues_count": len(issues),
                    "quality_score": analysis.get("quality_score"),
                    "issues": issues,
                }
            )
            
        except Exception as e:
            import traceback
            logger.error(f"代码分析失败: {e}")
            logger.error(f"LLM Provider: {self.llm_service.config.provider.value if self.llm_service.config else 'N/A'}")
            logger.error(f"LLM Model: {self.llm_service.config.model if self.llm_service.config else 'N/A'}")
            logger.error(f"API Key 前缀: {self.llm_service.config.api_key[:10] + '...' if self.llm_service.config and self.llm_service.config.api_key else 'N/A'}")
            logger.error(traceback.format_exc())
            return ToolResult(
                success=False,
                error=f"代码分析失败: {str(e)}",
            )

    def _load_code_from_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> tuple[str, Optional[str]]:
        """当只提供 file_path 时，自动读取代码内容。"""
        if not self.project_root:
            return "", "code_analysis 未配置 project_root，无法仅凭 file_path 读取代码。"

        if not file_path:
            return "", "file_path 不能为空。"

        root = os.path.realpath(self.project_root)
        full_path = os.path.realpath(os.path.join(root, file_path))
        if not full_path.startswith(root):
            return "", "安全错误：不允许读取项目目录外的文件。"
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            return "", f"文件不存在: {file_path}"

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as exc:
            return "", f"读取文件失败: {exc}"

        total = len(lines)
        s = 1 if start_line is None else max(1, int(start_line))
        e = total if end_line is None else min(total, int(end_line))
        if e < s:
            return "", f"无效行范围: start_line={s}, end_line={e}"

        snippet = "".join(lines[s - 1:e]).strip()
        if not snippet:
            return "", f"读取到空代码片段: {file_path}:{s}-{e}"
        return snippet, None

    @staticmethod
    def _infer_language_from_path(file_path: str) -> Optional[str]:
        ext = os.path.splitext(file_path.lower())[1]
        mapping = {
            ".php": "php",
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".sh": "bash",
        }
        return mapping.get(ext)


class DataFlowAnalysisInput(BaseModel):
    """数据流分析输入"""
    source_code: str = Field(description="包含数据源的代码")
    sink_code: Optional[str] = Field(default=None, description="包含数据汇的代码（如危险函数）")
    variable_name: str = Field(description="要追踪的变量名")
    file_path: str = Field(default="unknown", description="文件路径")


class DataFlowAnalysisTool(AgentTool):
    """
    数据流分析工具
    追踪变量从源到汇的数据流
    """
    
    def __init__(self, llm_service):
        super().__init__()
        self.llm_service = llm_service
    
    @property
    def name(self) -> str:
        return "dataflow_analysis"
    
    @property
    def description(self) -> str:
        return """分析代码中的数据流，追踪变量从源（如用户输入）到汇（如危险函数）的路径。

使用场景:
- 追踪用户输入如何流向危险函数
- 分析变量是否经过净化处理
- 识别污点传播路径

输入:
- source_code: 包含数据源的代码
- sink_code: 包含数据汇的代码（可选）
- variable_name: 要追踪的变量名
- file_path: 文件路径"""
    
    @property
    def args_schema(self):
        return DataFlowAnalysisInput
    
    async def _execute(
        self,
        source_code: str,
        variable_name: str,
        sink_code: Optional[str] = None,
        file_path: str = "unknown",
        **kwargs
    ) -> ToolResult:
        """执行数据流分析 - 增强版，带超时保护和回退逻辑"""
        import asyncio
        import re
        
        # 🔥 首先尝试基于规则的快速分析（不依赖 LLM）
        quick_analysis = self._quick_pattern_analysis(source_code, variable_name, sink_code)
        
        try:
            # 构建分析 prompt
            analysis_prompt = f"""分析以下代码中变量 '{variable_name}' 的数据流。

源代码:
```
{source_code}
```
"""
            if sink_code:
                analysis_prompt += f"""
汇代码（可能的危险函数）:
```
{sink_code}
```
"""

            analysis_prompt += f"""
请分析:
1. 变量 '{variable_name}' 的来源是什么？（用户输入、配置、数据库等）
2. 变量在传递过程中是否经过了净化/验证？
3. 变量最终流向了哪些危险函数？
4. 是否存在安全风险？

请返回 JSON 格式的分析结果，包含:
- source_type: 数据源类型
- sanitized: 是否经过净化
- sanitization_methods: 使用的净化方法
- dangerous_sinks: 流向的危险函数列表
- risk_level: 风险等级 (high/medium/low/none)
- explanation: 详细解释
- recommendation: 建议
"""
            
            # 🔥 添加超时保护（2分钟）
            try:
                result = await asyncio.wait_for(
                    self.llm_service.analyze_code_with_custom_prompt(
                        code=source_code,
                        language="text",
                        custom_prompt=analysis_prompt,
                    ),
                    timeout=120.0  # 2分钟超时
                )
            except asyncio.TimeoutError:
                logger.warning(f"数据流分析 LLM 调用超时，使用快速分析结果")
                return self._format_quick_analysis_result(quick_analysis, variable_name, file_path, "LLM调用超时，使用规则分析")
            
            # 🔥 检查结果是否有效
            if not result or (isinstance(result, dict) and not result.get("source_type") and not result.get("risk_level")):
                logger.warning(f"数据流分析 LLM 返回无效结果，使用快速分析结果")
                return self._format_quick_analysis_result(quick_analysis, variable_name, file_path, "LLM返回无效，使用规则分析")
            
            # 格式化输出
            output_parts = [f"📊 数据流分析结果 - 变量: {variable_name}\n"]
            
            if isinstance(result, dict):
                if result.get("source_type"):
                    output_parts.append(f"数据源: {result.get('source_type')}")
                if result.get("sanitized") is not None:
                    sanitized = "✅ 是" if result.get("sanitized") else "❌ 否"
                    output_parts.append(f"是否净化: {sanitized}")
                if result.get("sanitization_methods"):
                    methods = result.get('sanitization_methods', [])
                    if isinstance(methods, list):
                        output_parts.append(f"净化方法: {', '.join(methods)}")
                    else:
                        output_parts.append(f"净化方法: {methods}")
                if result.get("dangerous_sinks"):
                    sinks = result.get('dangerous_sinks', [])
                    if isinstance(sinks, list):
                        output_parts.append(f"危险函数: {', '.join(sinks)}")
                    else:
                        output_parts.append(f"危险函数: {sinks}")
                if result.get("risk_level"):
                    risk_icons = {"high": "🔴", "medium": "🟠", "low": "🟡", "none": "🟢"}
                    icon = risk_icons.get(result.get("risk_level", ""), "⚪")
                    output_parts.append(f"风险等级: {icon} {result.get('risk_level', '').upper()}")
                if result.get("explanation"):
                    output_parts.append(f"\n分析: {result.get('explanation')}")
                if result.get("recommendation"):
                    output_parts.append(f"\n建议: {result.get('recommendation')}")
            else:
                output_parts.append(str(result))
            
            return ToolResult(
                success=True,
                data="\n".join(output_parts),
                metadata={
                    "variable": variable_name,
                    "file_path": file_path,
                    "analysis": result,
                }
            )
            
        except Exception as e:
            logger.error(f"数据流分析失败: {e}")
            # 🔥 回退到快速分析
            return self._format_quick_analysis_result(
                quick_analysis, 
                variable_name, 
                file_path, 
                f"LLM调用失败({str(e)[:50]}...)，使用规则分析"
            )
    
    def _quick_pattern_analysis(
        self, 
        source_code: str, 
        variable_name: str,
        sink_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """基于规则的快速数据流分析（不依赖 LLM）"""
        import re
        
        result = {
            "source_type": "unknown",
            "sanitized": False,
            "sanitization_methods": [],
            "dangerous_sinks": [],
            "risk_level": "low",
        }
        
        code_to_analyze = source_code + (sink_code or "")
        
        # 检测数据源类型
        source_patterns = {
            "user_input_get": r'\$_GET\[',
            "user_input_post": r'\$_POST\[',
            "user_input_request": r'\$_REQUEST\[',
            "user_input_cookie": r'\$_COOKIE\[',
            "request_param": r'request\.(GET|POST|args|form|data)',
            "input_func": r'\binput\s*\(',
        }
        
        for source_name, pattern in source_patterns.items():
            if re.search(pattern, source_code, re.IGNORECASE):
                result["source_type"] = source_name
                break
        
        # 检测净化方法
        sanitize_patterns = [
            (r'htmlspecialchars\s*\(', "htmlspecialchars"),
            (r'mysqli_real_escape_string\s*\(', "mysqli_escape"),
            (r'addslashes\s*\(', "addslashes"),
            (r'strip_tags\s*\(', "strip_tags"),
            (r'filter_var\s*\(', "filter_var"),
            (r'escape\s*\(', "escape"),
            (r'sanitize', "sanitize"),
            (r'validate', "validate"),
        ]
        
        for pattern, name in sanitize_patterns:
            if re.search(pattern, code_to_analyze, re.IGNORECASE):
                result["sanitized"] = True
                result["sanitization_methods"].append(name)
        
        # 检测危险 sink
        sink_patterns = [
            (r'mysql_query\s*\(', "mysql_query"),
            (r'mysqli_query\s*\(', "mysqli_query"),
            (r'execute\s*\(', "execute"),
            (r'shell_exec\s*\(', "shell_exec"),
            (r'system\s*\(', "system"),
            (r'exec\s*\(', "exec"),
            (r'eval\s*\(', "eval"),
            (r'include\s*\(', "include"),
            (r'require\s*\(', "require"),
            (r'file_get_contents\s*\(', "file_get_contents"),
            (r'echo\s+', "echo"),
            (r'print\s*\(', "print"),
        ]
        
        for pattern, name in sink_patterns:
            if re.search(pattern, code_to_analyze, re.IGNORECASE):
                result["dangerous_sinks"].append(name)
        
        # 计算风险等级
        if result["source_type"].startswith("user_input") and result["dangerous_sinks"]:
            if not result["sanitized"]:
                result["risk_level"] = "high"
            else:
                result["risk_level"] = "medium"
        elif result["dangerous_sinks"]:
            result["risk_level"] = "medium"
        
        return result
    
    def _format_quick_analysis_result(
        self, 
        analysis: Dict[str, Any], 
        variable_name: str,
        file_path: str,
        note: str
    ) -> ToolResult:
        """格式化快速分析结果"""
        output_parts = [f"📊 数据流分析结果 - 变量: {variable_name}"]
        output_parts.append(f"⚠️ 注意: {note}\n")
        
        output_parts.append(f"数据源: {analysis.get('source_type', 'unknown')}")
        output_parts.append(f"是否净化: {'✅ 是' if analysis.get('sanitized') else '❌ 否'}")
        
        if analysis.get("sanitization_methods"):
            output_parts.append(f"净化方法: {', '.join(analysis['sanitization_methods'])}")
        
        if analysis.get("dangerous_sinks"):
            output_parts.append(f"危险函数: {', '.join(analysis['dangerous_sinks'])}")
        
        risk_icons = {"high": "🔴", "medium": "🟠", "low": "🟡", "none": "🟢"}
        risk = analysis.get("risk_level", "low")
        output_parts.append(f"风险等级: {risk_icons.get(risk, '⚪')} {risk.upper()}")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "variable": variable_name,
                "file_path": file_path,
                "analysis": analysis,
                "fallback_used": True,
            }
        )


class VulnerabilityValidationInput(BaseModel):
    """漏洞验证输入"""
    code: str = Field(description="可能存在漏洞的代码")
    vulnerability_type: str = Field(description="漏洞类型")
    file_path: str = Field(default="unknown", description="文件路径")
    line_number: Optional[int] = Field(default=None, description="行号")
    context: Optional[str] = Field(default=None, description="额外上下文")


class VulnerabilityValidationTool(AgentTool):
    """
    漏洞验证工具
    验证疑似漏洞是否真实存在
    """
    
    def __init__(self, llm_service):
        super().__init__()
        self.llm_service = llm_service
    
    @property
    def name(self) -> str:
        return "vulnerability_validation"
    
    @property
    def description(self) -> str:
        return """验证疑似漏洞是否真实存在。
对发现的潜在漏洞进行深入分析，判断是否为真正的安全问题。

输入:
- code: 包含疑似漏洞的代码
- vulnerability_type: 漏洞类型（如 sql_injection, xss 等）
- file_path: 文件路径
- line_number: 可选，行号
- context: 可选，额外的上下文代码

输出:
- 验证结果（确认/可能/误报）
- 详细分析
- 利用条件
- PoC 思路（如果确认存在漏洞）"""
    
    @property
    def args_schema(self):
        return VulnerabilityValidationInput
    
    async def _execute(
        self,
        code: str,
        vulnerability_type: str,
        file_path: str = "unknown",
        line_number: Optional[int] = None,
        context: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """执行漏洞验证"""
        try:
            validation_prompt = f"""你是一个专业的安全研究员，请验证以下代码中是否真的存在 {vulnerability_type} 漏洞。

代码:
```
{code}
```

{f'额外上下文:' + chr(10) + '```' + chr(10) + context + chr(10) + '```' if context else ''}

请分析:
1. 这段代码是否真的存在 {vulnerability_type} 漏洞？
2. 漏洞的利用条件是什么？
3. 攻击者如何利用这个漏洞？
4. 这是否可能是误报？为什么？

请返回 JSON 格式:
{{
    "is_vulnerable": true/false/null (null表示无法确定),
    "confidence": 0.0-1.0,
    "verdict": "confirmed/likely/unlikely/false_positive",
    "exploitation_conditions": ["条件1", "条件2"],
    "attack_vector": "攻击向量描述",
    "poc_idea": "PoC思路（如果存在漏洞）",
    "false_positive_reason": "如果是误报，说明原因",
    "detailed_analysis": "详细分析"
}}
"""
            
            result = await self.llm_service.analyze_code_with_custom_prompt(
                code=code,
                language="text",
                custom_prompt=validation_prompt,
            )
            
            # 格式化输出
            output_parts = [f"🔎 漏洞验证结果 - {vulnerability_type}\n"]
            output_parts.append(f"文件: {file_path}")
            if line_number:
                output_parts.append(f"行号: {line_number}")
            output_parts.append("")
            
            if isinstance(result, dict):
                # 验证结果
                verdict_icons = {
                    "confirmed": "🔴 确认存在漏洞",
                    "likely": "🟠 可能存在漏洞",
                    "unlikely": "🟡 可能是误报",
                    "false_positive": "🟢 误报",
                }
                verdict = result.get("verdict", "unknown")
                output_parts.append(f"判定: {verdict_icons.get(verdict, verdict)}")
                
                if result.get("confidence"):
                    output_parts.append(f"置信度: {result.get('confidence') * 100:.0f}%")
                
                if result.get("exploitation_conditions"):
                    output_parts.append(f"\n利用条件:")
                    for cond in result.get("exploitation_conditions", []):
                        output_parts.append(f"  - {cond}")
                
                if result.get("attack_vector"):
                    output_parts.append(f"\n攻击向量: {result.get('attack_vector')}")
                
                if result.get("poc_idea") and verdict in ["confirmed", "likely"]:
                    output_parts.append(f"\nPoC思路: {result.get('poc_idea')}")
                
                if result.get("false_positive_reason") and verdict in ["unlikely", "false_positive"]:
                    output_parts.append(f"\n误报原因: {result.get('false_positive_reason')}")
                
                if result.get("detailed_analysis"):
                    output_parts.append(f"\n详细分析:\n{result.get('detailed_analysis')}")
            else:
                output_parts.append(str(result))
            
            return ToolResult(
                success=True,
                data="\n".join(output_parts),
                metadata={
                    "vulnerability_type": vulnerability_type,
                    "file_path": file_path,
                    "line_number": line_number,
                    "validation": result,
                }
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                error=f"漏洞验证失败: {str(e)}",
            )
