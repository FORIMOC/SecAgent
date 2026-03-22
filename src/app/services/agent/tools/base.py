"""
Agent 工具基类
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
from dataclasses import dataclass, field
from pydantic import BaseModel
import logging
import time

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }
    
    def to_string(self, max_length: int = 5000) -> str:
        """转换为字符串（用于 LLM 输出）"""
        if not self.success:
            return f"Error: {self.error}"
        
        if isinstance(self.data, str):
            result = self.data
        elif isinstance(self.data, (dict, list)):
            import json
            result = json.dumps(self.data, ensure_ascii=False, indent=2)
        else:
            result = str(self.data)
        
        if len(result) > max_length:
            result = result[:max_length] + f"\n... (truncated, total {len(result)} chars)"
        
        return result


class AgentTool(ABC):
    """
    Agent 工具基类
    所有工具需要继承此类并实现必要的方法
    """
    
    def __init__(self):
        self._call_count = 0
        self._total_duration_ms = 0
    
    @property
    @abstractmethod
    def name(self) -> str:
        """工具名称"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """工具描述（用于 Agent 理解工具功能）"""
        pass
    
    @property
    def args_schema(self) -> Optional[Type[BaseModel]]:
        """参数 Schema（Pydantic 模型）"""
        return None
    
    @abstractmethod
    async def _execute(self, **kwargs) -> ToolResult:
        """执行工具（子类实现）"""
        pass
    
    async def execute(self, **kwargs) -> ToolResult:
        """执行工具（带计时和日志）"""
        start_time = time.time()
        
        try:
            validated_kwargs = kwargs
            if self.args_schema:
                try:
                    schema_cls = self.args_schema
                    if hasattr(schema_cls, "model_validate"):  # Pydantic v2
                        parsed = schema_cls.model_validate(kwargs)
                        parsed_data = parsed.model_dump()
                    else:  # Pydantic v1
                        parsed = schema_cls.parse_obj(kwargs)
                        parsed_data = parsed.dict()

                    # 保留 schema 未定义的扩展参数，同时使用校验后的值覆盖同名字段
                    validated_kwargs = dict(kwargs)
                    validated_kwargs.update(parsed_data)
                except Exception as e:
                    required_fields = []
                    try:
                        if hasattr(schema_cls, "model_json_schema"):  # Pydantic v2
                            required_fields = schema_cls.model_json_schema().get("required", [])
                        else:  # Pydantic v1
                            required_fields = schema_cls.schema().get("required", [])
                    except Exception:
                        required_fields = []

                    required_hint = (
                        f"，必填参数: {', '.join(required_fields)}"
                        if required_fields
                        else ""
                    )
                    details = ""
                    if hasattr(e, "errors"):
                        try:
                            normalized_errors = []
                            for item in e.errors()[:3]:
                                loc = ".".join(str(x) for x in item.get("loc", [])) or "参数"
                                msg = item.get("msg", "格式错误")
                                normalized_errors.append(f"{loc}: {msg}")
                            details = "; ".join(normalized_errors)
                        except Exception:
                            details = ""
                    if not details:
                        details = str(e).splitlines()[0]

                    current_keys: list[str] = []
                    if isinstance(kwargs, dict):
                        current_keys = [str(k) for k in kwargs.keys()]
                    extra_hints: list[str] = []
                    if isinstance(kwargs, dict) and isinstance(kwargs.get("items"), list):
                        extra_hints.append("检测到 items 包装，请将 Action Input 改为单个 JSON 对象，不要使用 {'items': [...]}。")
                    if isinstance(kwargs, dict) and "raw_input" in kwargs:
                        extra_hints.append("检测到 raw_input，说明上游 Action Input JSON 解析失败，请输出严格 JSON。")
                    if required_fields:
                        extra_hints.append(f"建议至少包含必填字段: {', '.join(required_fields)}")
                    if current_keys:
                        extra_hints.append(f"当前顶层键: {', '.join(current_keys[:12])}")
                    hint_text = f" 纠错建议: {' | '.join(extra_hints)}" if extra_hints else ""

                    error_msg = f"参数校验失败{required_hint}。详细: {details}.{hint_text}"
                    logger.warning(f"Tool '{self.name}' {error_msg}")
                    return ToolResult(
                        success=False,
                        data=f"工具参数错误: {error_msg}",
                        error=error_msg,
                    )

            logger.debug(f"Tool '{self.name}' executing with args: {validated_kwargs}")
            result = await self._execute(**validated_kwargs)
            
        except Exception as e:
            logger.error(f"Tool '{self.name}' error: {e}", exc_info=True)
            error_msg = str(e)
            result = ToolResult(
                success=False,
                data=f"工具执行异常: {error_msg}",  # 🔥 修复：设置 data 字段避免 None
                error=error_msg,
            )
        
        duration_ms = int((time.time() - start_time) * 1000)
        result.duration_ms = duration_ms
        
        self._call_count += 1
        self._total_duration_ms += duration_ms
        
        logger.debug(f"Tool '{self.name}' completed in {duration_ms}ms, success={result.success}")
        
        return result
    
    def get_langchain_tool(self):
        """转换为 LangChain Tool"""
        from langchain.tools import Tool, StructuredTool
        import asyncio
        
        def sync_wrapper(**kwargs):
            """同步包装器"""
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.execute(**kwargs))
                    result = future.result()
            else:
                result = asyncio.run(self.execute(**kwargs))
            return result.to_string()
        
        async def async_wrapper(**kwargs):
            """异步包装器"""
            result = await self.execute(**kwargs)
            return result.to_string()
        
        if self.args_schema:
            return StructuredTool(
                name=self.name,
                description=self.description,
                func=sync_wrapper,
                coroutine=async_wrapper,
                args_schema=self.args_schema,
            )
        else:
            return Tool(
                name=self.name,
                description=self.description,
                func=lambda x: sync_wrapper(query=x),
                coroutine=lambda x: async_wrapper(query=x),
            )
    
    @property
    def stats(self) -> Dict[str, Any]:
        """工具使用统计"""
        return {
            "name": self.name,
            "call_count": self._call_count,
            "total_duration_ms": self._total_duration_ms,
            "avg_duration_ms": self._total_duration_ms // max(1, self._call_count),
        }
