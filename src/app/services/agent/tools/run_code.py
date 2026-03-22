"""
通用代码执行工具 - LLM 驱动的漏洞验证

核心理念：
- LLM 是验证的大脑，工具只提供执行能力
- 不硬编码 payload、检测规则
- LLM 自己决定测试策略、编写测试代码、分析结果

使用场景：
- LLM 编写 Fuzzing Harness 进行局部测试
- LLM 构造 PoC 验证漏洞
- LLM 编写 mock 代码隔离测试函数
"""

import asyncio
import logging
import os
import tempfile
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult
from .sandbox_tool import SandboxManager, SandboxConfig

logger = logging.getLogger(__name__)


LANGUAGE_ALIASES: Dict[str, str] = {
    "python": "python",
    "py": "python",
    "php": "php",
    "javascript": "javascript",
    "js": "javascript",
    "node": "javascript",
    "go": "go",
    "golang": "go",
    "java": "java",
    "ruby": "ruby",
    "bash": "bash",
    "sh": "bash",
}

DEFAULT_RUNTIME_VERSIONS: Dict[str, str] = {
    "python": "3.11",
    "php": "8.2",
    "javascript": "20",
    "go": "1.22",
    "java": "17",
}

RUNTIME_IMAGE_TEMPLATES: Dict[str, str] = {
    "python": "python:{version}-slim",
    "php": "php:{version}-cli",
    "javascript": "node:{version}-slim",
    "go": "golang:{version}-bookworm",
    "java": "eclipse-temurin:{version}-jdk",
}


def _normalize_language_name(language: str) -> str:
    lang = str(language or "").strip().lower()
    return LANGUAGE_ALIASES.get(lang, lang)


def _sanitize_runtime_version(version: Optional[str]) -> Optional[str]:
    raw = str(version or "").strip()
    if not raw:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in raw):
        return None
    return raw[:32]


class RunCodeInput(BaseModel):
    """代码执行输入"""
    code: str = Field(..., description="要执行的代码")
    language: str = Field(default="python", description="编程语言: python, php, javascript, ruby, go, java, bash")
    runtime_version: Optional[str] = Field(
        default=None,
        description="可选运行时版本（如 python=3.12, javascript=20, go=1.22, java=17, php=8.2）",
    )
    docker_image: Optional[str] = Field(
        default=None,
        description="可选完整 Docker 镜像名，提供后将覆盖 language/runtime_version 自动选镜像",
    )
    timeout: int = Field(default=60, description="超时时间（秒），复杂测试可设置更长")
    description: str = Field(default="", description="简短描述这段代码的目的（用于日志）")


class RunCodeTool(AgentTool):
    """
    通用代码执行工具

    让 LLM 自由编写测试代码，在沙箱中执行。

    LLM 可以：
    - 编写 Fuzzing Harness 隔离测试单个函数
    - 构造 mock 对象模拟依赖
    - 设计各种 payload 进行测试
    - 分析执行结果判断漏洞

    工具不做任何假设，完全由 LLM 控制测试逻辑。
    """

    def __init__(self, sandbox_manager: Optional[SandboxManager] = None, project_root: str = "."):
        super().__init__()
        self._fixed_sandbox_manager = sandbox_manager
        self._sandbox_manager_cache: Dict[str, SandboxManager] = {}
        self._base_sandbox_timeout = 120
        self._base_sandbox_memory_limit = "1g"
        self.project_root = project_root

    @property
    def name(self) -> str:
        return "run_code"

    @property
    def description(self) -> str:
        return """🔥 通用代码执行工具 - 在沙箱中运行你编写的测试代码

这是你进行漏洞验证的核心工具。你可以：
1. 编写 Fuzzing Harness 隔离测试单个函数
2. 构造 mock 对象模拟数据库、HTTP 请求等依赖
3. 设计各种 payload 进行漏洞测试
4. 编写完整的 PoC 验证脚本

输入：
- code: 你编写的测试代码（完整可执行）
- language: python, php, javascript, ruby, go, java, bash
- runtime_version: 可选运行时版本（5种语言默认: python=3.11, php=8.2, javascript=20, go=1.22, java=17）
- docker_image: 可选完整镜像（例如 `node:20-slim`），会覆盖自动镜像选择
- timeout: 超时秒数（默认60，复杂测试可设更长）
- description: 简短描述代码目的

支持的语言和执行方式：
- python: python3 -c 'code'
- php: php -r 'code'  (注意：不需要 <?php 标签)
- javascript: node -e 'code'
- ruby: ruby -e 'code'
- go: go run (需写完整 package main)
- java: javac + java (需写完整 class)
- bash: bash -c 'code'

示例 - 命令注入 Fuzzing Harness:
```python
# 提取目标函数并构造测试
import os

# Mock os.system 来检测是否被调用
executed_commands = []
original_system = os.system
def mock_system(cmd):
    print(f"[DETECTED] os.system called: {cmd}")
    executed_commands.append(cmd)
    return 0
os.system = mock_system

# 目标函数（从项目代码复制）
def vulnerable_function(user_input):
    os.system(f"echo {user_input}")

# Fuzzing 测试
payloads = ["; id", "| whoami", "$(cat /etc/passwd)", "`id`"]
for payload in payloads:
    print(f"\\nTesting payload: {payload}")
    executed_commands.clear()
    try:
        vulnerable_function(payload)
        if executed_commands:
            print(f"[VULN] Command injection detected!")
    except Exception as e:
        print(f"Error: {e}")
```

⚠️ 重要提示：
- 代码在 Docker 沙箱中执行，与真实环境隔离
- 你需要自己 mock 依赖（数据库、HTTP、文件系统等）
- 你需要自己设计 payload 和检测逻辑
- 你需要自己分析输出判断漏洞是否存在"""

    @property
    def args_schema(self):
        return RunCodeInput

    async def _execute(
        self,
        code: str,
        language: str = "python",
        runtime_version: Optional[str] = None,
        docker_image: Optional[str] = None,
        timeout: int = 60,
        description: str = "",
        **kwargs
    ) -> ToolResult:
        """执行用户编写的代码"""
        language_requested = str(language or "").strip().lower()
        language = _normalize_language_name(language)

        sandbox_image, image_source = self._resolve_runtime_image(
            language=language,
            runtime_version=runtime_version,
            docker_image=docker_image,
        )
        sandbox_manager = self._get_sandbox_manager(sandbox_image)

        # 初始化沙箱
        try:
            await sandbox_manager.initialize()
        except Exception as e:
            logger.warning(f"Sandbox init failed: {e}")

        if not sandbox_manager.is_available:
            diagnosis = sandbox_manager.get_diagnosis()
            return ToolResult(
                success=False,
                error=f"沙箱环境不可用 (Docker Unavailable): {diagnosis}",
                data=(
                    "请确保当前 Python 进程可访问 Docker daemon。"
                    f"\n诊断: {diagnosis}\n"
                    f"镜像: {sandbox_image}\n"
                    "如果无法使用沙箱，你可以通过静态分析代码来验证漏洞。"
                ),
            )

        # 构建执行命令
        command = self._build_command(code, language)

        if command is None:
            return ToolResult(
                success=False,
                error=f"不支持的语言: {language}",
                data=f"支持的语言: python, php, javascript, ruby, go, java, bash"
            )

        # 在沙箱中执行
        runtime_env = self._build_runtime_env(language)
        result = await sandbox_manager.execute_command(
            command=command,
            timeout=timeout,
            env=runtime_env,
        )

        # 格式化输出
        output_parts = [f"🔬 代码执行结果"]
        if description:
            output_parts.append(f"目的: {description}")
        output_parts.append(f"语言: {language}")
        output_parts.append(f"镜像: {sandbox_image}")
        output_parts.append(f"退出码: {result['exit_code']}")

        if result.get("stdout"):
            stdout = result["stdout"]
            if len(stdout) > 5000:
                stdout = stdout[:5000] + f"\n... (截断，共 {len(result['stdout'])} 字符)"
            output_parts.append(f"\n输出:\n```\n{stdout}\n```")

        if result.get("stderr"):
            stderr = result["stderr"]
            if len(stderr) > 2000:
                stderr = stderr[:2000] + "\n... (截断)"
            output_parts.append(f"\n错误输出:\n```\n{stderr}\n```")

        if result.get("error"):
            output_parts.append(f"\n执行错误: {result['error']}")

        # 提示 LLM 分析结果
        output_parts.append("\n---")
        output_parts.append("请根据上述输出分析漏洞是否存在。")

        return ToolResult(
            success=result.get("success", False),
            data="\n".join(output_parts),
            error=result.get("error"),
            metadata={
                "language": language,
                "language_requested": language_requested,
                "runtime_version": _sanitize_runtime_version(runtime_version),
                "sandbox_image": sandbox_image,
                "image_source": image_source,
                "runtime_env": runtime_env,
                "exit_code": result.get("exit_code", -1),
                "stdout_length": len(result.get("stdout", "")),
                "stderr_length": len(result.get("stderr", "")),
            }
        )

    def _build_runtime_env(self, language: str) -> Dict[str, str]:
        lang = _normalize_language_name(language)
        env: Dict[str, str] = {
            "HOME": "/home/sandbox",
            "XDG_CACHE_HOME": "/tmp/.cache",
        }
        if lang == "go":
            env.update(
                {
                    # /tmp 在当前沙箱里可能带 noexec，go run 产物无法执行。
                    # 使用 /workspace 可执行挂载目录作为缓存路径。
                    "GOCACHE": "/workspace/.cache/go-build",
                    "GOPATH": "/workspace/.cache/go",
                    "GOENV": "/workspace/.cache/go/env",
                    "TMPDIR": "/workspace/.cache/tmp",
                    "GOTMPDIR": "/workspace/.cache/tmp",
                }
            )
        return env

    def _default_runtime_version(self, language: str) -> str:
        lang = _normalize_language_name(language)
        env_version = _sanitize_runtime_version(os.getenv(f"SANDBOX_VERSION_{lang.upper()}"))
        if env_version:
            return env_version
        return DEFAULT_RUNTIME_VERSIONS.get(lang, "")

    def _resolve_runtime_image(
        self,
        language: str,
        runtime_version: Optional[str] = None,
        docker_image: Optional[str] = None,
    ) -> tuple[str, str]:
        custom_image = str(docker_image or "").strip()
        if custom_image:
            return custom_image, "custom_image"

        lang = _normalize_language_name(language)
        env_image = str(os.getenv(f"SANDBOX_IMAGE_{lang.upper()}") or "").strip()
        if env_image:
            return env_image, "env_lang_image"

        template = RUNTIME_IMAGE_TEMPLATES.get(lang)
        if template:
            version = _sanitize_runtime_version(runtime_version) or self._default_runtime_version(lang)
            if version:
                return template.format(version=version), "language_version_default"

        fallback = str(os.getenv("SANDBOX_IMAGE") or "").strip()
        if fallback:
            return fallback, "env_default_image"
        return "python:3.11-slim", "hardcoded_default_image"

    def _get_sandbox_manager(self, image: str) -> SandboxManager:
        if self._fixed_sandbox_manager is not None:
            return self._fixed_sandbox_manager

        key = str(image or "").strip() or "python:3.11-slim"
        mgr = self._sandbox_manager_cache.get(key)
        if mgr is not None:
            return mgr

        cfg = SandboxConfig(
            image=key,
            timeout=self._base_sandbox_timeout,
            memory_limit=self._base_sandbox_memory_limit,
        )
        mgr = SandboxManager(cfg)
        self._sandbox_manager_cache[key] = mgr
        return mgr

    def _build_command(self, code: str, language: str) -> Optional[str]:
        """根据语言构建执行命令"""

        # 转义单引号的通用方法
        def escape_for_shell(s: str) -> str:
            return s.replace("'", "'\"'\"'")

        if language == "python":
            escaped = escape_for_shell(code)
            return f"python3 -c '{escaped}'"

        elif language == "php":
            # PHP: php -r 不需要 <?php 标签
            clean_code = code.strip()
            if clean_code.startswith("<?php"):
                clean_code = clean_code[5:].strip()
            if clean_code.startswith("<?"):
                clean_code = clean_code[2:].strip()
            if clean_code.endswith("?>"):
                clean_code = clean_code[:-2].strip()
            escaped = escape_for_shell(clean_code)
            return f"php -r '{escaped}'"

        elif language in ["javascript", "js", "node"]:
            escaped = escape_for_shell(code)
            return f"node -e '{escaped}'"

        elif language == "ruby":
            escaped = escape_for_shell(code)
            return f"ruby -e '{escaped}'"

        elif language == "bash":
            escaped = escape_for_shell(code)
            return f"bash -c '{escaped}'"

        elif language == "go":
            # Go 需要完整的 package main
            escaped = escape_for_shell(code).replace("\\", "\\\\")
            return (
                "mkdir -p /workspace/.cache/tmp /workspace/.cache/go /workspace/.cache/go-build "
                f"&& echo '{escaped}' > /workspace/main.go "
                "&& go run /workspace/main.go"
            )

        elif language == "java":
            # Java 需要完整的 class
            escaped = escape_for_shell(code).replace("\\", "\\\\")
            # 提取类名
            import re
            class_match = re.search(r'public\s+class\s+(\w+)', code)
            class_name = class_match.group(1) if class_match else "Test"
            return f"echo '{escaped}' > /tmp/{class_name}.java && javac /tmp/{class_name}.java && java -cp /tmp {class_name}"

        return None


class ExtractFunctionInput(BaseModel):
    """函数提取输入"""
    file_path: str = Field(..., description="源文件路径")
    function_name: str = Field(..., description="要提取的函数名")
    include_imports: bool = Field(default=True, description="是否包含 import 语句")


class ExtractFunctionTool(AgentTool):
    """
    函数提取工具

    从源文件中提取指定函数及其依赖，用于构建 Fuzzing Harness
    """

    def __init__(self, project_root: str = "."):
        super().__init__()
        self.project_root = project_root

    @property
    def name(self) -> str:
        return "extract_function"

    @property
    def description(self) -> str:
        return """从源文件中提取指定函数的代码

用于构建 Fuzzing Harness 时获取目标函数代码。

输入：
- file_path: 源文件路径
- function_name: 要提取的函数名
- include_imports: 是否包含文件开头的 import 语句（默认 true）

返回：
- 函数代码
- 相关的 import 语句
- 函数参数列表

示例：
{"file_path": "app/api.py", "function_name": "process_command"}"""

    @property
    def args_schema(self):
        return ExtractFunctionInput

    async def _execute(
        self,
        file_path: str,
        function_name: str,
        include_imports: bool = True,
        **kwargs
    ) -> ToolResult:
        """提取函数代码"""
        import ast
        import re

        full_path = os.path.join(self.project_root, file_path)
        if not os.path.exists(full_path):
            return ToolResult(success=False, error=f"文件不存在: {file_path}")

        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()

        # 检测语言
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".py":
            result = self._extract_python(code, function_name, include_imports)
        elif ext == ".php":
            result = self._extract_php(code, function_name)
        elif ext in [".js", ".ts"]:
            result = self._extract_javascript(code, function_name)
        else:
            result = self._extract_generic(code, function_name)

        if result["success"]:
            output_parts = [f"📦 函数提取结果\n"]
            output_parts.append(f"文件: {file_path}")
            output_parts.append(f"函数: {function_name}")

            if result.get("imports"):
                output_parts.append(f"\n相关 imports:\n```\n{result['imports']}\n```")

            if result.get("parameters"):
                output_parts.append(f"\n参数: {', '.join(result['parameters'])}")

            output_parts.append(f"\n函数代码:\n```\n{result['code']}\n```")

            output_parts.append("\n---")
            output_parts.append("你现在可以使用这段代码构建 Fuzzing Harness")

            return ToolResult(
                success=True,
                data="\n".join(output_parts),
                metadata=result
            )
        else:
            return ToolResult(
                success=False,
                error=result.get("error", "提取失败"),
                data=f"无法提取函数 '{function_name}'。你可以使用 read_file 工具直接读取文件，手动定位函数代码。"
            )

    def _extract_python(self, code: str, function_name: str, include_imports: bool) -> Dict:
        """提取 Python 函数"""
        import ast

        try:
            tree = ast.parse(code)
        except SyntaxError:
            # 降级到正则提取
            return self._extract_generic(code, function_name)

        # 收集 imports
        imports = []
        if include_imports:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.append(ast.unparse(node))
                elif isinstance(node, ast.ImportFrom):
                    imports.append(ast.unparse(node))

        # 查找函数
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == function_name:
                    lines = code.split('\n')
                    func_code = '\n'.join(lines[node.lineno - 1:node.end_lineno])
                    params = [arg.arg for arg in node.args.args]

                    return {
                        "success": True,
                        "code": func_code,
                        "imports": '\n'.join(imports) if imports else None,
                        "parameters": params,
                        "line_start": node.lineno,
                        "line_end": node.end_lineno,
                    }

        return {"success": False, "error": f"未找到函数 '{function_name}'"}

    def _extract_php(self, code: str, function_name: str) -> Dict:
        """提取 PHP 函数"""
        import re

        pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{'
        match = re.search(pattern, code)

        if not match:
            return {"success": False, "error": f"未找到函数 '{function_name}'"}

        start_pos = match.start()
        brace_count = 0
        end_pos = match.end() - 1

        for i, char in enumerate(code[match.end() - 1:], start=match.end() - 1):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        func_code = code[start_pos:end_pos]

        # 提取参数
        param_match = re.search(r'function\s+\w+\s*\(([^)]*)\)', func_code)
        params = []
        if param_match:
            params_str = param_match.group(1)
            params = [p.strip().split('=')[0].strip().replace('$', '')
                     for p in params_str.split(',') if p.strip()]

        return {
            "success": True,
            "code": func_code,
            "parameters": params,
        }

    def _extract_javascript(self, code: str, function_name: str) -> Dict:
        """提取 JavaScript 函数"""
        import re

        patterns = [
            rf'function\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{',
            rf'(?:const|let|var)\s+{re.escape(function_name)}\s*=\s*function\s*\([^)]*\)\s*\{{',
            rf'(?:const|let|var)\s+{re.escape(function_name)}\s*=\s*\([^)]*\)\s*=>\s*\{{',
            rf'async\s+function\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{',
        ]

        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                start_pos = match.start()
                brace_count = 0
                end_pos = match.end() - 1

                for i, char in enumerate(code[match.end() - 1:], start=match.end() - 1):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_pos = i + 1
                            break

                func_code = code[start_pos:end_pos]

                return {
                    "success": True,
                    "code": func_code,
                }

        return {"success": False, "error": f"未找到函数 '{function_name}'"}

    def _extract_generic(self, code: str, function_name: str) -> Dict:
        """通用函数提取（正则）"""
        import re

        # 尝试多种模式
        patterns = [
            rf'def\s+{re.escape(function_name)}\s*\([^)]*\)\s*:',  # Python
            rf'function\s+{re.escape(function_name)}\s*\([^)]*\)',  # PHP/JS
            rf'func\s+{re.escape(function_name)}\s*\([^)]*\)',  # Go
        ]

        for pattern in patterns:
            match = re.search(pattern, code, re.MULTILINE)
            if match:
                start_line = code[:match.start()].count('\n')
                lines = code.split('\n')

                # 尝试找到函数结束
                end_line = start_line + 1
                indent = len(lines[start_line]) - len(lines[start_line].lstrip())

                for i in range(start_line + 1, min(start_line + 100, len(lines))):
                    line = lines[i]
                    if line.strip() and not line.startswith(' ' * (indent + 1)):
                        if not line.strip().startswith('#'):
                            end_line = i
                            break
                    end_line = i + 1

                func_code = '\n'.join(lines[start_line:end_line])

                return {
                    "success": True,
                    "code": func_code,
                }

        return {"success": False, "error": f"未找到函数 '{function_name}'"}
