# Sec Agent（从 DeepAudit 重构）

SecAgent 已迁移 DeepAudit 的核心 Multi-Agent 审计逻辑，并将输入/输出重构为 **CVE 定向审计模式**。

## 重构目标

- 输入：`Repo + CVE 语义集`
  - 包含 CVE ID、CWE、描述、补丁信息、公告等
  - 样例：`data/example.json`
- 输出：每个 CVE 的 **定向 Top1 漏洞结果**（字段风格兼容 DeepAudit finding）

## 已迁移的 DeepAudit 核心逻辑

已迁移到 `src/app/services/`：

- Multi-Agent 核心：
  - `agent/agents/`（Orchestrator / Recon / Analysis / Verification / BaseAgent）
- Agent 基础设施：
  - `agent/core/state.py`
  - `agent/core/registry.py`
  - `agent/core/message.py`
- Agent 关键能力：
  - `agent/json_parser.py`
  - `agent/prompts/`
  - `agent/tools/base.py`
  - `agent/tools/file_tool.py`
  - `agent/tools/pattern_tool.py`
- LLM 辅助：
  - `llm/memory_compressor.py`
  - `llm/tokenizer.py`

此外，已将 `DeepAudit/backend/app` 中此前未迁移的模块全部补齐到 `SecAgent/src/app`（按原目录结构，缺失文件数已降为 0），包括：
- `api/`, `db/`, `models/`, `schemas/`, `utils/`
- `services/agent` 下的 `knowledge/streaming/telemetry/core/tools` 等子模块
- `services/llm/adapters`, `services/rag`, `services/scanner`, `services/report_generator` 等

## SecAgent 重构层（输入/输出重点）

位于 `src/secagent/`：

- `cve_parser.py`：CVE 语义解析
- `agent_runner.py`：CVE 约束驱动的 Multi-Agent 执行入口
- `pipeline.py`：每个 CVE 的 Top1 结果筛选与标准化
- `cli.py`：命令行入口

## 运行

```bash
cd /Users/forimoc/Desktop/workspace/SecAgent
pip install -e .
PYTHONPATH=src python -m secagent.cli --cve data/example.json --workers 8 --out result.json
```

默认使用**真实 LLM 服务**（无 mock 分支）。

LLM 配置文件：`config/llm.toml`
- 统一配置 `provider/model/base_url/timeout/temperature/max_tokens`
- `api_key` 不写明文，使用 `api_key_env` 指定环境变量名读取（默认 `DEEPSEEK_API_KEY`）
- 可通过 `SECAGENT_LLM_CONFIG=/abs/path/llm.toml` 指向自定义配置文件

运行前请至少导出 key（其余参数可走 `config/llm.toml`）：

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY=xxx
# 可选
export LLM_MODEL=gpt-4o-mini
```

或：

```bash
export LLM_PROVIDER=deepseek
export DEEPSEEK_API_KEY=xxx
```

也可仅设置 provider 对应密钥，不设置 `LLM_PROVIDER`，系统会自动推断：

```bash
export DEEPSEEK_API_KEY=xxx
```

说明：
- 默认模式（不传 `--repo`）：对 `data/example.json` 中每个 CVE 并发执行  
  流程：读取 CVE -> 将 `repo_url` 缓存到 `data/repos`（同仓库只 clone 一次）-> 从缓存 clean copy 到临时 workspace -> 启动 secagent 分析。
- 兼容模式（传 `--repo`）：所有 CVE 都在同一个本地仓库上分析（不 clone）。
- 可选参数：
  - `--workspace-root /path/to/ws` 指定 clone 目录根
  - `--repo-cache-root /path/to/repos` 指定仓库缓存根目录（默认 `data/repos`）
  - `--keep-workspace` 保留临时 clone 目录用于排查

输出统一为 DeepAudit 风格 `issues`（不再同时输出 `findings`，避免重复语义）。
当前执行链已关闭规则式兜底（不再使用 `path_finder/verifier` 进行预定义规则匹配回填），结果仅来自 Multi-Agent 主流程。
每个 issue 额外包含 `Nodes` 字段，结构对齐 Source/Propagation/Sink 节点（Type/File/StartLine/EndLine/Desc）。

## 说明

- 当前版本已实现“迁移后可运行”与“CVE 定向输入输出”。
- LLM 配置支持 `config/llm.toml` + 环境变量覆盖（`src/app/core/config.py` + `src/secagent/agent_runner.py`）。
- 输入兼容：`--cve` 支持 JSON 数组，以及包含 `items/cves/data/records/list` 任一列表字段的对象格式。
