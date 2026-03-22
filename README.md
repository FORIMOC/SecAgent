# Sec Agent（从 DeepAudit 重构）

SecAgent 已迁移 DeepAudit 的核心 Multi-Agent 审计逻辑，并将输入/输出重构为 **CVE 定向审计模式**。

## 重构目标

- 输入：`Repo + CVE 语义集`
  - 包含 CVE ID、CWE、描述、补丁信息、公告等
  - 样例：`data/input/example.json`（仓库中还包含 `data/input/example_1.json`、`data/input/4369.json`）
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

### 1) 安装

```bash
cd /Users/forimoc/Desktop/workspace/SecAgent
pip install -e .
# 查看参数
secagent -h
```

也可使用模块方式：

```bash
PYTHONPATH=src python -m secagent.cli -h
```

### 2) 配置 LLM

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

### 3) 执行

默认模式（不传 `--repo`，按 CVE 中 `RepoURL` 自动缓存 + clone + checkout）：

```bash
secagent --cve data/input/example.json --workers 8 --out data/result/result.json
```

兼容模式（传 `--repo`，所有 CVE 都在同一个本地仓库分析，不 clone）：

```bash
secagent --cve data/input/example_1.json --repo data/repos/dolibarr_7dfee3b2bfb421ef --workers 1 --out data/result/result_example.json
```

仅验证模式（只走 VerificationAgent，输入为已有结果文件）：

```bash
secagent --verify-evidence --cve data/result/result.json --out data/result/evidence.json
```

说明：
- 默认模式（不传 `--repo`）：对输入中的每个 CVE 并发执行。  
  流程：读取 CVE -> 将 `repo_url` 缓存到 `data/repos`（同仓库只 clone 一次）-> 从缓存 clean copy 到临时 workspace -> `git checkout` 到 `ParentHash` -> 启动 secagent 分析。
- 兼容模式（传 `--repo`）：所有 CVE 都在同一个本地仓库上分析（不 clone）。
- `--out` 默认值为 `data/result/result.json`。若文件已存在，默认会断点续跑并合并已有结果；可用 `--no-resume` 关闭。
- 开启 `--verify-evidence` 时：
  - `--cve` 不再是 CVE 语义文件，而是已有结果文件（包含 `issues[]`）
  - 仅调用 VerificationAgent 验证 `source-to-sink` 路径证据
  - 当输入包含多个 CVE 时，按 `CVEID` 分组并发验证（每个 CVE 仅执行一次 verifier，使用 `--workers` 控制并发）
  - 自动从仓库缓存中定位对应仓库（默认 `<project>/data/repos`，可用 `--repo-cache-root` 覆盖）
  - 同样支持断点续跑：若 `--out` 已存在，会自动跳过已完成的 `CVEID`；使用 `--no-resume` 可关闭
  - `--out` 默认切换为 `data/result/evidence.json`
- 每次运行会写日志到 `data/log/run_YYYYMMDD_HHMMSS.log`；默认写入 thought 日志，使用 `--log-full` 可写入完整 stdout/stderr。
- 可选参数：
  - `--workspace-root /path/to/ws` 指定 clone 临时工作目录根
  - `--repo-cache-root /path/to/repos` 指定仓库缓存根目录（默认 `<project>/data/repos`）
  - `--keep-workspace` 保留临时 clone 目录用于排查
  - `--log-dir data/log` 指定日志目录

注意：
- 默认模式依赖 CVE 输入中的 `PatchInfo.ParentHash`，缺失时会在准备工作区阶段失败。
- 默认使用真实 LLM 服务，需保证网络可访问所选模型服务端。

`--verify-evidence` 输出结构（evidence 文件）：
- `meta`：模式、生成时间、输入文件、处理统计
- `summary`：
  - `source_to_sink_claims`：路径属实性汇总（`true/false/inconclusive`）
  - `verifier_verdicts`：Verifier 判定汇总（`confirmed/likely/uncertain/false_positive`）
- `evidence[]`：按 `CVEID` 索引的 evidence 列表，每项结构为：
  - `cve_id`
  - `summary`：该 CVE 的路径属实性与 verifier 判定汇总
  - `evidence_items[]`：该 CVE 下每条路径的验证证据（不回填输入中的路径原文）
    - `issue_index`：输入 `issues[]` 的序号引用
    - `source_to_sink_claim`：路径是否属实（`true/false/inconclusive`）及理由
    - `verifier_judgement`：Verifier 的判定与置信度
    - `proof`：
      - `type`：`dynamic/static_analysis/mixed/none`
      - `method/details`：Verifier 给出的验证方法与证据描述
      - `artifacts`：可选 PoC/Harness/steps/payload
      - `path_checks`：基于仓库缓存做的节点级匹配证据（匹配/不匹配/缺文件等）

输出统一为 DeepAudit 风格 `issues`（不再同时输出 `findings`，避免重复语义）。
当前执行链已关闭规则式兜底（不再使用 `path_finder/verifier` 进行预定义规则匹配回填），结果仅来自 Multi-Agent 主流程。
每个 issue 额外包含 `Nodes` 字段，结构对齐 Source/Propagation/Sink 节点（Type/File/StartLine/EndLine/Desc）。

## 说明

- 当前版本已实现“迁移后可运行”与“CVE 定向输入输出”。
- LLM 配置支持 `config/llm.toml` + 环境变量覆盖（`src/app/core/config.py` + `src/secagent/agent_runner.py`）。
- 输入兼容：`--cve` 支持 JSON 数组，以及包含 `items/cves/data/records/list` 任一列表字段的对象格式。
