# SecAgent 架构设计

本文档描述当前 SecAgent（CVE 定向审计版）的整体流程、模块分层、关键数据结构与运行时行为。

## 1. 目标与设计原则

SecAgent 的目标是：
- 输入 `CVE 语义信息 + 目标仓库`（单仓或批量多仓）
- 基于 Multi-Agent 进行定向漏洞审计
- 输出 DeepAudit 风格的结构化 `issues`

核心设计原则：
- 以 CVE 语义约束驱动分析范围，而非全仓盲扫
- Multi-Agent 自主决策（Orchestrator / Recon / Analysis / Verification）
- 批量任务并发执行，仓库 clone 缓存复用
- 输出统一到单一语义（`issues`），避免 finding/issue 重复

---

## 2. 端到端流程（E2E）

### 2.1 CLI 入口
文件：`src/secagent/cli.py`

入口命令：
- `python -m secagent.cli --cve ... --workers ... --out ...`

主要参数：
- `--cve`：CVE JSON 输入文件（支持数组或包装字段）
- `--repo`：可选，兼容模式下固定本地仓库
- `--workers`：批处理并发度
- `--workspace-root`：临时工作目录根
- `--repo-cache-root`：仓库缓存目录（默认 `data/repos`）
- `--keep-workspace`：保留临时目录用于排查

CLI 调用 `run_pipeline(...)`，将结果转换为 DeepAudit 兼容格式输出。

### 2.2 Pipeline 编排
文件：`src/secagent/pipeline.py`

高层逻辑：
1. 解析 CVE 列表（`parse_cve_file`）
2. 对每个 CVE 运行审计（固定 repo 或 clone 模式）
3. 从 Multi-Agent 结果中挑选 Top1 可行动结果
4. 归一化为 `DirectedFinding`
5. 生成汇总统计（matched/unmatched/failed）

两种运行模式：
- `--repo` 指定：所有 CVE 复用同一仓库（兼容模式）
- 不指定 `--repo`：按 CVE 的 `repo_url` 自动处理
  - `data/repos` 缓存 clone（同仓只 clone 一次）
  - 每个 CVE 从缓存 clean copy 到临时 workspace
  - 审计结束后按配置清理 workspace

### 2.3 CVE 定向审计执行
文件：`src/secagent/agent_runner.py`

对单个 CVE：
1. 构建 LLM 服务（真实 LLM）
2. 依据 CVE 约束选择目标文件集合（`target_files`）
3. 实例化 3 个文件工具：`list_files/read_file/search_code`
4. 初始化 4 个 Agent：Orchestrator + Recon + Analysis + Verification
5. 组装 `project_info/config`（含 CVE 语义与范围约束）
6. 调用 `orchestrator.run(...)`

Orchestrator 会在运行中调度子 Agent，并在终端打印子 Agent 输入输出（便于观测）。

### 2.4 输出适配
文件：`src/secagent/deepaudit_adapter.py`

将 `PipelineResult` 转换为最终输出：
- `issues[]`
- `quality_score`
- `severity_summary`
- `summary`

并补充 `Nodes`（Source/Propagation/Sink）与 `source_to_sink_path` 字段。

---

## 3. 输入语义与约束构建

文件：`src/secagent/cve_parser.py`, `src/secagent/models.py`

`CVEConstraint` 关键字段：
- 基础信息：`cve_id/cwe_ids/title/description/repo_url/language`
- 补丁信息：`target_files/patch_old_lines/patch_new_lines`
- 补丁焦点变量：`patch_focus_variables`
- 安全公告摘要：`advisory_summary/advisory_refs`
- 漏洞类型提示：`vulnerability_hint`

### SecurityAdvisories 注入
解析时会提取并精炼：
- `SecurityAdvisories[].content`
- `References[]`

生成 `[SecurityAdvisories摘要]` 文本，并在 `agent_runner` 中注入：
- Orchestrator 的 `scope_message`
- 子 Agent 的 `config.cve_advisory_summary`

作用：让 Agent 在补丁 diff 之外，获得公告中的影响范围、修复建议、版本信息等上下文。

---

## 4. Multi-Agent 层设计

目录：`src/app/services/agent/agents/`

### 4.1 OrchestratorAgent
职责：
- 作为总控，循环决策下一步动作
- 调度 `recon/analysis/verification`
- 汇总并去重各阶段发现
- 控制退出（`finish`）与异常兜底

行为特点：
- ReAct 风格循环（Thought/Action/Action Input）
- 终端输出子 Agent 入参与结果摘要
- 限制重复调度同一子 Agent，防止无效循环

### 4.2 ReconAgent
职责：
- 项目结构与技术栈侦察
- 识别入口点、高风险区域
- 生成初步发现与后续分析建议

输入重点：
- `target_files`（CVE 定向范围）
- `cve_advisory_summary`（若有）

### 4.3 AnalysisAgent
职责：
- 深度漏洞分析与证据构建
- 优先聚焦高风险区域与目标文件
- 输出结构化 findings（供后续验证）

输入重点：
- Recon 的 handoff / previous_results
- `target_vulnerabilities`
- `cve_advisory_summary`

### 4.4 VerificationAgent
职责：
- 对 Analysis 发现进行验证
- 给出 verdict（confirmed/likely/uncertain/false_positive）
- 补充验证方法、证据、PoC 信息

约束：
- 至少执行一次工具调用才允许 `Final Answer`
- 避免“无验证直接收敛”的假阳性输出

---

## 5. 工具层设计

目录：`src/app/services/agent/tools/`

当前 CVE 定向主链核心使用：
- `file_tool.py`
  - `ListFilesTool`
  - `FileReadTool`
  - `FileSearchTool`

说明：
- 现阶段主链以代码阅读/搜索为主
- 其他工具（外部扫描、沙箱、run_code 等）已在框架中保留，可作为后续增强路径

---

## 6. LLM 与配置体系

### 6.1 运行时 LLM 构建
文件：`src/secagent/agent_runner.py`

规则：
- 默认真实 LLM（无 mock 主链）
- 若未显式设置 `LLM_PROVIDER`，会按 API Key 自动推断 provider
- DeepSeek 未指定模型时兜底 `deepseek-chat`

### 6.2 配置来源优先级
文件：`src/app/core/config.py`, `config/llm.toml`

优先级：
1. 环境变量
2. `config/llm.toml`（或 `SECAGENT_LLM_CONFIG` 指向的文件）

`llm.toml` 可配置：
- `provider/model/base_url/timeout/temperature/max_tokens`
- `api_key_env`（从环境变量读取 key，避免明文）
- agent 超时相关参数

---

## 7. 并发与工作区管理

文件：`src/secagent/pipeline.py`

### 7.1 批量并发
- 通过 `ThreadPoolExecutor(max_workers=workers)` 并发处理 CVE
- 每个 CVE 独立 workspace，互不污染

### 7.2 仓库缓存机制
- 缓存目录：`data/repos`
- cache key：`repo_url` 哈希 + repo 名
- 若缓存存在直接复用，避免重复 clone

### 7.3 临时工作区
- 默认位于系统临时目录（`tempfile.mkdtemp`，macOS 常见 `/var/folders/.../T/...`）
- 每个 CVE 会从缓存仓 clean copy 到 `.../<cve_ws>/repo`
- `--keep-workspace` 可保留目录用于调试

---

## 8. 输出模型

内部模型：`DirectedFinding`
- 包含 `cve_id/vulnerability_type/severity/title/description/...`
- `source/sink/source_to_sink_path` 支持数据流表达
- `evidence` 承载验证细节与原始记录

最终输出：`issues[]`
- 统一单一问题语义
- 附加 `Nodes`（Source/Propagation/Sink）便于路径展示

Top1 选择策略：
- 优先可行动 finding（有 sink、代码片段、路径信息）
- 综合置信度、文件命中、漏洞类型一致性、验证状态进行打分

---

## 9. 稳定性与防护机制

已实现的关键防护：
- LLM 空响应重试与格式重试
- API 错误分级处理（认证/配额/限流/连接）
- 工具重复失败检测，强制提示换策略
- Verification 阶段强制工具调用，避免无证据结论
- JSON 解析失败回退（建议安装 `json-repair` 提高鲁棒性）

---

## 10. 目录分层总览

- `src/secagent/`
  - CVE 定向重构层（CLI、解析、pipeline、runner、输出适配）
- `src/app/services/agent/`
  - DeepAudit Multi-Agent 核心（agents/core/tools/prompts/json_parser/...）
- `src/app/services/llm/`
  - LLMService + provider adapter（litellm）
- `config/`
  - LLM/agent 运行配置
- `data/`
  - CVE 输入、repo 缓存、运行数据

---

## 11. 当前状态与后续扩展建议

当前主链已具备：
- CVE 语义约束 + patch diff 驱动
- SecurityAdvisories 精炼注入
- 批量并发审计与仓库缓存
- Multi-Agent 自主分析与验证
- DeepAudit 风格输出统一

后续建议优先级：
1. 将 Semgrep/Bandit 等 SAST 工具纳入 Analysis 主链（非可选旁路）
2. 增强 source->sink 路径重建质量（跨函数/跨文件）
3. 为不同语言建立更细粒度的约束提示模板
4. 增加可复现验证工件（验证脚本与执行日志落盘）

