# DeepAudit 对齐清单

## 1) 代码迁移状态

- 对齐源：`/Users/forimoc/Desktop/workspace/DeepAudit/backend/app`
- 对齐目标：`/Users/forimoc/Desktop/workspace/SecAgent/src/app`
- 结果：缺失文件数 `117 -> 0`（未覆盖已改造文件，只补缺失）

已补齐目录：
- `api/*`
- `core/*`
- `db/*`
- `models/*`
- `schemas/*`
- `services/*`（含 `agent/knowledge/streaming/telemetry/core/tools`、`llm/adapters`、`rag`、`scanner`、`report_generator`）
- `utils/*`

## 2) 输入对齐

`secagent.cve_parser.parse_cve_file` 已兼容：
- 原始数组格式：`[ {...}, {...} ]`
- 包装对象格式：`{ "items": [...] }` / `cves` / `data` / `records` / `list`
- 字段兼容：
  - `CVEInfo` 或扁平字段
  - `PatchInfo` 或 `patch_info`
  - `CWE` 对象数组或 `cwe_ids` 字符串数组
  - `Title/Description` 与 `title/description`
  - `RepoURL/Language` 与 `repo_url/language`

## 3) 输出对齐

新增 `src/secagent/deepaudit_adapter.py`：
- CLI 统一输出 DeepAudit 风格 `issues`（去除 `findings/issues` 双轨重复输出）

DeepAudit `issues` 对齐字段包含：
- `type`, `severity`, `title`, `description`
- `file_path`, `line`, `line_end`, `location`
- `code_snippet`, `suggestion`, `recommendation`
- `confidence`, `verdict`, `ai_explanation`
- `source`, `sink`, `source_to_sink_path`

## 4) 证据质量约束

`pipeline` 已启用强约束：
- 过滤占位发现（`potential_issue/recon_high_risk` 等）
- 必须有可用 `sink + code_snippet`
- 必须存在 `source_to_sink_path` 且至少含 `source` 与 `sink` 节点

## 5) 已知剩余差距（运行时依赖层）

以下并非“代码未迁移”，而是“运行时环境未接入”：
- 真实 LLM Adapter/Provider 已接入（当前默认真实 LLM，需配置可用 key/model）
- DB / FastAPI 服务启动依赖（仅在需要 API 服务时）
- 外部安全工具与沙箱能力（semgrep/bandit/动态验证）
- 完整前后端联调链路（本次聚焦 SecAgent CLI + 批量 CVE 工作流）
