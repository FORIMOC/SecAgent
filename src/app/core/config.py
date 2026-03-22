from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


class _Settings:
    # Agent defaults
    LLM_FIRST_TOKEN_TIMEOUT = 30
    LLM_STREAM_TIMEOUT = 60
    AGENT_TIMEOUT_SECONDS = 1800
    SUB_AGENT_TIMEOUT_SECONDS = 1800
    TOOL_TIMEOUT_SECONDS = 60

    # Sandbox defaults (non-SAST verification tools)
    SANDBOX_IMAGE = "python:3.11-slim"
    SANDBOX_CAP_DROP = "ALL"
    SANDBOX_NO_NEW_PRIVILEGES = True

    def __init__(self) -> None:
        self._file_values = self._load_file_values()

    @staticmethod
    def _project_root() -> Path:
        # src/app/core/config.py -> project root
        return Path(__file__).resolve().parents[3]

    def _load_file_values(self) -> dict[str, Any]:
        config_path = os.getenv(
            "SECAGENT_LLM_CONFIG",
            str(self._project_root() / "config" / "llm.toml"),
        )
        path = Path(config_path)
        if not path.is_file():
            return {}

        with path.open("rb") as f:
            raw = tomllib.load(f)

        llm = raw.get("llm", {}) if isinstance(raw, dict) else {}
        agent = raw.get("agent", {}) if isinstance(raw, dict) else {}

        out: dict[str, Any] = {}

        # LLM config
        if llm.get("provider"):
            out["LLM_PROVIDER"] = str(llm["provider"])
        if llm.get("model"):
            out["LLM_MODEL"] = str(llm["model"])
        if llm.get("base_url"):
            out["LLM_BASE_URL"] = str(llm["base_url"])
        if llm.get("timeout") is not None:
            out["LLM_TIMEOUT"] = int(llm["timeout"])
        if llm.get("temperature") is not None:
            out["LLM_TEMPERATURE"] = float(llm["temperature"])
        if llm.get("max_tokens") is not None:
            out["LLM_MAX_TOKENS"] = int(llm["max_tokens"])

        # Read API key from env variable name defined in file.
        api_key_env = llm.get("api_key_env")
        if api_key_env:
            out["LLM_API_KEY"] = os.getenv(str(api_key_env), "")

        # Optional provider-specific keys from file-specified env names.
        provider_key_envs = llm.get("provider_key_env", {})
        if isinstance(provider_key_envs, dict):
            for provider, env_name in provider_key_envs.items():
                if not provider or not env_name:
                    continue
                out[f"{str(provider).upper()}_API_KEY"] = os.getenv(str(env_name), "")

        # Agent timeout config
        if agent.get("llm_first_token_timeout") is not None:
            out["LLM_FIRST_TOKEN_TIMEOUT"] = int(agent["llm_first_token_timeout"])
        if agent.get("llm_stream_timeout") is not None:
            out["LLM_STREAM_TIMEOUT"] = int(agent["llm_stream_timeout"])
        if agent.get("agent_timeout_seconds") is not None:
            out["AGENT_TIMEOUT_SECONDS"] = int(agent["agent_timeout_seconds"])
        if agent.get("sub_agent_timeout_seconds") is not None:
            out["SUB_AGENT_TIMEOUT_SECONDS"] = int(agent["sub_agent_timeout_seconds"])
        if agent.get("tool_timeout_seconds") is not None:
            out["TOOL_TIMEOUT_SECONDS"] = int(agent["tool_timeout_seconds"])

        return out

    def __getattr__(self, name: str):
        """
        Priority:
        1. Environment variable
        2. config/llm.toml (or SECAGENT_LLM_CONFIG)
        3. AttributeError (so getattr(..., default) works)
        """
        env_val = os.getenv(name)
        if env_val is not None:
            # Keep compatibility with existing usage that expects str/int/float conversions
            if name in {"LLM_TIMEOUT", "LLM_MAX_TOKENS", "LLM_FIRST_TOKEN_TIMEOUT", "LLM_STREAM_TIMEOUT", "AGENT_TIMEOUT_SECONDS", "SUB_AGENT_TIMEOUT_SECONDS", "TOOL_TIMEOUT_SECONDS"}:
                return int(env_val)
            if name in {"LLM_TEMPERATURE"}:
                return float(env_val)
            return env_val

        if name in self._file_values:
            return self._file_values[name]

        raise AttributeError(name)


settings = _Settings()
