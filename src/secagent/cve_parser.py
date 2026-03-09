from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import CVEConstraint


CWE_HINTS = {
    "CWE-89": "sql_injection",
    "CWE-79": "xss",
    "CWE-918": "ssrf",
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-94": "code_injection",
}


def _infer_hint(cwe_ids: list[str], title: str, description: str) -> str:
    for cwe in cwe_ids:
        if cwe in CWE_HINTS:
            return CWE_HINTS[cwe]

    text = f"{title} {description}".lower()
    if "sql" in text:
        return "sql_injection"
    if "xss" in text or "html injection" in text:
        return "xss"
    if "ssrf" in text:
        return "ssrf"
    if "path traversal" in text or "lfi" in text:
        return "path_traversal"
    if "command injection" in text:
        return "command_injection"
    return "generic"


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {
    "if", "for", "while", "return", "try", "except", "catch", "throw", "new", "class",
    "def", "function", "const", "let", "var", "public", "private", "protected", "static",
    "true", "false", "null", "none", "and", "or", "not", "in", "from", "import", "await",
}
_STOPWORDS = {
    "check", "means", "that", "this", "when", "with", "string", "forget", "forging",
    "request", "sanitize", "vulnerability", "patch", "fix", "safe", "unsafe",
}


def _normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


_NOISY_TOKENS = {
    "skip to content", "navigation menu", "appearance settings", "sign in", "sign up",
    "footer", "terms", "privacy", "community", "docs", "manage cookies",
}
_SHA_RE = re.compile(r"\b[0-9a-fA-F]{7,40}\b")


def _extract_checkout_ref(
    patch_info: dict[str, Any],
    references: list[dict[str, Any]],
    advisory_refs: list[str],
) -> str:
    # Strict mode: only ParentHash is accepted as checkout target.
    for key in ("ParentHash", "parent_hash", "parentHash"):
        v = patch_info.get(key)
        if isinstance(v, str) and _SHA_RE.fullmatch(v.strip()):
            return v.strip()
    return ""


def _extract_advisory_summary(
    advisories: list[dict[str, Any]],
    description: str,
    references: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    key_lines: list[str] = []

    # keep one concise sentence from CVE description as baseline context
    desc = _normalize_space(description)
    if desc:
        first = re.split(r"(?<=[.!?])\s+", desc)[0]
        if first:
            key_lines.append(first[:240])

    important_kw = (
        "impact", "affected", "patched", "patches", "workaround", "workarounds",
        "fix", "upgrade", "recommended", "severity", "cvss", "cve",
        "影响", "修复", "补丁", "升级", "缓解",
    )

    for adv in advisories[:3]:
        if not isinstance(adv, dict):
            continue
        raw = str(adv.get("content") or "")
        if not raw:
            continue

        for line in raw.splitlines():
            line = _normalize_space(line)
            if len(line) < 12 or len(line) > 260:
                continue
            low = line.lower()
            if any(tok in low for tok in _NOISY_TOKENS):
                continue
            if any(k in low for k in important_kw):
                key_lines.append(line)

    # dedup while preserving order
    dedup: list[str] = []
    seen: set[str] = set()
    for line in key_lines:
        if line in seen:
            continue
        seen.add(line)
        dedup.append(line)
        if len(dedup) >= 8:
            break

    urls: list[str] = []
    for r in references or []:
        if isinstance(r, dict) and r.get("url"):
            urls.append(str(r.get("url")))
    for a in advisories or []:
        if isinstance(a, dict) and a.get("url"):
            urls.append(str(a.get("url")))

    url_dedup: list[str] = []
    seen_url: set[str] = set()
    for u in urls:
        u = u.strip()
        if not u or u in seen_url:
            continue
        seen_url.add(u)
        url_dedup.append(u)
        if len(url_dedup) >= 8:
            break

    if not dedup and not url_dedup:
        return "", []

    lines = ["[SecurityAdvisories摘要]"]
    for i, item in enumerate(dedup, 1):
        lines.append(f"{i}. {item}")
    if url_dedup:
        lines.append("[参考链接]")
        for u in url_dedup[:5]:
            lines.append(f"- {u}")

    return "\n".join(lines), url_dedup


def _extract_focus_variables(old_lines: list[str], new_lines: list[str]) -> list[str]:
    candidates: list[str] = []
    for line in old_lines[:60]:
        # Prefer code-like lines, skip natural language descriptions
        if not any(ch in line for ch in ("=", "(", ")", "[", "]", "{", "}", ".", "->", "$", "::")):
            continue
        for tok in _IDENT_RE.findall(line):
            low = tok.lower()
            if low in _KEYWORDS:
                continue
            if low in _STOPWORDS:
                continue
            if len(tok) < 3:
                continue
            if tok[0].isupper() and tok.lower() not in {"sql", "xss", "ssrf"}:
                # likely class/constants or natural text labels, deprioritize
                continue
            candidates.append(tok)

    # Prefer variables that disappear or change from vulnerable old_line to new_line.
    if new_lines:
        new_text = "\n".join(new_lines)
        weighted: list[tuple[int, str]] = []
        for tok in candidates:
            score = 1
            if tok not in new_text:
                score += 2
            if tok.lower() in {"query", "sql", "cmd", "path", "url", "input", "param", "payload"}:
                score += 2
            weighted.append((score, tok))
        weighted.sort(key=lambda x: (-x[0], x[1]))
        ordered = [t for _s, t in weighted]
    else:
        ordered = candidates

    seen: set[str] = set()
    out: list[str] = []
    for tok in ordered:
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= 20:
            break
    return out


def parse_cve_file(path: str | Path) -> list[CVEConstraint]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    constraints: list[CVEConstraint] = []

    if isinstance(raw, dict):
        for key in ("items", "cves", "data", "records", "list"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raise ValueError("CVE input must be a JSON array or object containing one of: items/cves/data/records/list")

    if not isinstance(raw, list):
        raise ValueError("CVE input must be a JSON array")

    for item in raw:
        if not isinstance(item, dict):
            continue

        info: dict[str, Any] = item.get("CVEInfo", {}) if isinstance(item.get("CVEInfo"), dict) else item
        patch_info: dict[str, Any] = info.get("PatchInfo", {}) if isinstance(info.get("PatchInfo"), dict) else {}
        if not patch_info and isinstance(item.get("patch_info"), dict):
            patch_info = item["patch_info"]
        diffs: list[dict[str, Any]] = patch_info.get("Diff", []) or patch_info.get("diff", []) or []

        cwe_entries = info.get("CWE", []) or []
        if cwe_entries and isinstance(cwe_entries[0], str):
            cwe_ids = [str(c).strip() for c in cwe_entries if str(c).strip()]
        else:
            cwe_ids = [c.get("ID", "") for c in cwe_entries if isinstance(c, dict) and c.get("ID")]
        if not cwe_ids and info.get("cwe_ids"):
            cwe_ids = [str(c).strip() for c in (info.get("cwe_ids") or []) if str(c).strip()]

        target_files: list[str] = []
        old_lines: list[str] = []
        new_lines: list[str] = []

        for d in diffs:
            filename = d.get("Filename")
            if filename:
                target_files.append(filename)
            patch_text = d.get("Patch", "")
            if patch_text:
                for line in str(patch_text).splitlines():
                    line = line.strip()
                    if line.startswith("old_line:"):
                        old_lines.append(line[len("old_line:"):].strip())
                    elif line.startswith("new_line:"):
                        new_lines.append(line[len("new_line:"):].strip())

        title = info.get("Title", "") or info.get("title", "")
        description = info.get("Description", "") or info.get("description", "")
        advisories = info.get("SecurityAdvisories", []) or info.get("security_advisories", []) or []
        references = info.get("References", []) or info.get("references", []) or []
        advisory_summary, advisory_refs = _extract_advisory_summary(
            advisories=advisories if isinstance(advisories, list) else [],
            description=description,
            references=references if isinstance(references, list) else [],
        )
        checkout_ref = _extract_checkout_ref(
            patch_info=patch_info if isinstance(patch_info, dict) else {},
            references=references if isinstance(references, list) else [],
            advisory_refs=advisory_refs,
        )
        hint = _infer_hint(cwe_ids, title, description)
        cve_id = info.get("CVEID", "UNKNOWN") or info.get("cve_id", "UNKNOWN")
        repo_url = patch_info.get("RepoURL", "") or patch_info.get("repo_url", "")
        language = patch_info.get("Language", "") or patch_info.get("language", "")
        if not target_files and isinstance(info.get("target_files"), list):
            target_files = [str(x) for x in info.get("target_files", []) if str(x).strip()]
        if not old_lines and isinstance(info.get("patch_old_lines"), list):
            old_lines = [str(x) for x in info.get("patch_old_lines", []) if str(x).strip()]
        if not new_lines and isinstance(info.get("patch_new_lines"), list):
            new_lines = [str(x) for x in info.get("patch_new_lines", []) if str(x).strip()]
        focus_vars = _extract_focus_variables(old_lines, new_lines)

        constraints.append(
            CVEConstraint(
                cve_id=cve_id,
                cwe_ids=cwe_ids,
                title=title,
                description=description,
                repo_url=repo_url,
                language=language,
                target_files=target_files,
                patch_old_lines=old_lines,
                patch_new_lines=new_lines,
                patch_focus_variables=focus_vars,
                advisory_summary=advisory_summary,
                advisory_refs=advisory_refs,
                vulnerability_hint=hint,
                checkout_ref=checkout_ref,
            )
        )

    return constraints
