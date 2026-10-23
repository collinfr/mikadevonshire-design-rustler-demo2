#!/usr/bin/env python3
"""
CodeMender GitHub Issues Automation Helper
Parses findings from findings.json (or cm-find.log), deduplicates/updates existing
issues using multi-signal fuzzy matching (File, Line Proximity, CWE/Type, Lexical),
and creates/updates individual GitHub Issues enriched with full details and
embedded stateless metadata for cross-model verification.
"""

import json
import os
import re
import subprocess
import sys
from difflib import SequenceMatcher

def run_cmd(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error running: {cmd}\n{result.stderr}", file=sys.stderr)
    return result

def run_gh_cmd(cmd):
    env = os.environ.copy()
    bot_token = os.environ.get("ACTIONS_BOT_TOKEN")
    if bot_token:
        env["GH_TOKEN"] = bot_token
    elif os.environ.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode == 0:
        return res
    fallback_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if fallback_token and fallback_token != bot_token:
        env["GH_TOKEN"] = fallback_token
        return subprocess.run(cmd, capture_output=True, text=True, env=env)
    return res

def get_language_from_ext(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    lang_map = {
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".py": "python",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".go": "go",
        ".java": "java",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".sh": "bash",
        ".bash": "bash",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".sql": "sql"
    }
    return lang_map.get(ext, "")

def clean_file_path(path):
    if not path:
        return ""
    p = str(path).strip()
    if p.startswith("/workspace/repo/"):
        p = p[len("/workspace/repo/"):]
    elif p.startswith("/workspace/"):
        p = p[len("/workspace/"):]
    elif os.path.isabs(p):
        for marker in ["/repo/"]:
            if marker in p:
                p = p.split(marker, 1)[1]
                break
    p = re.sub(r"^\.?/+", "", p)
    p = re.sub(r"^(\.\./)+", "", p)
    return p

CWE_CATEGORY_MAP = {
    "sql injection": ("CWE-89", "injection"),
    "sqli": ("CWE-89", "injection"),
    "cwe-89": ("CWE-89", "injection"),
    "nosql injection": ("CWE-943", "injection"),
    "nosql / javascript injection": ("CWE-943", "injection"),
    "cwe-943": ("CWE-943", "injection"),
    "cross-site scripting": ("CWE-79", "xss"),
    "xss": ("CWE-79", "xss"),
    "cwe-79": ("CWE-79", "xss"),
    "open redirect": ("CWE-601", "redirect"),
    "unvalidated redirect": ("CWE-601", "redirect"),
    "cwe-601": ("CWE-601", "redirect"),
    "remote code execution": ("CWE-94", "rce"),
    "rce": ("CWE-94", "rce"),
    "code injection": ("CWE-94", "rce"),
    "cwe-94": ("CWE-94", "rce"),
    "arbitrary file overwrite": ("CWE-22", "path-traversal"),
    "path traversal": ("CWE-22", "path-traversal"),
    "directory traversal": ("CWE-22", "path-traversal"),
    "cwe-22": ("CWE-22", "path-traversal"),
    "xml external entity": ("CWE-611", "xxe"),
    "xxe": ("CWE-611", "xxe"),
    "cwe-611": ("CWE-611", "xxe"),
    "server-side request forgery": ("CWE-918", "ssrf"),
    "ssrf": ("CWE-918", "ssrf"),
    "cwe-918": ("CWE-918", "ssrf"),
    "insecure direct object reference": ("CWE-639", "authz"),
    "idor": ("CWE-639", "authz"),
    "cwe-639": ("CWE-639", "authz"),
    "cwe-284": ("CWE-284", "authz"),
    "improper authentication": ("CWE-287", "authn"),
    "cwe-287": ("CWE-287", "authn"),
    "security misconfiguration": ("CWE-16", "config"),
    "improper restriction": ("CWE-200", "disclosure"),
    "cwe-200": ("CWE-200", "disclosure"),
}

def canonicalize_cwe_type(cwe_str, type_str):
    for raw in [cwe_str, type_str]:
        if not raw:
            continue
        cleaned = re.sub(r"[^a-zA-Z0-9\s\-_]", " ", str(raw)).strip().lower()
        if cleaned in CWE_CATEGORY_MAP:
            return CWE_CATEGORY_MAP[cleaned]
        for key, val in CWE_CATEGORY_MAP.items():
            if key in cleaned:
                return val
    m = re.search(r"cwe-(\d+)", f"{cwe_str} {type_str}", re.IGNORECASE)
    if m:
        cwe_code = f"CWE-{m.group(1)}"
        return (cwe_code, "generic")
    return ("UNKNOWN", "generic")

def format_file_and_lines(repo, ref, file_path, start_line, end_line):
    clean_path = clean_file_path(file_path)
    if start_line and end_line and int(start_line) > 0:
        s_line = int(start_line)
        e_line = int(end_line)
        line_label = f"L{s_line}–L{e_line}" if s_line != e_line else f"L{s_line}"
        line_anchor = f"#L{s_line}-L{e_line}" if s_line != e_line else f"#L{s_line}"
        file_link = f"https://github.com/{repo}/blob/{ref}/{clean_path}{line_anchor}"
        markdown_link = f"[`{clean_path} ({line_label})`]({file_link})"
    elif start_line and int(start_line) > 0:
        s_line = int(start_line)
        line_label = f"L{s_line}"
        line_anchor = f"#L{s_line}"
        file_link = f"https://github.com/{repo}/blob/{ref}/{clean_path}{line_anchor}"
        markdown_link = f"[`{clean_path} ({line_label})`]({file_link})"
    else:
        file_link = f"https://github.com/{repo}/blob/{ref}/{clean_path}"
        markdown_link = f"[`{clean_path}`]({file_link})"
    return clean_path, markdown_link

def format_cwe_link(vuln_id):
    if not vuln_id:
        return "N/A"
    vuln_str = str(vuln_id).strip()
    cwe_match = re.search(r"CWE-(\d+)", vuln_str, re.IGNORECASE)
    if cwe_match:
        cwe_num = cwe_match.group(1)
        return f"[{vuln_str}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
    return vuln_str

def format_severity(severity_str):
    s = str(severity_str).strip()
    s_clean = re.sub(r"^[🔴🟠🟡🟢⚪]\s*", "", s).strip().upper()
    emoji_map = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "ℹ️"
    }
    emoji = emoji_map.get(s_clean, "🛡️")
    return f"{emoji} {s_clean}" if s_clean else s

STANDARD_LABELS = {
    "codemender": {"color": "0366d6", "description": "Detected or acted upon by CodeMender AI"},
    "severity:critical": {"color": "b60205", "description": "Critical severity security vulnerability"},
    "severity:high": {"color": "d93f0b", "description": "High severity security vulnerability"},
    "severity:medium": {"color": "fbca04", "description": "Medium severity security vulnerability"},
    "severity:low": {"color": "0e8a16", "description": "Low severity security vulnerability"},
    "severity:info": {"color": "c5def5", "description": "Informational security finding"},
    "codemender:verified": {"color": "6f42c1", "description": "Exploit verified in secure CodeMender sandbox"},
    "codemender:fix-ready": {"color": "0e8a16", "description": "Automated remediation patch available"},
    "codemender:remediation": {"color": "0e8a16", "description": "Pull Request containing CodeMender remediation patch"},
    "codemender:auto-fixed": {"color": "0075ca", "description": "Pull Request automatically patched by CodeMender AI"},
}

_ensured_labels = set()

def ensure_labels(repo, labels):
    global _ensured_labels
    for lbl in labels:
        if lbl in _ensured_labels:
            continue
        meta = STANDARD_LABELS.get(lbl)
        if meta:
            run_gh_cmd([
                "gh", "label", "create", lbl,
                "--repo", repo,
                "--color", meta["color"],
                "--description", meta["description"],
                "--force"
            ])
            _ensured_labels.add(lbl)

def get_severity_label(severity_str):
    s = str(severity_str).strip()
    s_clean = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️]\s*", "", s).strip().lower()
    if s_clean in ["critical", "high", "medium", "low", "info"]:
        return f"severity:{s_clean}"
    return "severity:medium"

def format_confidence(conf):
    if conf is None or conf == "":
        return "100%"
    c = str(conf).strip()
    if not c.endswith("%"):
        try:
            val = float(c)
            return f"{int(val)}%" if val.is_integer() else f"{val}%"
        except ValueError:
            return f"{c}%"
    return c

def parse_metadata_from_body(body):
    if not body:
        return None
    m = re.search(r"<!--\s*codemender-finding-metadata\s*\n(.*?)\n-->", body, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return None

def extract_issue_attributes(issue):
    number = issue.get("number")
    title = issue.get("title", "")
    body = issue.get("body", "")

    meta = parse_metadata_from_body(body)
    if meta:
        file_path = clean_file_path(meta.get("file", ""))
        cwe, cat = canonicalize_cwe_type(meta.get("cwe", ""), meta.get("vuln_type", ""))
        start_line = meta.get("start_line")
        end_line = meta.get("end_line") or start_line
        finding_id = meta.get("finding_id", "")
        models = meta.get("models", [])
        return {
            "number": number,
            "title": title,
            "file": file_path,
            "cwe": cwe,
            "category": cat,
            "vuln_type": meta.get("vuln_type", ""),
            "start_line": int(start_line) if start_line is not None else None,
            "end_line": int(end_line) if end_line is not None else None,
            "finding_id": finding_id,
            "models": models,
            "meta": meta
        }

    # Fallback to parsing legacy markdown issue text
    file_path = ""
    m_file = re.search(r"\|\s*\*\*Vulnerable File\*\*\s*\|\s*\[?`?([^`\]\(\)\n\r]+)", body)
    if m_file:
        file_path = m_file.group(1).strip()
        file_path = re.sub(r"\s*\([^\)]*\)", "", file_path).strip()
    if not file_path:
        m_title_file = re.search(r" in ([^\s\(\)]+\.[a-zA-Z0-9]+)", title)
        if m_title_file:
            file_path = m_title_file.group(1).strip()
    file_path = clean_file_path(file_path)

    start_line, end_line = None, None
    m_lines = re.search(r"\(L(\d+)(?:[–\-]L?(\d+))?\)", body)
    if m_lines:
        start_line = int(m_lines.group(1))
        end_line = int(m_lines.group(2)) if m_lines.group(2) else start_line

    finding_id = ""
    m_fid = re.search(r"\(([a-f0-9]{8})\)", title)
    if m_fid:
        finding_id = m_fid.group(1)

    cwe_raw = ""
    m_cwe = re.search(r"\|\s*\*\*CWE ID\*\*\s*\|\s*\[?`?([^`\]\|\n\r]+)", body)
    if m_cwe:
        cwe_raw = m_cwe.group(1).strip()

    vtype_raw = ""
    m_vtype = re.search(r"\|\s*\*\*Vulnerability Type\*\*\s*\|\s*`?([^`\|\n\r]+)", body)
    if m_vtype:
        vtype_raw = m_vtype.group(1).strip()

    cwe, cat = canonicalize_cwe_type(cwe_raw, vtype_raw)

    return {
        "number": number,
        "title": title,
        "file": file_path,
        "cwe": cwe,
        "category": cat,
        "vuln_type": vtype_raw or cat,
        "start_line": start_line,
        "end_line": end_line,
        "finding_id": finding_id,
        "models": [],
        "meta": None
    }

def compute_similarity(issue_attr, finding):
    # 1. Hard Filter: File path must match
    cand_file = issue_attr["file"]
    find_file = clean_file_path(finding.get("file", ""))
    if not cand_file or not find_file or cand_file != find_file:
        return 0.0

    # 2. Finding ID Exact Override
    if issue_attr["finding_id"] and finding.get("id"):
        if issue_attr["finding_id"].lower() == str(finding["id"]).lower():
            return 1.0

    # 3. CWE / Category Similarity (Weight: 35%)
    f_cwe, f_cat = canonicalize_cwe_type(finding.get("vuln_id", ""), finding.get("type", ""))
    i_cwe, i_cat = issue_attr["cwe"], issue_attr["category"]
    if f_cwe != "UNKNOWN" and f_cwe == i_cwe:
        type_score = 1.0
    elif f_cat == i_cat and f_cat != "generic":
        type_score = 0.85
    elif f_cwe == "UNKNOWN" or i_cwe == "UNKNOWN":
        type_score = 0.5
    else:
        type_score = 0.0

    # 4. Line Range Overlap & Proximity (Weight: 35%)
    i_s, i_e = issue_attr["start_line"], issue_attr["end_line"]
    f_s = finding.get("start_line")
    f_e = finding.get("end_line") or f_s
    f_s = int(f_s) if f_s is not None else None
    f_e = int(f_e) if f_e is not None else None

    if i_s is not None and f_s is not None:
        overlap = max(0, min(i_e or i_s, f_e or f_s) - max(i_s, f_s) + 1)
        if overlap > 0:
            loc_score = 1.0
        else:
            delta = min(abs(i_s - (f_e or f_s)), abs(f_s - (i_e or i_s)))
            loc_score = max(0.0, 1.0 - (delta / 25.0))
    else:
        # If line numbers are unspecified, rely neutrally on other signals
        loc_score = 0.6

    # 5. Lexical & Token Similarity (Weight: 30%)
    t1 = re.sub(r"\[CodeMender[^\]]*\]|\([a-f0-9]{8}\)", "", issue_attr["title"]).lower()
    t2 = str(finding.get("title", "")).lower()
    tokens1 = set(re.findall(r"\b[a-zA-Z0-9_]{3,}\b", t1))
    tokens2 = set(re.findall(r"\b[a-zA-Z0-9_]{3,}\b", t2))
    if tokens1 and tokens2:
        jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
    else:
        jaccard = 0.5
    seq_ratio = SequenceMatcher(None, t1, t2).ratio()
    text_score = max(jaccard, seq_ratio)

    total_score = (0.35 * type_score) + (0.35 * loc_score) + (0.30 * text_score)
    return total_score

def parse_findings(artifacts_dir, log_path):
    findings = []
    json_path = os.path.join(artifacts_dir, "findings.json")

    # 1. Try to load structured findings from findings.json first
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [])
                for item in items:
                    full_id = item.get("FindingID") or item.get("id") or item.get("finding_id") or ""
                    status_val = str(item.get("Status") or item.get("status") or "OPEN").strip()
                    if status_val.upper() in ("DISMISSED", "FALSE_POSITIVE", "REJECTED", "IGNORED"):
                        continue
                    if full_id:
                        short_id = str(full_id).strip()[:8]
                        findings.append({
                            "id": short_id,
                            "full_id": str(full_id).strip(),
                            "severity": str(item.get("Severity") or item.get("severity") or "HIGH").strip(),
                            "type": str(item.get("VulnType") or item.get("type") or item.get("vulnerability_type") or "Security Finding").strip(),
                            "file": str(item.get("FilePath") or item.get("file") or item.get("path") or item.get("file_path") or "unknown").strip(),
                            "title": str(item.get("Title") or item.get("title") or item.get("description") or "Vulnerability detected").strip(),
                            "confidence": str(item.get("Confidence") or item.get("confidence") or "100%").strip(),
                            "analysis": str(item.get("Analysis") or item.get("analysis") or "").strip(),
                            "snippet": str(item.get("Snippet") or item.get("snippet") or "").strip(),
                            "vuln_id": str(item.get("VulnID") or item.get("vuln_id") or item.get("cwe") or "").strip(),
                            "status": status_val,
                            "start_line": item.get("StartLine") or item.get("start_line"),
                            "end_line": item.get("EndLine") or item.get("end_line")
                        })
            if findings:
                return findings
        except Exception as e:
            print(f"Notice: findings.json parse fallback: {e}", file=sys.stderr)

    if not os.path.exists(log_path):
        return findings

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Strip ANSI escape codes
    content = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", content)

    pattern = re.compile(
        r"^([a-f0-9]{8})\s+([🔴🟠🟡🟢]?\s*[A-Z]+)\s+([A-Za-z0-9\s\/\-_]+?)\s{2,}([^\s]+?\.[a-zA-Z0-9]+)\s{2,}(.+?)\s{2,}(\d+%)",
        re.MULTILINE
    )

    for match in pattern.finditer(content):
        finding_id, severity, vuln_type, file_path, title, confidence = match.groups()
        findings.append({
            "id": finding_id.strip(),
            "full_id": finding_id.strip(),
            "severity": severity.strip(),
            "type": vuln_type.strip(),
            "file": file_path.strip(),
            "title": title.strip(),
            "confidence": confidence.strip(),
            "analysis": "",
            "snippet": "",
            "vuln_id": "",
            "status": "OPEN",
            "start_line": None,
            "end_line": None
        })

    return findings

def detect_cm_model(artifacts_dir=None):
    env_m = os.environ.get("SCAN_MODEL") or os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL")
    if env_m and env_m.strip():
        return env_m.strip()

    if not artifacts_dir:
        artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")

    if artifacts_dir and os.path.exists(artifacts_dir):
        for log_name in ["cm-find.log", "cm-verify.log", "cm-fix.log"]:
            log_p = os.path.join(artifacts_dir, log_name)
            if os.path.exists(log_p):
                try:
                    with open(log_p, "r", errors="ignore") as f:
                        text = f.read(4096)
                        m = re.search(r"default model to\s+([\w\.\-]+)", text, re.IGNORECASE)
                        if m:
                            return m.group(1).strip()
                except Exception:
                    pass

    try:
        res = subprocess.run(["cm", "find", "--help"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            m = re.search(r"--model[^\n]+\(default\s+\"?([^\s\"\)]+)\"?\)", res.stdout)
            if m:
                return m.group(1).strip()
    except Exception:
        pass

    return "gemini-3.8-flash"

def format_analysis_codeblocks(text):
    """Ensures Conceptual Exploit Payload inside Vulnerability Analysis is wrapped in a fenced codeblock."""
    if not text:
        return text

    text = re.sub(r"^(Source|Validation|Sanitization/Validation|Sink):\s*", r"**\1:** ", text, flags=re.MULTILINE)

    m = re.search(
        r"(?:###\s*|\*\*)?Conceptual Exploit Payload:?(?:\*\*)?[ \t]*\n+(.*)",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return text

    prefix = text[:m.start()]
    payload_section = m.group(1).strip()
    payload_section = re.sub(r"^\*\*\s*\n+", "", payload_section)

    if "```" in payload_section:
        return f"{prefix}**Conceptual Exploit Payload:**\n\n{payload_section}"

    # Unwrap single-backticked HTTP request lines like `GET /... HTTP/1.1`
    payload_section = re.sub(
        r"^`((?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/[^\n`]+)`$",
        r"\1",
        payload_section,
        flags=re.MULTILINE,
    )

    def wrap_http_block(match):
        block = match.group(0).strip()
        return f"\n```http\n{block}\n```\n"

    http_pattern = re.compile(
        r"^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/[^\n]*"
        r"(?:\n(?:Host|Content-Type|Authorization|Accept|Cookie|User-Agent|Connection|X-[A-Za-z0-9\-]+):[^\n]*)*"
        r"(?:\n\n\{\n.*?\n\})?",
        re.MULTILINE | re.DOTALL,
    )
    if http_pattern.search(payload_section):
        payload_section = http_pattern.sub(wrap_http_block, payload_section)
        parts = re.split(r"(```.*?```)", payload_section, flags=re.DOTALL)
        for i in range(0, len(parts), 2):
            parts[i] = re.sub(
                r"(?:^|\n)(\{\n[^{}`]+?\n\})(?=\n|$)",
                r"\n```json\n\1\n```\n",
                parts[i],
                flags=re.DOTALL,
            )
        payload_section = "".join(parts)

    if "```" not in payload_section:
        payload_section = re.sub(
            r"^`([^`\n]{10,})`$",
            r"```text\n\1\n```",
            payload_section,
            flags=re.MULTILINE,
        )

    if "```" not in payload_section:
        inline_http = re.findall(r"`((?:GET|POST|PUT|DELETE|PATCH)\s+/[^`\n]+)`", payload_section)
        if inline_http:
            joined = "\n".join(inline_http)
            payload_section = f"```http\n{joined}\n```\n\n{payload_section}"
        else:
            indented_ticks = re.findall(r"^\s+`([^`\n]+)`\s*$", payload_section, flags=re.MULTILINE)
            if indented_ticks:
                joined = "\n".join(indented_ticks)
                payload_section = f"```text\n{joined}\n```\n\n{payload_section}"
            else:
                payload_section = f"```text\n{payload_section}\n```"

    payload_section = re.sub(r"\n{3,}", "\n\n", payload_section).strip()
    return f"{prefix}**Conceptual Exploit Payload:**\n\n{payload_section}"


def build_issue_body(repo, ref, finding, current_models=None, artifacts_dir=None):
    short_id = finding["id"]
    full_id = finding.get("full_id") or short_id
    severity = format_severity(finding.get("severity", "HIGH"))
    status = str(finding.get("status", "OPEN")).strip().upper()
    vuln_type = finding.get("type", "Security Finding")
    cwe_link = format_cwe_link(finding.get("vuln_id", ""))
    confidence = format_confidence(finding.get("confidence", "100%"))

    clean_path, file_link_md = format_file_and_lines(
        repo, ref, finding.get("file", ""), finding.get("start_line"), finding.get("end_line")
    )

    models_list = [m for m in (current_models or []) if m and m != "CodeMender Default"]
    active_model = detect_cm_model(artifacts_dir)
    if active_model and active_model not in models_list:
        models_list.append(active_model)

    models_badge = ", ".join([f"`{m}`" for m in models_list]) if models_list else f"`{active_model}`"

    meta_payload = {
        "file": clean_path,
        "vuln_type": vuln_type,
        "cwe": finding.get("vuln_id", ""),
        "start_line": finding.get("start_line"),
        "end_line": finding.get("end_line"),
        "finding_id": short_id,
        "confidence": confidence,
        "models": models_list
    }

    manual_workflow_url = f"https://github.com/{repo}/actions/workflows/codemender-manual.yml"

    body_parts = [
        f"<!-- codemender-finding-metadata\n{json.dumps(meta_payload, indent=2)}\n-->\n",
        "### 🛡️ CodeMender Vulnerability Report\n",
        "| Attribute | Details |",
        "| :--- | :--- |",
        f"| **Finding ID** | `{short_id}`" + (f" (`{full_id}`)" if full_id and full_id != short_id else "") + " |",
        f"| **Severity** | **{severity}** |",
        f"| **Status** | `{status}` |",
        f"| **Vulnerability Type** | `{vuln_type}` |",
        f"| **CWE ID** | {cwe_link} |",
        f"| **Vulnerable File** | {file_link_md} |",
        f"| **Confidence** | **{confidence}** |",
        f"| **Verified by Models** | {models_badge} |"
    ]

    pr_num = os.environ.get("PR_NUMBER")
    if pr_num:
        body_parts.append(f"| **Associated Pull Request** | [#{pr_num}](https://github.com/{repo}/pull/{pr_num}) |")

    body_parts.extend(["\n", "---\n"])

    analysis = format_analysis_codeblocks(finding.get("analysis", "").strip())
    if analysis:
        body_parts.extend([
            "### 🔬 Vulnerability Analysis\n",
            f"{analysis}\n",
            "---\n"
        ])

    snippet = finding.get("snippet", "").strip()
    if snippet:
        lang = get_language_from_ext(clean_path)
        start_l = finding.get("start_line")
        end_l = finding.get("end_line")
        if start_l and end_l:
            line_str = f"line {start_l}" if str(start_l) == str(end_l) else f"lines {start_l}–{end_l}"
            snippet_header = f"// {clean_path} ({line_str})"
        elif start_l:
            snippet_header = f"// {clean_path} (line {start_l})"
        else:
            snippet_header = f"// {clean_path}"
        body_parts.extend([
            "### 📄 Vulnerable Code Snippet\n",
            f"```{lang}",
            f"{snippet_header}",
            f"{snippet}",
            "```\n",
            "---\n"
        ])

    if os.path.exists("/tmp/cm-attached-artifacts.md"):
        try:
            with open("/tmp/cm-attached-artifacts.md", "r", encoding="utf-8", errors="ignore") as af:
                art_md = af.read().strip()
            if art_md:
                body_parts.extend([
                    f"{art_md}\n",
                    "---\n"
                ])
        except Exception:
            pass

    body_parts.extend([
        "### 🚀 Actions & Remediation\n",
        f"* **[🛠️ Fix Workflow]({manual_workflow_url})** — Trigger automated AI remediation.",
        f"* **[🔬 Verify Workflow]({manual_workflow_url})** — Run exploit verification in sandbox.",
        "* **💬 ChatOps:** Comment `/cm verify`, `/cm hunt`, or `/cm fix` directly on this issue.\n",
        "---\n",
        "*Detected by CodeMender.*"
    ])

    return "\n".join(body_parts)

def fetch_all_open_issues(repo):
    res = run_cmd(
        f'gh issue list --repo "{repo}" --state open --limit 200 --json number,title,body',
        check=False
    )
    if res.returncode == 0 and res.stdout.strip():
        try:
            return json.loads(res.stdout)
        except Exception:
            pass
    return []

def sync_findings_to_github(repo, ref, findings, artifacts_dir=None):
    print(f"📥 Fetching open issues from {repo} for deduplication...")
    open_issues_raw = fetch_all_open_issues(repo)
    existing_issue_attrs = [extract_issue_attributes(iss) for iss in open_issues_raw]
    claimed_issue_numbers = set()

    for finding in findings:
        finding_id = finding["id"]
        clean_path = clean_file_path(finding["file"])
        title = finding["title"]
        # Clean up title: strip any legacy [CodeMender ...] prefix or colored emoji dots
        clean_title = re.sub(r"^\[CodeMender[^\]]*\]\s*", "", title)
        clean_title = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️🛡️]\s*", "", clean_title).strip()
        if clean_path and clean_path != "unknown" and clean_path not in clean_title:
            issue_title = f"{clean_title} in {clean_path} ({finding_id})"
        else:
            issue_title = f"{clean_title} ({finding_id})"

        best_match = None
        best_score = 0.0

        for attr in existing_issue_attrs:
            if attr["number"] in claimed_issue_numbers:
                continue
            score = compute_similarity(attr, finding)
            if score > best_score:
                best_score = score
                best_match = attr

        labels = ["codemender", get_severity_label(finding.get("severity", ""))]
        ensure_labels(repo, labels)

        MATCH_THRESHOLD = 0.70
        if best_match and best_score >= MATCH_THRESHOLD:
            issue_number = best_match["number"]
            claimed_issue_numbers.add(issue_number)
            print(f"🔄 Deduplication Match: Finding {finding_id} ({clean_path}) matched Issue #{issue_number} (score: {best_score:.2f}). Updating in-place...")

            active_model = detect_cm_model(artifacts_dir)
            existing_models = [m for m in best_match.get("models", []) if m and m != "CodeMender Default"]
            combined_models = list(set(existing_models + ([active_model] if active_model else [])))
            updated_body = build_issue_body(repo, ref, finding, current_models=combined_models, artifacts_dir=artifacts_dir)

            edit_cmd = ["gh", "issue", "edit", str(issue_number), "--repo", repo, "--title", issue_title, "--body", updated_body]
            for lbl in labels:
                edit_cmd.extend(["--add-label", lbl])
            edit_res = run_gh_cmd(edit_cmd)
            if edit_res.returncode == 0:
                print(f"✅ Successfully updated Issue #{issue_number}")
            else:
                print(f"⚠️ Failed to update Issue #{issue_number}: {edit_res.stderr.strip()}", file=sys.stderr)
        else:
            print(f"📝 Creating new GitHub Issue for finding {finding_id}: {title} in {clean_path} (labels: {labels})...")
            new_body = build_issue_body(repo, ref, finding, artifacts_dir=artifacts_dir)
            create_res = run_gh_cmd(
                ["gh", "issue", "create", "--repo", repo, "--title", issue_title, "--body", new_body, "--label", ",".join(labels)]
            )
            if create_res.returncode == 0:
                print(f"✅ Created issue: {create_res.stdout.strip()}")
            else:
                print(f"⚠️ Failed to create issue: {create_res.stderr.strip()}", file=sys.stderr)

def get_pr_diff_changes():
    base_ref = os.environ.get("BASE_REF", "main")
    subprocess.run(["git", "fetch", "origin", f"{base_ref}:refs/remotes/origin/{base_ref}"], capture_output=True)
    res = subprocess.run(
        ["git", "diff", "-U0", f"origin/{base_ref}...HEAD"],
        capture_output=True, text=True
    )
    changed_lines = {}
    current_file = None
    if res.returncode == 0 and res.stdout.strip():
        for line in res.stdout.splitlines():
            if line.startswith("+++ b/"):
                current_file = clean_file_path(line[6:].strip())
                if current_file not in changed_lines:
                    changed_lines[current_file] = set()
            elif line.startswith("@@ ") and current_file:
                m = re.search(r"\+([0-9]+)(?:,([0-9]+))?", line)
                if m:
                    start = int(m.group(1))
                    count = int(m.group(2)) if m.group(2) else 1
                    for l in range(start, start + count):
                        changed_lines[current_file].add(l)
    return changed_lines

def is_finding_in_pr_diff(f, changed_lines):
    clean_f = clean_file_path(f.get("file", ""))
    matched_file = None
    for cf in changed_lines:
        if clean_f.endswith(cf) or cf.endswith(clean_f):
            matched_file = cf
            break
    if not matched_file:
        return False
    line_set = changed_lines[matched_file]
    if not line_set:
        return True
    try:
        s_line = int(f.get("start_line") or 0)
    except (ValueError, TypeError):
        s_line = 0
    if s_line > 0:
        for l in range(max(1, s_line - 5), s_line + 6):
            if l in line_set:
                return True
        return False
    return True

def main():
    repo = os.environ.get("REPO", "")
    ref = os.environ.get("REF", "main")
    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")
    log_path = os.path.join(artifacts_dir, "cm-find.log")

    if not repo:
        print("No REPO specified. Exiting issue creation.")
        return

    print(f"🔍 Parsing findings from artifacts dir '{artifacts_dir}' for repo {repo}...")
    findings = parse_findings(artifacts_dir, log_path)
    print(f"📊 Found {len(findings)} unique vulnerability entries.")

    pr_num = os.environ.get("PR_NUMBER")
    head_b = os.environ.get("HEAD_BRANCH")
    if pr_num or (head_b and head_b not in ["main", "master"]):
        changed_lines = get_pr_diff_changes()
        if changed_lines:
            findings = [f for f in findings if is_finding_in_pr_diff(f, changed_lines)]
            print(f"🎯 Scoped to {len(findings)} findings strictly introduced in PR diff.")

    sync_findings_to_github(repo, ref, findings, artifacts_dir=artifacts_dir)

if __name__ == "__main__":
    main()
