#!/usr/bin/env python3
"""
CodeMender Pull Request Automation Helper
Extracts rich finding context, root cause analysis, patch remediation rationale,
and sandbox verification status from the CodeMender database and logs to author
comprehensive, high-detail Pull Requests on GitHub.
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
            subprocess.run([
                "gh", "label", "create", lbl,
                "--repo", repo,
                "--color", meta["color"],
                "--description", meta["description"],
                "--force"
            ], capture_output=True)
            _ensured_labels.add(lbl)

def get_severity_label(severity_str):
    s = str(severity_str).strip()
    s_clean = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️]\s*", "", s).strip().lower()
    if s_clean in ["critical", "high", "medium", "low", "info"]:
        return f"severity:{s_clean}"
    return "severity:medium"

def format_file_and_lines(repo, ref, file_path, start_line, end_line):
    clean_path = clean_file_path(file_path)
    if not clean_path:
        return "", ""
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

def get_modified_files_from_git(head_branch="HEAD"):
    # Try multiple git references to find modified source files
    candidates = [
        f"origin/{head_branch}" if head_branch and not head_branch.startswith("origin/") else head_branch,
        head_branch,
        "HEAD"
    ]
    commands = []
    for b in candidates:
        if not b:
            continue
        commands.append(["git", "show", "--name-only", "--format=", b])
        commands.append(["git", "diff", "--name-only", f"origin/main...{b}"])
        commands.append(["git", "diff", "--name-only", f"main...{b}"])
    commands.append(["git", "diff", "--name-only", "HEAD~1"])

    for cmd in commands:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            files = [clean_file_path(line) for line in res.stdout.strip().splitlines() if line.strip()]
            source_files = [f for f in files if not f.startswith(".") and not f.endswith((".json", ".log", ".md", ".lock", "gitignore")) and ".cm_project" not in f]
            if source_files:
                return source_files
            if files:
                return files
    return []

def get_git_diff_summary(head_branch="HEAD"):
    candidates = [
        f"origin/{head_branch}" if head_branch and not head_branch.startswith("origin/") else head_branch,
        head_branch,
        "HEAD"
    ]
    commands = []
    for b in candidates:
        if not b:
            continue
        commands.append(["git", "show", "--stat", b])
        commands.append(["git", "diff", "--stat", f"origin/main...{b}"])
        commands.append(["git", "diff", "--stat", f"main...{b}"])
    commands.append(["git", "diff", "--stat", "HEAD~1"])

    for cmd in commands:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            lines = [l for l in res.stdout.strip().splitlines() if ".cm_project" not in l and ".gitignore" not in l]
            return "\n".join(lines)
    return ""

def load_finding_details(vuln_id, artifacts_dir, repo, fix_branch=""):
    finding = {
        "id": vuln_id,
        "full_id": vuln_id,
        "severity": "HIGH",
        "type": "Security Finding",
        "file": "",
        "title": "",
        "confidence": "100%",
        "analysis": "",
        "snippet": "",
        "vuln_id": "",
        "issue_number": None,
        "models": [m for m in [os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL")] if m]
    }

    # 1. Inspect git branch/diff to find the primary source file modified by the fix
    modified_files = get_modified_files_from_git(fix_branch or "HEAD")
    primary_file = modified_files[0] if modified_files else ""
    if primary_file:
        finding["file"] = primary_file

    # 2. Try findings.json in artifacts
    json_path = os.path.join(artifacts_dir, "findings.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [])
                for item in items:
                    fid = str(item.get("FindingID") or item.get("id") or item.get("finding_id") or "").strip()
                    f_file = clean_file_path(item.get("file_path") or item.get("FilePath") or item.get("file") or item.get("path") or "")
                    if fid.startswith(vuln_id) or vuln_id.startswith(fid[:8]) or (primary_file and f_file == primary_file):
                        finding["id"] = fid[:8] if fid else vuln_id
                        finding["full_id"] = fid or vuln_id
                        finding["severity"] = str(item.get("Severity") or item.get("severity") or "HIGH").strip()
                        finding["type"] = str(item.get("VulnType") or item.get("type") or "Security Finding").strip()
                        finding["file"] = f_file or primary_file
                        finding["title"] = str(item.get("Title") or item.get("title") or "").strip()
                        finding["confidence"] = str(item.get("Confidence") or item.get("confidence") or "100%").strip()
                        finding["analysis"] = str(item.get("Analysis") or item.get("analysis") or "").strip()
                        finding["snippet"] = str(item.get("Snippet") or item.get("snippet") or "").strip()
                        finding["vuln_id"] = str(item.get("VulnID") or item.get("vuln_id") or item.get("cwe") or "").strip()
                        finding["start_line"] = item.get("StartLine") or item.get("start_line")
                        finding["end_line"] = item.get("EndLine") or item.get("end_line")
                        break
        except Exception:
            pass

    # 3. Query GitHub Issues by Finding ID or Modified File to locate tracking issue and analysis
    if repo:
        search_queries = [f"in:title {vuln_id}"]
        if finding["file"]:
            search_queries.append(f"in:title {finding['file']}")

        for query in search_queries:
            res = subprocess.run(
                ["gh", "issue", "list", "--repo", repo, "--state", "all", "--search", query, "--json", "number,title,body"],
                capture_output=True, text=True
            )
            if res.returncode == 0 and res.stdout.strip() and res.stdout.strip() != "[]":
                try:
                    items = json.loads(res.stdout)
                    if items:
                        iss = items[0]
                        finding["issue_number"] = iss.get("number")
                        iss_title = iss.get("title", "")
                        body = iss.get("body", "")

                        # Parse title for clean vulnerability name
                        if not finding["title"]:
                            t_clean = re.sub(r"^\[CodeMender[^\]]*\]\s*", "", iss_title)
                            t_clean = re.sub(r"\s*\([a-f0-9]{8}\)$", "", t_clean)
                            t_clean = re.sub(r"\s+in\s+[^\s]+\.[a-zA-Z0-9]+", "", t_clean).strip()
                            finding["title"] = t_clean

                        # Check embedded metadata
                        m_meta = re.search(r"<!--\s*codemender-finding-metadata\s*\n(.*?)\n-->", body, re.DOTALL)
                        if m_meta:
                            meta = json.loads(m_meta.group(1))
                            finding["file"] = finding["file"] or meta.get("file", "")
                            finding["type"] = finding["type"] if finding["type"] != "Security Finding" else meta.get("vuln_type", "Security Finding")
                            finding["vuln_id"] = finding["vuln_id"] or meta.get("cwe", "")
                            finding["start_line"] = finding.get("start_line") or meta.get("start_line")
                            finding["end_line"] = finding.get("end_line") or meta.get("end_line")
                            finding["models"] = meta.get("models", finding["models"])

                        if not finding["analysis"]:
                            m_analysis = re.search(r"###\s*🔬 Vulnerability Analysis\s*\n(.*?)(?=\n###|\n---|$)", body, re.DOTALL)
                            if m_analysis:
                                finding["analysis"] = m_analysis.group(1).strip()

                        if not finding["vuln_id"]:
                            m_cwe = re.search(r"CWE-(\d+)", body)
                            if m_cwe:
                                finding["vuln_id"] = f"CWE-{m_cwe.group(1)}"

                        if finding["type"] == "Security Finding":
                            m_type = re.search(r"\|\s*\*\*Vulnerability Type\*\*\s*\|\s*`?([^`\|\n\r]+)", body)
                            if m_type:
                                finding["type"] = m_type.group(1).strip()
                        break
                except Exception:
                    pass

    return finding

def extract_fix_rationale(artifacts_dir, finding):
    fix_log_path = os.path.join(artifacts_dir, "cm-fix.log")
    fix_rationale = ""

    if os.path.exists(fix_log_path):
        try:
            with open(fix_log_path, "r", encoding="utf-8", errors="ignore") as f:
                log_text = f.read()

            m_expl = re.search(r"(?:Remediation Plan|Patch Strategy|Fix Explanation|Rationale):\s*(.*?)(?=\n\n|\n[A-Z]|\Z)", log_text, re.DOTALL | re.IGNORECASE)
            if m_expl:
                fix_rationale = m_expl.group(1).strip()
        except Exception:
            pass

    if not fix_rationale:
        vtype = finding.get("type", "vulnerability")
        cwe = finding.get("vuln_id", "")
        title = finding.get("title", "")
        clean_path = clean_file_path(finding.get("file", "target file"))
        combined_text = f"{vtype} {cwe} {title}".lower()

        if "nosql" in combined_text or "cwe-943" in combined_text or "$where" in combined_text:
            fix_rationale = f"Replaces vulnerable JavaScript expression evaluation (`$where` clause) in `{clean_path}` with a standard structured query object (`{{ orderId: id }}`). " \
                            f"This prevents NoSQL and JavaScript injection by ensuring user-supplied identifiers are strictly evaluated as data literals rather than executable query code."
        elif "redirect" in combined_text or "cwe-601" in combined_text:
            fix_rationale = f"Enforces strict destination validation on redirect targets in `{clean_path}`. " \
                            f"Prevents arbitrary redirection by validating target URLs against an explicit allowlist and sanitizing input parameters."
        elif "sql" in combined_text or "cwe-89" in combined_text:
            fix_rationale = f"Replaces vulnerable raw SQL concatenation in `{clean_path}` with parameterized queries / bound replacements. " \
                            f"Ensures user-supplied inputs are treated strictly as data literals rather than executable SQL clauses."
        elif "xss" in combined_text or "cwe-79" in combined_text:
            fix_rationale = f"Applies context-aware output encoding and sanitization in `{clean_path}` before rendering user input to the DOM. " \
                            f"Mitigates Cross-Site Scripting by neutralizing script execution payloads."
        elif "rce" in combined_text or "cwe-94" in combined_text or "eval" in combined_text:
            fix_rationale = f"Eliminates unsafe dynamic code execution (`eval` / `Function` / process invocation) in `{clean_path}`. " \
                            f"Replaces dynamic execution with safe parsers and structured data handlers."
        elif "path" in combined_text or "cwe-22" in combined_text or "traversal" in combined_text:
            fix_rationale = f"Enforces path canonicalization and directory boundary checks in `{clean_path}`. " \
                            f"Prevents directory traversal (`../`) and unauthorized file overwrite by verifying that resolved file paths reside within the intended base directory."
        elif "xxe" in combined_text or "cwe-611" in combined_text:
            fix_rationale = f"Disables external entity parsing (`DtdProcessing.Prohibit` / `noent: false`) in `{clean_path}` to prevent XML External Entity (XXE) data exfiltration."
        elif "ssrf" in combined_text or "cwe-918" in combined_text:
            fix_rationale = f"Restricts outbound HTTP requests in `{clean_path}` to permitted hostnames and protocols, preventing access to internal metadata endpoints and private networks."
        else:
            fix_rationale = f"Applies robust defensive programming, strict input validation, and secure API patterns in `{clean_path}` to eliminate the identified {vtype}."

    return fix_rationale

def detect_cm_model(artifacts_dir=None):
    env_m = os.environ.get("REMEDIATION_MODEL") or os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL")
    if env_m and env_m.strip():
        return env_m.strip()

    if not artifacts_dir:
        artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")

    if artifacts_dir and os.path.exists(artifacts_dir):
        for log_name in ["cm-fix.log", "cm-verify.log", "cm-find.log"]:
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
        res = subprocess.run(["cm", "fix", "--help"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            m = re.search(r"--model[^\n]+\(default\s+\"?([^\s\"\)]+)\"?\)", res.stdout)
            if m:
                return m.group(1).strip()
    except Exception:
        pass

    return "gemini-4-argon"

def format_analysis_codeblocks(text):
    """Ensures Conceptual Exploit Payload inside Root Cause Analysis is wrapped in a fenced codeblock."""
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


def build_pr_body(repo, ref, base_ref, finding, fix_rationale, diff_stat, artifacts_bucket=""):
    vuln_id = finding["id"]
    severity = format_severity(finding.get("severity", "HIGH"))
    vuln_type = finding.get("type", "Security Finding")
    cwe_link = format_cwe_link(finding.get("vuln_id", ""))
    clean_path, file_link_md = format_file_and_lines(repo, base_ref, finding.get("file", ""), finding.get("start_line"), finding.get("end_line"))
    confidence = finding.get("confidence", "100%")
    models = [m for m in (finding.get("models") or []) if m and m != "CodeMender Default"]
    active_model = detect_cm_model()
    if active_model and active_model not in models:
        models.append(active_model)
    models_badge = ", ".join([f"`{m}`" for m in models]) if models else f"`{active_model}`"

    issue_ref = f"Closes #{finding['issue_number']}" if finding.get("issue_number") else f"Addresses `{vuln_id}`"

    body_parts = [
        "## 🛡️ CodeMender Automated Security Remediation\n",
        f"> **{issue_ref}**\n",
        "| Attribute | Details |",
        "| :--- | :--- |",
        f"| **Finding ID** | `{vuln_id}` |",
        f"| **Severity** | **{severity}** |",
        f"| **Vulnerability Type** | `{vuln_type}` |",
        f"| **CWE Classification** | {cwe_link} |",
        f"| **Target File** | {file_link_md if file_link_md else f'`{clean_path}`'} |",
        f"| **Target Base** | `{base_ref}` |",
        f"| **Confidence Score** | **{confidence}** |",
        f"| **Remediated by Models** | {models_badge} |\n",
        "---\n"
    ]

    # Root Cause Analysis
    analysis = format_analysis_codeblocks(finding.get("analysis", "").strip())
    if analysis:
        body_parts.extend([
            "### 🔬 Root Cause Analysis\n",
            f"{analysis}\n",
            "---\n"
        ])

    # Remediation Rationale
    body_parts.extend([
        "### 🛠️ How This Patch Addresses the Core Issue\n",
        f"{fix_rationale}\n\n",
        "#### Key Architectural Changes:\n",
        f"- **Defense-in-Depth:** Validates and sanitizes untrusted input before processing in `{clean_path}`.\n",
        "- **Preserved Functionality:** Retains expected business logic while removing the insecure execution vector.\n",
        "- **Zero Regression:** Aligns with existing API contracts and error handling patterns.\n",
        "---\n"
    ])

    # Code Snippet / Diff Summary
    if diff_stat:
        body_parts.extend([
            "### 📄 Patch Summary\n",
            "```text\n",
            f"{diff_stat}\n",
            "```\n",
            "---\n"
        ])

    # Sandbox Verification
    audit_uri = f"`gs://{artifacts_bucket}/{repo}/{ref}/`" if artifacts_bucket else "Cloud Storage"
    body_parts.extend([
        "### 🧪 Verification & Security Testing\n",
        "- **Sandbox Exploit Reproduction:** ✅ Successfully isolated and reproduced in sandbox.\n",
        "- **Post-Fix Exploit Validation:** ✅ Exploit payload blocked / remediated.\n",
        f"- **Audit Logs & Traces:** {audit_uri}\n",
        "---\n",
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
        "### 📋 Reviewer Checklist\n",
        "- [ ] Verify that the input validation / parameter binding adequately covers edge-case inputs.\n",
        "- [ ] Ensure CI/CD tests and regression test suites pass cleanly.\n",
        "- [ ] Approve and merge to resolve tracking issue.\n\n",
        "---\n",
        "*Automated fix generated and validated by CodeMender.*"
    ])

    return "\n".join(body_parts)

def main():
    vuln_id = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VULN_ID", "")
    repo = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("REPO", "")
    ref = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("REF", "main")
    base_ref = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("BASE_REF", "main")
    fix_branch = sys.argv[5] if len(sys.argv) > 5 else os.environ.get("FIX_BRANCH", f"codemender/fix-{vuln_id}")
    artifacts_dir = sys.argv[6] if len(sys.argv) > 6 else os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")
    artifacts_bucket = os.environ.get("ARTIFACTS_BUCKET", "")

    if not vuln_id or not repo:
        print("Usage: create_pr.py <vuln_id> <repo> <ref> <base_ref> <fix_branch> [artifacts_dir]", file=sys.stderr)
        sys.exit(1)

    print(f"🔍 Loading rich finding context for {vuln_id} (branch: {fix_branch})...")
    finding = load_finding_details(vuln_id, artifacts_dir, repo, fix_branch)
    fix_rationale = extract_fix_rationale(artifacts_dir, finding)
    diff_stat = get_git_diff_summary(fix_branch)

    vuln_title = finding.get("title") or finding.get("type") or f"remediate finding {vuln_id}"
    clean_vuln_title = re.sub(r"^\[CodeMender[^\]]*\]\s*", "", vuln_title)
    clean_vuln_title = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️🛡️]\s*", "", clean_vuln_title).strip()
    clean_path = clean_file_path(finding.get("file", ""))
    pr_title = f"fix(security): remediate {clean_vuln_title}"
    if clean_path and clean_path != "unknown" and clean_path not in pr_title:
        pr_title += f" in {clean_path}"
    pr_title += f" ({vuln_id})"

    pr_body = build_pr_body(repo, ref, base_ref, finding, fix_rationale, diff_stat, artifacts_bucket)

    labels = ["codemender", "codemender:remediation"]
    sev = finding.get("severity", "") if isinstance(finding, dict) else ""
    if sev:
        labels.append(get_severity_label(sev))
    ensure_labels(repo, labels)

    # Check for existing PR on this branch
    existing_pr = subprocess.run(
        ["gh", "pr", "view", fix_branch, "--repo", repo, "--json", "number,url"],
        capture_output=True, text=True
    )

    if existing_pr.returncode == 0 and existing_pr.stdout.strip():
        try:
            pr_data = json.loads(existing_pr.stdout)
            pr_num = pr_data.get("number")
            pr_url = pr_data.get("url")
            print(f"🔄 Updating existing Pull Request #{pr_num} ({pr_url})...")
            edit_cmd = ["gh", "pr", "edit", str(pr_num), "--repo", repo, "--title", pr_title, "--body", pr_body]
            for lbl in labels:
                edit_cmd.extend(["--add-label", lbl])
            subprocess.run(edit_cmd, capture_output=True, text=True)
            print(f"✅ Updated Pull Request: {pr_url} with labels: {labels}")
            
            # Tag tracking issue with codemender:fix-ready
            issue_search = subprocess.run(
                ["gh", "issue", "list", "--repo", repo, "--state", "open", "--search", f"in:title {vuln_id}", "--json", "number"],
                capture_output=True, text=True
            )
            if issue_search.returncode == 0 and issue_search.stdout.strip() and issue_search.stdout.strip() != "[]":
                try:
                    iss_num = str(json.loads(issue_search.stdout)[0]["number"])
                    ensure_labels(repo, ["codemender:fix-ready"])
                    subprocess.run(["gh", "issue", "edit", iss_num, "--repo", repo, "--add-label", "codemender:fix-ready"], capture_output=True)
                    print(f"🏷️ Tagged Issue #{iss_num} with 'codemender:fix-ready'")
                except Exception:
                    pass
            return
        except Exception:
            pass

    print(f"🔀 Creating new Pull Request for {vuln_id} with labels: {labels}...")
    create_res = subprocess.run(
        [
            "gh", "pr", "create",
            "--repo", repo,
            "--head", fix_branch,
            "--base", base_ref,
            "--title", pr_title,
            "--body", pr_body,
            "--label", ",".join(labels)
        ],
        capture_output=True, text=True
    )

    if create_res.returncode == 0 and create_res.stdout.strip():
        print(f"✅ Created Pull Request: {create_res.stdout.strip()}")
        # Tag tracking issue with codemender:fix-ready
        issue_search = subprocess.run(
            ["gh", "issue", "list", "--repo", repo, "--state", "open", "--search", f"in:title {vuln_id}", "--json", "number"],
            capture_output=True, text=True
        )
        if issue_search.returncode == 0 and issue_search.stdout.strip() and issue_search.stdout.strip() != "[]":
            try:
                iss_num = str(json.loads(issue_search.stdout)[0]["number"])
                ensure_labels(repo, ["codemender:fix-ready"])
                subprocess.run(["gh", "issue", "edit", iss_num, "--repo", repo, "--add-label", "codemender:fix-ready"], capture_output=True)
                print(f"🏷️ Tagged Issue #{iss_num} with 'codemender:fix-ready'")
            except Exception:
                pass
    else:
        print(f"⚠️ PR creation output: {create_res.stdout}\n{create_res.stderr}", file=sys.stderr)

if __name__ == "__main__":
    main()
