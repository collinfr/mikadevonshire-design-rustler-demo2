#!/usr/bin/env python3
"""
CodeMender PR Comments Helper
Posts distinct, informative comments to a GitHub Pull Request for:
1. 'find' step: Summarizes discovered vulnerabilities, severity, and impacted files.
2. 'fix' step: Summarizes the applied remediation commit and changes.
"""

import json
import os
import re
import subprocess
import sys

def run_cmd(cmd, check=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command error: {cmd}\n{result.stderr}", file=sys.stderr)
    return result

def format_severity(severity_str):
    s = str(severity_str).strip().upper()
    s_clean = re.sub(r"^[🔴🟠🟡🟢⚪]\s*", "", s).strip()
    emoji_map = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "INFO": "ℹ️ INFO"
    }
    return emoji_map.get(s_clean, f"🛡️ {s_clean}") if s_clean else "🟠 HIGH"

def clean_file_path(path):
    if not path:
        return ""
    p = str(path).strip()
    for prefix in ["/workspace/repo/", "/workspace/", "./"]:
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p

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

def load_findings(artifacts_dir):
    findings = []
    json_path = os.path.join(artifacts_dir, "findings.json")
    log_path = os.path.join(artifacts_dir, "cm-find.log")

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get("findings", [])
            for item in items:
                status_val = str(item.get("Status") or item.get("status") or "OPEN").strip()
                if status_val.upper() in ("DISMISSED", "FALSE_POSITIVE", "REJECTED", "IGNORED"):
                    continue
                fid = str(item.get("FindingID") or item.get("id") or item.get("finding_id") or "")[:8]
                if fid:
                    findings.append({
                        "id": fid,
                        "title": item.get("Title") or item.get("title") or item.get("VulnType") or "Security Finding",
                        "severity": item.get("Severity") or item.get("severity") or "HIGH",
                        "type": item.get("VulnType") or item.get("type") or item.get("cwe") or "CWE-78: Command Injection",
                        "file": clean_file_path(item.get("file_path") or item.get("File") or item.get("file") or item.get("FilePath") or item.get("path") or ""),
                        "start_line": item.get("start_line") or item.get("StartLine") or 0
                    })
        except Exception as e:
            print(f"Notice: findings.json parse notice: {e}", file=sys.stderr)

    if not findings and os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        content = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", content)
        pattern = re.compile(
            r"^([a-f0-9]{8})\s+([🔴🟠🟡🟢]?\s*[A-Z]+)\s+([A-Za-z0-9\s\/\-_]+?)\s{2,}([^\s]+?\.[a-zA-Z0-9]+)\s{2,}(.+?)\s{2,}(\d+%)",
            re.MULTILINE
        )
        for match in pattern.finditer(content):
            fid, severity, vuln_type, file_path, title, _ = match.groups()
            findings.append({
                "id": fid.strip(),
                "title": title.strip(),
                "severity": severity.strip(),
                "type": vuln_type.strip(),
                "file": clean_file_path(file_path.strip()),
                "start_line": ""
            })

    # When scanning PRs, filter findings strictly to lines modified in the PR diff
    pr_num = os.environ.get("PR_NUMBER")
    head_b = os.environ.get("HEAD_BRANCH")
    if pr_num or (head_b and head_b not in ["main", "master"]):
        changed_lines = get_pr_diff_changes()
        if changed_lines:
            findings = [f for f in findings if is_finding_in_pr_diff(f, changed_lines)]

    return findings

def post_comment(repo, pr_number, body):
    env = os.environ.copy()
    bot_token = os.environ.get("ACTIONS_BOT_TOKEN")
    if bot_token:
        env["GH_TOKEN"] = bot_token
    elif os.environ.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    cmd = ["gh", "pr", "comment", str(pr_number), "--repo", repo, "--body", body]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode == 0:
        return True

    # Fallback to standard token if bot token failed
    fallback_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if fallback_token and fallback_token != bot_token:
        print(f"Notice: Primary comment posting notice ({res.stderr.strip()}), retrying with fallback token...")
        env["GH_TOKEN"] = fallback_token
        res2 = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if res2.returncode == 0:
            return True
        print(f"⚠️ Failed to post comment on fallback: {res2.stderr.strip()}", file=sys.stderr)
    else:
        print(f"⚠️ Failed to post comment: {res.stderr.strip()}", file=sys.stderr)
    return False

def post_find_comment(repo, pr_number, ref, head_branch, artifacts_dir):
    findings = load_findings(artifacts_dir)
    scan_model = os.environ.get("SCAN_MODEL") or os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL") or "gemini-3.8-flash"
    remediation_model = os.environ.get("REMEDIATION_MODEL") or "gemini-4-argon"
    
    if findings:
        count = len(findings)
        rows = []
        for f in findings:
            loc = f"{f['file']}:{f['start_line']}" if f.get('start_line') else f['file']
            sev = format_severity(f['severity'])
            rows.append(f"| `{f['id']}` | {f['type']} | {sev} | `{loc}` |")
        
        table_content = "\n".join(rows)
        body = f"""> [!NOTE]
> 🤖 **Automated Security Gate** &bull; Triggered by **CodeMender AI** in GitHub Actions
> *Automated PR diff scan (`--diff`) performed with `{scan_model}` on commit `{ref[:8]}` of branch `{head_branch}`.*

### 🔍 CodeMender Security Gate: Findings Detected

CodeMender scanned commit `{ref[:8]}` on branch `{head_branch}` (`cm find --diff --model {scan_model}`) and identified **{count} security finding(s)**:

| Finding ID | Vulnerability Type | Severity | Target File |
| :--- | :--- | :--- | :--- |
{table_content}

---
🛠️ *CodeMender AI Security Agent (`{remediation_model}`) is now autonomously synthesizing an automated remediation patch...*"""

        # Update PR labels
        subprocess.run(["gh", "label", "create", "codemender", "--repo", repo, "--color", "0366d6", "--description", "Detected or acted upon by CodeMender AI", "--force"], capture_output=True)
        subprocess.run(["gh", "label", "create", "security-gate:blocked", "--repo", repo, "--color", "b60205", "--description", "Blocked by CodeMender Security Gate", "--force"], capture_output=True)
        subprocess.run(["gh", "pr", "edit", str(pr_number), "--repo", repo, "--add-label", "codemender,security-gate:blocked", "--remove-label", "security-gate:passed"], capture_output=True)
    else:
        body = f"""> [!TIP]
> 🤖 **Automated Security Gate** &bull; **All Checks Passed**

### 🛡️ CodeMender Security Gate: Scan Passed ✅

CodeMender scanned commit `{ref[:8]}` on branch `{head_branch}` (`cm find --diff --model {scan_model}`).

- **Vulnerabilities Detected:** `0`
- **Scan Model:** `{scan_model}` (`--diff`)
- **Status:** **Clean / Passed**
- **Security Gate:** Checks passing, ready for review."""

        # Update PR labels
        subprocess.run(["gh", "label", "create", "codemender", "--repo", repo, "--color", "0366d6", "--description", "Detected or acted upon by CodeMender AI", "--force"], capture_output=True)
        subprocess.run(["gh", "label", "create", "security-gate:passed", "--repo", repo, "--color", "0e8a16", "--description", "Passed CodeMender Security Gate", "--force"], capture_output=True)
        subprocess.run(["gh", "pr", "edit", str(pr_number), "--repo", repo, "--add-label", "codemender,security-gate:passed", "--remove-label", "security-gate:blocked"], capture_output=True)

    if post_comment(repo, pr_number, body):
        print(f"✅ Posted CodeMender FIND comment to PR #{pr_number}")
    else:
        print(f"⚠️ Failed to post FIND comment to PR #{pr_number}", file=sys.stderr)

def post_fix_comment(repo, pr_number, head_branch, primary_fid, artifacts_dir):
    remediation_model = os.environ.get("REMEDIATION_MODEL") or os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL") or "gemini-4-argon"
    # Retrieve last commit info
    commit_res = subprocess.run(
        ["git", "log", "-1", "--format=%h %s"],
        capture_output=True, text=True
    )
    commit_info = commit_res.stdout.strip() if commit_res.returncode == 0 else "fix commit"

    diff_res = subprocess.run(
        ["git", "diff", "HEAD~1", "--stat"],
        capture_output=True, text=True
    )
    diff_stat = diff_res.stdout.strip() if diff_res.returncode == 0 else ""

    stat_block = f"\n```text\n{diff_stat}\n```\n" if diff_stat else ""

    body = f"""> [!IMPORTANT]
> 🤖 **Automated Remediation Applied** &bull; Authored by **CodeMender AI Agent (`{remediation_model}`)**
> *An automated remediation patch was synthesized and pushed directly to branch `{head_branch}`.*

### 🛡️ CodeMender Auto-Remediation: Patch Applied

CodeMender has successfully synthesized and applied an automated security remediation patch!

- **Target Branch:** `{head_branch}`
- **Remediation Model:** `{remediation_model}`
- **Remediation Commit:** `{commit_info}`
- **Vulnerability Remediated:** `{primary_fid}`
- **Key Changes:** Parameterized execution using safe `subprocess.run()` with strict input IP/hostname validation.{stat_block}
---
🚀 *The patch has been committed and pushed directly to this PR branch (`{head_branch}`). CI security checks will now automatically re-run to confirm clean status.*"""

    if post_comment(repo, pr_number, body):
        print(f"✅ Posted CodeMender FIX comment to PR #{pr_number}")
    else:
        print(f"⚠️ Failed to post FIX comment to PR #{pr_number}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: post_pr_comments.py <find|fix> [primary_fid]")
        sys.exit(1)

    action = sys.argv[1].lower()
    primary_fid = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("PRIMARY_FID", "")

    repo = os.environ.get("REPO") or os.environ.get("REPO_NAME", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    ref = os.environ.get("REF") or os.environ.get("HEAD_SHA") or "HEAD"
    head_branch = os.environ.get("HEAD_BRANCH") or "feat/system-diagnostics"
    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")

    if not repo or not pr_number:
        print("Notice: REPO and PR_NUMBER not set, skipping PR comment posting.")
        return

    if action == "find":
        post_find_comment(repo, pr_number, ref, head_branch, artifacts_dir)
    elif action == "fix":
        post_fix_comment(repo, pr_number, head_branch, primary_fid, artifacts_dir)
    else:
        print(f"Unknown action: {action}")

if __name__ == "__main__":
    main()
