#!/usr/bin/env python3
"""
Finding Import and Resolution Helper for CodeMender Worker
Imports findings directly from GitHub Issues into a clean CodeMender environment,
leveraging embedded metadata blocks and multi-signal matching to ensure stateless
execution with GitHub as the single source of truth.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from difflib import SequenceMatcher

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

def get_current_findings(artifacts_dir="/workspace/artifacts"):
    json_path = os.path.join(artifacts_dir, "findings.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [])
                if items:
                    return items
        except Exception:
            pass

    res = subprocess.run(["cm", "report", "-f", "json"], capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip():
        try:
            items = json.loads(res.stdout)
            if isinstance(items, list) and items:
                return items
        except Exception:
            pass

    return []

def fetch_issue_data(repo, issue_number=None, vuln_id=None):
    if not repo:
        return None

    if issue_number:
        res = subprocess.run(
            ["gh", "issue", "view", str(issue_number), "--repo", repo, "--json", "number,title,body"],
            capture_output=True, text=True
        )
        if res.returncode == 0 and res.stdout.strip():
            try:
                return json.loads(res.stdout)
            except Exception:
                pass

    if vuln_id:
        res = subprocess.run(
            ["gh", "issue", "list", "--repo", repo, "--state", "all", "--search", f"in:title {vuln_id}", "--json", "number,title,body"],
            capture_output=True, text=True
        )
        if res.returncode == 0 and res.stdout.strip() and res.stdout.strip() != "[]":
            try:
                items = json.loads(res.stdout)
                if items:
                    return items[0]
            except Exception:
                pass

    return None

def parse_finding_from_issue(issue_data):
    if not issue_data:
        return None

    title = issue_data.get("title", "")
    body = issue_data.get("body", "")

    # Check for embedded JSON metadata first
    m_meta = re.search(r"<!--\s*codemender-finding-metadata\s*\n(.*?)\n-->", body, re.DOTALL)
    if m_meta:
        try:
            meta = json.loads(m_meta.group(1))
            file_path = clean_file_path(meta.get("file", ""))
            start_line = meta.get("start_line") or 1
            vuln_type = meta.get("vuln_type", "Security Finding")
            clean_title = re.sub(r"^\[CodeMender[^\]]*\]\s*", "", title)
            clean_title = re.sub(r"\s*\([a-f0-9]{8}\)$", "", clean_title).strip()

            analysis = ""
            m_analysis = re.search(r"###\s*🔬 Vulnerability Analysis\s*\n(.*?)(?=\n---|$)", body, re.DOTALL)
            if m_analysis:
                analysis = m_analysis.group(1).strip()

            return {
                "file_path": file_path,
                "line": int(start_line),
                "end_line": int(meta.get("end_line") or start_line),
                "title": clean_title or f"{vuln_type} in {file_path}",
                "message": analysis or f"{clean_title} detected in {file_path}.",
                "severity": meta.get("severity", "HIGH"),
                "vuln_type": vuln_type,
                "cwe": meta.get("cwe", ""),
                "confidence": meta.get("confidence", "")
            }
        except Exception:
            pass

    # Fallback to parsing markdown fields
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

    if not file_path:
        return None

    line = 1
    m_line = re.search(r"\(L(\d+)", body)
    if m_line:
        line = int(m_line.group(1))

    severity = "HIGH"
    m_sev = re.search(r"\|\s*\*\*Severity\*\*\s*\|\s*[\*🔴🟠🟡🟢⚪\s]*([A-Z]+)", body)
    if m_sev:
        severity = m_sev.group(1).strip().upper()
    else:
        m_title_sev = re.search(r"\[CodeMender\s+[🔴🟠🟡🟢⚪]?\s*([A-Z]+)\]", title)
        if m_title_sev:
            severity = m_title_sev.group(1).strip().upper()

    vuln_type = "Security Finding"
    m_vtype = re.search(r"\|\s*\*\*Vulnerability Type\*\*\s*\|\s*`?([^`\|\n\r]+)", body)
    if m_vtype:
        vuln_type = m_vtype.group(1).strip()

    clean_title = re.sub(r"^\[CodeMender[^\]]*\]\s*", "", title)
    clean_title = re.sub(r"\s*\([a-f0-9]{8}\)$", "", clean_title)
    clean_title = re.sub(r"\s+in\s+[^\s]+\.[a-zA-Z0-9]+", "", clean_title).strip()
    if not clean_title:
        clean_title = f"{vuln_type} in {file_path}"

    message = ""
    m_analysis = re.search(r"###\s*🔬 Vulnerability Analysis\s*\n(.*?)(?=\n---|$)", body, re.DOTALL)
    if m_analysis:
        message = m_analysis.group(1).strip()
    if not message:
        message = f"{clean_title} detected in {file_path}."

    return {
        "file_path": file_path,
        "line": line,
        "end_line": line,
        "title": clean_title,
        "message": message,
        "severity": severity,
        "vuln_type": vuln_type,
        "cwe": "",
        "confidence": ""
    }


def extract_original_scan_artifacts(repo, vuln_id, issue_number=None, finding_dict=None, artifacts_dir="/workspace/artifacts"):
    """
    Looks up the original finding entry and SARIF 2.1.0 record from `codemender/artifacts`
    (or synthesizes a per-issue SARIF 2.1.0 file) and writes `issue-finding.json` and `issue-sarif.json`
    into `artifacts_dir` so every issue verification/fix bundle includes complete SARIF details.
    """
    os.makedirs(artifacts_dir, exist_ok=True)
    matched_finding = None
    matched_sarif_res = None
    matched_sarif_rule = None

    if repo:
        tmp = tempfile.mkdtemp(prefix="cm-orig-scan-")
        try:
            res = subprocess.run(
                ["git", "clone", "--depth=1", "--branch", "codemender/artifacts", f"https://github.com/{repo}.git", tmp],
                capture_output=True, text=True
            )
            if res.returncode == 0 and os.path.isdir(os.path.join(tmp, "find")):
                all_findings = []
                all_sarif = []
                for root, _, files in os.walk(os.path.join(tmp, "find")):
                    if "findings.json" in files:
                        try:
                            data = json.load(open(os.path.join(root, "findings.json"), "r", encoding="utf-8"))
                            items = data if isinstance(data, list) else data.get("findings", [])
                            for it in items:
                                all_findings.append(it)
                        except Exception:
                            pass
                    if "codemender.sarif" in files:
                        try:
                            sdata = json.load(open(os.path.join(root, "codemender.sarif"), "r", encoding="utf-8"))
                            for run in sdata.get("runs", []):
                                rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
                                for sres in run.get("results", []):
                                    all_sarif.append((sres, rules.get(sres.get("ruleId"))))
                        except Exception:
                            pass

                for it in all_findings:
                    fid = str(it.get("finding_id") or it.get("FindingID") or it.get("id") or "")
                    if vuln_id and fid.startswith(vuln_id):
                        matched_finding = it
                        break

                target_file = clean_file_path(
                    (matched_finding or {}).get("file_path") or (finding_dict or {}).get("file_path") or ""
                )
                for sres, srule in all_sarif:
                    locs = sres.get("locations", [])
                    uri = clean_file_path(locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")) if locs else ""
                    if target_file and (uri == target_file or target_file.endswith(uri) or uri.endswith(target_file)):
                        matched_sarif_res = sres
                        matched_sarif_rule = srule
                        break
        except Exception:
            pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    if matched_finding:
        with open(os.path.join(artifacts_dir, "issue-finding.json"), "w", encoding="utf-8") as f:
            json.dump(matched_finding, f, indent=2)
        if finding_dict:
            if matched_finding.get("analysis"):
                finding_dict["message"] = matched_finding["analysis"]
            if matched_finding.get("start_line"):
                finding_dict["line"] = int(matched_finding["start_line"])
            if matched_finding.get("severity"):
                finding_dict["severity"] = matched_finding["severity"]
            if matched_finding.get("vuln_type"):
                finding_dict["vuln_type"] = matched_finding["vuln_type"]

    # Build a standalone per-issue SARIF 2.1.0 file (`issue-sarif.json`)
    if not matched_sarif_res and finding_dict:
        rule_id = finding_dict.get("vuln_type") or "SECURITY_FINDING"
        matched_sarif_rule = {
            "id": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"security-severity": "7.5"}
        }
        matched_sarif_res = {
            "ruleId": rule_id,
            "level": "error",
            "message": {
                "text": f"{finding_dict.get('title', '')}\n\n{finding_dict.get('message', '')}".strip(),
                "markdown": f"**{finding_dict.get('title', '')}**\n\n{finding_dict.get('message', '')}".strip()
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding_dict.get("file_path", ""),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": int(finding_dict.get("line") or 1),
                            "endLine": int(finding_dict.get("end_line") or finding_dict.get("line") or 1)
                        }
                    }
                }
            ],
            "properties": {"security-severity": "7.5"}
        }

    if matched_sarif_res:
        props = dict(matched_sarif_res.get("properties") or {})
        props["finding_id"] = (matched_finding or {}).get("finding_id") or vuln_id
        props["short_finding_id"] = vuln_id
        if issue_number:
            props["github_issue_number"] = int(issue_number)
        if matched_finding:
            for k in ("severity", "confidence", "vuln_id", "vuln_type", "status", "session_id", "fingerprint"):
                if matched_finding.get(k) is not None:
                    props[k] = matched_finding[k]
        matched_sarif_res["properties"] = props

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeMender",
                            "version": "1.0.0",
                            "rules": [matched_sarif_rule] if matched_sarif_rule else []
                        }
                    },
                    "results": [matched_sarif_res]
                }
            ]
        }
        sarif_path = os.path.join(artifacts_dir, "issue-sarif.json")
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)
        cm_sarif_path = os.path.join(artifacts_dir, "codemender.sarif")
        if not os.path.exists(cm_sarif_path):
            with open(cm_sarif_path, "w", encoding="utf-8") as f:
                json.dump(sarif_doc, f, indent=2)


def import_finding_to_codemender(finding_dict, project_dir="."):
    import_payload = {
        "file_path": finding_dict["file_path"],
        "line": int(finding_dict.get("line") or 1),
        "title": finding_dict["title"],
        "message": finding_dict["message"],
        "severity": finding_dict.get("severity", "HIGH"),
        "vuln_type": finding_dict.get("vuln_type", "Security Finding"),
    }
    temp_json = "/tmp/cm-import-finding.json"
    with open(temp_json, "w", encoding="utf-8") as f:
        json.dump([import_payload], f, indent=2)

    cmd = ["cm", "report", "import", "-f", temp_json]
    if project_dir and os.path.isdir(project_dir):
        cmd.extend(["-p", project_dir])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"⚠️ Warning: cm report import returned code {res.returncode}: {res.stderr.strip()}", file=sys.stderr)
        return False
    return True

def resolve_and_import(vuln_id, issue_number=None, repo=None, project_dir=".", artifacts_dir="/workspace/artifacts"):
    if not vuln_id or vuln_id.lower() == "none":
        return vuln_id

    vuln_id = vuln_id.strip()

    # 1. Fetch issue from GitHub and original scan SARIF/finding details
    print(f"🔍 Fetching finding context from GitHub Issue (ID: {vuln_id}, Issue: #{issue_number})...", file=sys.stderr)
    issue_data = fetch_issue_data(repo, issue_number, vuln_id)
    finding_dict = parse_finding_from_issue(issue_data) if issue_data else None
    actual_issue_num = issue_data.get("number") if issue_data else issue_number

    extract_original_scan_artifacts(
        repo=repo,
        vuln_id=vuln_id,
        issue_number=actual_issue_num,
        finding_dict=finding_dict,
        artifacts_dir=artifacts_dir,
    )

    # 2. Check if finding already exists in current workspace state
    findings = get_current_findings(artifacts_dir)
    for f in findings:
        fid = str(f.get("FindingID") or f.get("finding_id") or f.get("id") or "").strip()
        if fid.startswith(vuln_id) or vuln_id.startswith(fid[:8]):
            return fid[:8]

    if not finding_dict:
        print(f"⚠️ Failed to parse finding attributes from GitHub Issue #{actual_issue_num}", file=sys.stderr)
        return vuln_id

    print(f"📥 Importing finding from GitHub into CodeMender: {finding_dict['file_path']} ({finding_dict['title']})...", file=sys.stderr)
    success = import_finding_to_codemender(finding_dict, project_dir)
    if not success:
        return vuln_id

    # 3. Retrieve the newly assigned finding ID
    current_findings = get_current_findings(artifacts_dir)
    target_file = finding_dict["file_path"]
    for f in current_findings:
        f_path = clean_file_path(f.get("file_path") or f.get("FilePath") or f.get("file") or f.get("path") or "")
        if f_path == target_file or target_file in f_path:
            fid = str(f.get("finding_id") or f.get("FindingID") or f.get("id") or "").strip()[:8]
            print(f"✅ Successfully imported finding as ID '{fid}'", file=sys.stderr)
            return fid

    if current_findings:
        fid = str(current_findings[-1].get("finding_id") or current_findings[-1].get("FindingID") or current_findings[-1].get("id") or "").strip()[:8]
        return fid

    return vuln_id

def main():
    vuln_id = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VULN_ID", "")
    issue_number = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("ISSUE_NUMBER", "")
    repo = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("REPO", "")
    project_dir = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("PROJECT_DIR", ".")
    artifacts_dir = sys.argv[5] if len(sys.argv) > 5 else os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")

    resolved = resolve_and_import(vuln_id, issue_number, repo, project_dir, artifacts_dir)
    print(resolved)

if __name__ == "__main__":
    main()
