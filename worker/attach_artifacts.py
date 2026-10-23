#!/usr/bin/env python3
"""
CodeMender Artifact Collector & GitHub Issue Attachment Helper

1. Collects all generated CodeMender artifacts into ARTIFACTS_DIR:
   - .exploit/* (exploit.sh, PLAN.md, LOG.md, REPORT.md, info.yaml, poc.*, etc.)
   - /root/.codemender/artifacts/* (session artifacts)
   - /root/.codemender/logs/* (session logs & JSONL traces)
   - /root/.codemender/reports/* (HTML/JSON/SARIF/MD reports)
   - cm-find.log, cm-verify.log, cm-fix.log, findings.json, codemender.sarif
2. Writes an index README.md inside ARTIFACTS_DIR and publishes the entire
   artifacts directory to the 'codemender/artifacts' branch of the target
   GitHub repository.
3. Generates a clean, single-hyperlink Markdown section pointing to the
   published artifacts directory to attach to GitHub Issues and Pull Requests
   without cluttering the page.
"""

import os
import re
import shutil
import subprocess
import sys
import zipfile


ARTIFACT_BRANCH = "codemender/artifacts"
MAX_FILE_BYTES = 20 * 1024 * 1024  # 20 MB per-file safety limit for GitHub


def format_size(num_bytes):
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.1f} MB"


def categorize_artifact(rel_path):
    lower = rel_path.lower()
    base = os.path.basename(lower)
    if base.endswith(".zip"):
        return "📦 Complete Zip Archive (Artifacts + SARIF)"
    if base == "issue-sarif.json":
        return "🛡️ Issue SARIF Details (2.1.0)"
    if base == "issue-finding.json":
        return "🗂️ Issue Finding Details (JSON)"
    if base == "exploit.sh" or (lower.startswith("exploit/") and base.endswith((".sh", ".py", ".js"))):
        return "🧪 Exploit / PoC Script"
    if base == "plan.md":
        return "📋 Verification / Exploit Plan"
    if base == "log.md":
        return "📝 Agent Action Log"
    if base == "report.md":
        return "🔬 Verification Report"
    if base in ("info.yaml", "info.yml"):
        return "⚙️ Exploit Metadata"
    if lower.startswith("exploit/") or lower.startswith("cm-agent-artifacts/"):
        return "🧰 Sandbox Artifact"
    if base.startswith("cm-verify"):
        return "🖥️ Verify Execution Log"
    if base.startswith("cm-fix"):
        return "🛠️ Fix Execution Log"
    if base.startswith("cm-find"):
        return "🔍 Find Execution Log"
    if base.startswith("hunt-") or base.endswith(".yaral"):
        return "🕵️‍♂️ Forensic Hunt Artifact"
    if base == "findings-report.md":
        return "📊 Findings Report (Markdown)"
    if base == "findings.json":
        return "🗂️ Structured Findings (JSON)"
    if base == "codemender.sarif":
        return "🛡️ SARIF Report"
    if base == "report.html":
        return "🌐 Interactive HTML Report"
    if "cm-session-logs" in lower:
        return "📜 LLM Session Trace"
    return "📄 Artifact"


def collect_all_artifacts(workspace_dir="/workspace/repo", artifacts_dir="/workspace/artifacts"):
    """Copies .exploit/, /root/.codemender/artifacts/, and /root/.codemender/logs/ into artifacts_dir."""
    os.makedirs(artifacts_dir, exist_ok=True)
    exploit_dest = os.path.join(artifacts_dir, "exploit")

    # 1. Search workspace_dir for any .exploit directories created before/after reset
    if workspace_dir and os.path.isdir(workspace_dir):
        for root, dirs, _ in os.walk(workspace_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            if "node_modules" in dirs:
                dirs.remove("node_modules")
            if ".exploit" in dirs:
                src_exploit = os.path.join(root, ".exploit")
                os.makedirs(exploit_dest, exist_ok=True)
                for item in os.listdir(src_exploit):
                    s = os.path.join(src_exploit, item)
                    d = os.path.join(exploit_dest, item)
                    try:
                        if os.path.isdir(s):
                            shutil.copytree(s, d, dirs_exist_ok=True)
                        else:
                            shutil.copy2(s, d)
                    except Exception as e:
                        print(f"Notice copying {s}: {e}", file=sys.stderr)

    # 2. Copy /root/.codemender/artifacts/<session_id>/*
    cm_artifacts_root = "/root/.codemender/artifacts"
    if os.path.isdir(cm_artifacts_root):
        for entry in sorted(os.listdir(cm_artifacts_root)):
            session_path = os.path.join(cm_artifacts_root, entry)
            if os.path.isdir(session_path):
                os.makedirs(exploit_dest, exist_ok=True)
                for sub_root, _, files in os.walk(session_path):
                    for fname in files:
                        src_file = os.path.join(sub_root, fname)
                        rel = os.path.relpath(src_file, session_path)
                        rel_clean = re.sub(r"^(\.?exploit/)+", "", rel)
                        dst_file = os.path.join(exploit_dest, rel_clean)
                        os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                        try:
                            shutil.copy2(src_file, dst_file)
                        except Exception as e:
                            print(f"Notice copying session artifact {src_file}: {e}", file=sys.stderr)

    # 3. Copy /root/.codemender/logs/*
    cm_logs_root = "/root/.codemender/logs"
    if os.path.isdir(cm_logs_root):
        logs_dest = os.path.join(artifacts_dir, "cm-session-logs")
        os.makedirs(logs_dest, exist_ok=True)
        for item in os.listdir(cm_logs_root):
            s = os.path.join(cm_logs_root, item)
            d = os.path.join(logs_dest, item)
            try:
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            except Exception as e:
                print(f"Notice copying log {s}: {e}", file=sys.stderr)

    # 4. Copy /root/.codemender/reports/report.html if present
    html_report = "/root/.codemender/reports/report.html"
    if os.path.isfile(html_report) and not os.path.isfile(os.path.join(artifacts_dir, "report.html")):
        try:
            shutil.copy2(html_report, os.path.join(artifacts_dir, "report.html"))
        except Exception:
            pass


def create_artifacts_zip(artifacts_dir, subdir):
    """
    Creates a complete .zip bundle inside `artifacts_dir` containing all CodeMender
    artifacts (exploit/*, logs, reports, session traces) and SARIF details.
    Returns the zip filename (or empty string if no files exist).
    """
    if not os.path.isdir(artifacts_dir):
        return ""

    for fname in os.listdir(artifacts_dir):
        if fname.endswith(".zip") or fname == "README.md":
            try:
                os.remove(os.path.join(artifacts_dir, fname))
            except Exception:
                pass

    issue_num = os.environ.get("ISSUE_NUMBER", "").strip()
    vuln_id = os.environ.get("VULN_ID", "").strip()
    if issue_num and vuln_id:
        zip_name = f"codemender-issue-{issue_num}-{vuln_id}-artifacts.zip"
    elif vuln_id:
        zip_name = f"codemender-{vuln_id}-artifacts.zip"
    else:
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", subdir.strip("/")).strip("-") or "scan"
        zip_name = f"codemender-{slug}-artifacts.zip"

    files_to_zip = []
    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            if fname.endswith(".zip") or fname == "README.md":
                continue
            abs_p = os.path.join(root, fname)
            rel_p = os.path.relpath(abs_p, artifacts_dir).replace("\\", "/")
            try:
                if os.path.getsize(abs_p) > 0:
                    files_to_zip.append((abs_p, rel_p))
            except Exception:
                pass

    if not files_to_zip:
        return ""

    zip_path = os.path.join(artifacts_dir, zip_name)
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for abs_p, rel_p in sorted(files_to_zip, key=lambda x: x[1]):
                zf.write(abs_p, arcname=rel_p)
        return zip_name
    except Exception as e:
        print(f"⚠️ Notice creating zip archive {zip_path}: {e}", file=sys.stderr)
        return ""


def list_artifact_files(artifacts_dir):
    """Returns a sorted list of (rel_path, abs_path, size_bytes) for all files in artifacts_dir."""
    entries = []
    if not os.path.isdir(artifacts_dir):
        return entries

    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            if fname == "README.md":
                continue
            abs_p = os.path.join(root, fname)
            rel_p = os.path.relpath(abs_p, artifacts_dir).replace("\\", "/")
            try:
                sz = os.path.getsize(abs_p)
                if sz > 0:
                    entries.append((rel_p, abs_p, sz))
            except Exception:
                pass

    def sort_key(item):
        rel = item[0].lower()
        base = os.path.basename(rel)
        if base.endswith(".zip"):
            return (0, rel)
        if base == "report.html":
            return (1, rel)
        if base == "issue-sarif.json":
            return (2, rel)
        if base == "exploit.sh":
            return (3, rel)
        if base == "plan.md":
            return (4, rel)
        if base == "report.md":
            return (5, rel)
        if base == "log.md":
            return (6, rel)
        if base in ("info.yaml", "info.yml"):
            return (7, rel)
        if rel.startswith("exploit/"):
            return (8, rel)
        if base.startswith(("cm-verify", "cm-fix", "cm-find", "hunt-")):
            return (9, rel)
        if base in ("findings-report.md", "issue-finding.json", "findings.json", "codemender.sarif"):
            return (10, rel)
        if "cm-session-logs" in rel and not rel.endswith("-nosid.jsonl"):
            return (11, rel)
        return (12, rel)

    entries.sort(key=sort_key)
    return entries


def resolve_gcs_paths(repo, subdir_clean):
    bucket = os.environ.get("ARTIFACTS_BUCKET", "codemender-artifacts-cm-gh-506516")
    ref = os.environ.get("REF", "main")
    target_path = os.environ.get("TARGET_PATH", "")
    if subdir_clean.startswith(("verify/", "fix/", "hunt/")):
        gcs_prefix = f"{repo}/{ref}/{subdir_clean}"
    elif target_path and target_path != ".":
        target_slug = target_path.replace("/", "_")
        gcs_prefix = f"{repo}/{ref}/{target_slug}"
    elif subdir_clean.startswith(f"find/{ref}/"):
        tail_slug = subdir_clean[len(f"find/{ref}/"):]
        gcs_prefix = f"{repo}/{ref}/{tail_slug}"
    else:
        gcs_prefix = f"{repo}/{ref}"

    gcs_uri = f"gs://{bucket}/{gcs_prefix}/" if bucket else ""
    gcs_browser_base = f"https://storage.cloud.google.com/{bucket}/{gcs_prefix}" if bucket else ""
    gcs_console_dir = f"https://console.cloud.google.com/storage/browser/{bucket}/{gcs_prefix}" if bucket else ""
    return gcs_uri, gcs_browser_base, gcs_console_dir


def write_directory_readme(repo, subdir, artifacts_dir="/workspace/artifacts"):
    """Writes a helpful README.md inside the artifacts directory so browsing the GitHub folder shows 1-click links."""
    entries = list_artifact_files(artifacts_dir)
    if not entries:
        return

    subdir_clean = subdir.strip("/")
    gcs_uri, gcs_browser_base, gcs_console_dir = resolve_gcs_paths(repo, subdir_clean)
    zip_entries = [e for e in entries if e[0].lower().endswith(".zip")]
    has_html_report = any(os.path.basename(e[0]).lower() == "report.html" for e in entries)

    lines = [
        f"# 🛡️ CodeMender Run Artifacts (`{subdir_clean}`)",
        "",
    ]
    if zip_entries and repo:
        z_rel, _, z_sz = zip_entries[0]
        z_raw_url = f"https://github.com/{repo}/raw/{ARTIFACT_BRANCH}/{subdir_clean}/{z_rel}"
        lines.append(f"- 🗜️ **[⬇️ Download Complete Artifacts + SARIF Bundle (`{z_rel}`, {format_size(z_sz)})]({z_raw_url})**")
    if has_html_report and gcs_browser_base:
        lines.append(f"- 🌐 **[Open Interactive HTML Security Report (`report.html`)]({gcs_browser_base}/report.html)**")
    if gcs_console_dir and gcs_uri:
        lines.append(f"- ☁️ **Google Cloud Storage Directory:** [`{gcs_uri}`]({gcs_console_dir})")
    lines.extend([
        "",
        "## 📄 Artifact Index",
        "",
        "| Artifact File | Type | Size | Actions |",
        "| :--- | :--- | :--- | :--- |",
    ])

    for rel_p, _, sz in entries[:50]:
        cat = categorize_artifact(rel_p)
        sz_str = format_size(sz)
        blob_url = f"https://github.com/{repo}/blob/{ARTIFACT_BRANCH}/{subdir_clean}/{rel_p}"
        raw_url = f"https://github.com/{repo}/raw/{ARTIFACT_BRANCH}/{subdir_clean}/{rel_p}"
        if os.path.basename(rel_p).lower() == "report.html" and gcs_browser_base:
            links_md = f"**[🌐 Rendered HTML]({gcs_browser_base}/{rel_p})** &bull; [📄 Source]({blob_url}) &bull; [⬇️ Raw]({raw_url})"
        else:
            links_md = f"[📄 View]({blob_url}) &bull; [⬇️ Raw]({raw_url})"
        lines.append(f"| `{rel_p}` | {cat} | `{sz_str}` | {links_md} |")

    readme_path = os.path.join(artifacts_dir, "README.md")
    try:
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def publish_artifacts_to_branch(repo, artifacts_dir, subdir):
    """
    Commits and pushes the contents of artifacts_dir to the `codemender/artifacts`
    branch under `<subdir>/` in the target GitHub repository.
    Returns True if the push succeeded.
    """
    if not repo or not os.path.isdir(artifacts_dir):
        return False

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if token:
        remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"
    else:
        remote_url = f"https://github.com/{repo}.git"

    tmp_git_dir = "/tmp/cm-artifacts-publish"

    for attempt in range(1, 5):
        shutil.rmtree(tmp_git_dir, ignore_errors=True)
        os.makedirs(tmp_git_dir, exist_ok=True)
        try:
            clone_res = subprocess.run(
                ["git", "clone", "--depth=1", "--branch", ARTIFACT_BRANCH, remote_url, tmp_git_dir],
                capture_output=True,
                text=True,
            )
            if clone_res.returncode != 0:
                subprocess.run(["git", "init", tmp_git_dir], capture_output=True, check=True)
                subprocess.run(["git", "-C", tmp_git_dir, "remote", "add", "origin", remote_url], capture_output=True, check=True)
                subprocess.run(["git", "-C", tmp_git_dir, "checkout", "--orphan", ARTIFACT_BRANCH], capture_output=True, check=True)

            target_dest = os.path.join(tmp_git_dir, subdir.strip("/"))
            shutil.rmtree(target_dest, ignore_errors=True)
            os.makedirs(target_dest, exist_ok=True)

            copied_count = 0
            for root, _, files in os.walk(artifacts_dir):
                for fname in files:
                    src_path = os.path.join(root, fname)
                    try:
                        if os.path.getsize(src_path) > MAX_FILE_BYTES:
                            continue
                        rel_path = os.path.relpath(src_path, artifacts_dir)
                        dst_path = os.path.join(target_dest, rel_path)
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
                        copied_count += 1
                    except Exception:
                        pass

            if copied_count == 0:
                return False

            subprocess.run(["git", "-C", tmp_git_dir, "config", "user.name", "CodeMender AI [bot]"], capture_output=True)
            subprocess.run(["git", "-C", tmp_git_dir, "config", "user.email", "collinf@google.com"], capture_output=True)
            subprocess.run(["git", "-C", tmp_git_dir, "add", "-A"], capture_output=True, check=True)

            diff_res = subprocess.run(["git", "-C", tmp_git_dir, "diff", "--cached", "--quiet"], capture_output=True)
            if diff_res.returncode != 0:
                subprocess.run(
                    ["git", "-C", tmp_git_dir, "commit", "-s", "-m", f"chore(artifacts): store CodeMender artifacts for {subdir}"],
                    capture_output=True,
                    check=True,
                )
                push_cmd = ["git", "-C", tmp_git_dir, "push", "origin", f"HEAD:refs/heads/{ARTIFACT_BRANCH}"]
                if attempt == 4:
                    push_cmd.append("--force")
                push_res = subprocess.run(push_cmd, capture_output=True, text=True)
                if push_res.returncode != 0:
                    if attempt < 4:
                        continue
                    print(f"⚠️ Notice pushing artifacts branch: {push_res.stderr.strip()}", file=sys.stderr)
                    return False

            print(f"✅ Published {copied_count} artifact file(s) to {repo}@{ARTIFACT_BRANCH}/{subdir}", file=sys.stderr)
            return True
        except Exception as e:
            if attempt == 4:
                print(f"⚠️ Exception publishing artifacts branch: {e}", file=sys.stderr)
                return False
        finally:
            shutil.rmtree(tmp_git_dir, ignore_errors=True)
    return False


def build_artifacts_section(repo, subdir, artifacts_dir="/workspace/artifacts", published_to_gh=True):
    """
    Builds a concise single-hyperlink Markdown section pointing directly to the
    directory where all CodeMender artifacts, logs, SARIF reports, and bundles are stored.
    """
    entries = list_artifact_files(artifacts_dir)
    if not entries:
        return ""

    subdir_clean = subdir.strip("/")
    tree_url = f"https://github.com/{repo}/tree/{ARTIFACT_BRANCH}/{subdir_clean}"
    gcs_uri, _, gcs_console_dir = resolve_gcs_paths(repo, subdir_clean)

    lines = [
        "### 📦 Attached CodeMender Artifacts",
        "",
    ]
    if published_to_gh and repo:
        lines.append(f"📂 **[Browse All CodeMender Artifacts (`{ARTIFACT_BRANCH}/{subdir_clean}`)]({tree_url})**")
    elif gcs_console_dir:
        lines.append(f"📂 **[Browse All CodeMender Artifacts (`{gcs_uri}`)]({gcs_console_dir})**")
    else:
        lines.append(f"📂 **[Browse All CodeMender Artifacts]({tree_url})**")

    return "\n".join(lines)


def prepare_and_publish(repo, subdir, workspace_dir="/workspace/repo", artifacts_dir="/workspace/artifacts"):
    """Convenience entry point: collects all artifacts, builds .zip archive, writes directory README, pushes to codemender/artifacts, and returns the single-link Markdown block."""
    collect_all_artifacts(workspace_dir=workspace_dir, artifacts_dir=artifacts_dir)
    create_artifacts_zip(artifacts_dir=artifacts_dir, subdir=subdir)
    write_directory_paths = write_directory_readme(repo=repo, subdir=subdir, artifacts_dir=artifacts_dir)
    published = publish_artifacts_to_branch(repo=repo, artifacts_dir=artifacts_dir, subdir=subdir)
    return build_artifacts_section(repo=repo, subdir=subdir, artifacts_dir=artifacts_dir, published_to_gh=published)


if __name__ == "__main__":
    # CLI usage: attach_artifacts.py <repo> <subdir> [workspace_dir] [artifacts_dir] [output_md_file]
    repo_arg = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("REPO", "")
    subdir_arg = sys.argv[2] if len(sys.argv) > 2 else "find/main"
    ws_arg = sys.argv[3] if len(sys.argv) > 3 else "/workspace/repo"
    art_arg = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")
    out_file = sys.argv[5] if len(sys.argv) > 5 else ""

    md = prepare_and_publish(repo_arg, subdir_arg, ws_arg, art_arg)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)
