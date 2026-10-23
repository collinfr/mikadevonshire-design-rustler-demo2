#!/usr/bin/env python3
import sys
import unittest
from create_issues import (
    compute_similarity,
    extract_issue_attributes,
    canonicalize_cwe_type,
    clean_file_path
)

class TestDeduplication(unittest.TestCase):

    def test_canonicalize_cwe(self):
        cwe, cat = canonicalize_cwe_type("CWE-89", "SQL Injection")
        self.assertEqual(cwe, "CWE-89")
        self.assertEqual(cat, "injection")

        cwe2, cat2 = canonicalize_cwe_type("", "Open Redirect")
        self.assertEqual(cwe2, "CWE-601")
        self.assertEqual(cat2, "redirect")

    def test_clean_path(self):
        self.assertEqual(clean_file_path("/workspace/repo/routes/redirect.ts"), "routes/redirect.ts")
        self.assertEqual(clean_file_path("./routes/redirect.ts"), "routes/redirect.ts")

    def test_clean_db_rerun_matching(self):
        """Simulates a rerun on a fresh database with a newly generated finding ID."""
        existing_issue = {
            "number": 101,
            "title": "[CodeMender 🟡 MEDIUM] Open Redirect via Unvalidated `to` in routes/redirect.ts (a4058a05)",
            "body": """<!-- codemender-finding-metadata
{
  "file": "routes/redirect.ts",
  "vuln_type": "Open Redirect",
  "cwe": "CWE-601",
  "start_line": 14,
  "end_line": 20,
  "finding_id": "a4058a05",
  "confidence": "100%",
  "models": ["gemini-3.8-flash"]
}
-->
| Attribute | Details |
| :--- | :--- |
| **Finding ID** | `a4058a05` |
| **Vulnerable File** | [`routes/redirect.ts (L14–L20)`](https://github.com/foo) |"""
        }
        attr = extract_issue_attributes(existing_issue)

        # New scan with a different random finding ID and slightly different title
        new_finding = {
            "id": "f89b1234",
            "file": "routes/redirect.ts",
            "vuln_id": "CWE-601",
            "type": "Open Redirect",
            "title": "Open Redirect vulnerability in performRedirect handler",
            "start_line": 14,
            "end_line": 20
        }

        score = compute_similarity(attr, new_finding)
        print(f"\n[Test Clean DB Rerun] Match Score: {score:.3f}")
        self.assertGreaterEqual(score, 0.70)

    def test_flash_vs_pro_multi_model_matching(self):
        """Simulates Flash detecting a single line while Pro detects a line range and different wording."""
        existing_flash_issue = {
            "number": 102,
            "title": "[CodeMender 🔴 CRITICAL] SQL Injection in search.ts (b1122334)",
            "body": """<!-- codemender-finding-metadata
{
  "file": "routes/search.ts",
  "vuln_type": "SQL Injection",
  "cwe": "CWE-89",
  "start_line": 22,
  "end_line": 22,
  "finding_id": "b1122334",
  "confidence": "100%",
  "models": ["gemini-3.8-flash"]
}
-->"""
        }
        attr = extract_issue_attributes(existing_flash_issue)

        pro_finding = {
            "id": "c9988776",
            "file": "routes/search.ts",
            "vuln_id": "CWE-89",
            "type": "SQL Injection",
            "title": "Unsanitized User Input in Sequelize Raw Query (SQLi)",
            "start_line": 20,
            "end_line": 28
        }

        score = compute_similarity(attr, pro_finding)
        print(f"[Test Flash vs Pro] Match Score: {score:.3f}")
        self.assertGreaterEqual(score, 0.70)

    def test_different_bugs_in_same_file_no_match(self):
        """Ensures two different bugs in the same file are NOT collapsed into one."""
        existing_issue = {
            "number": 103,
            "title": "[CodeMender 🟠 HIGH] SQL Injection in routes/data.ts (11112222)",
            "body": """<!-- codemender-finding-metadata
{
  "file": "routes/data.ts",
  "vuln_type": "SQL Injection",
  "cwe": "CWE-89",
  "start_line": 10,
  "end_line": 15,
  "finding_id": "11112222",
  "confidence": "100%",
  "models": ["gemini-3.8-flash"]
}
-->"""
        }
        attr = extract_issue_attributes(existing_issue)

        xss_finding = {
            "id": "33334444",
            "file": "routes/data.ts",
            "vuln_id": "CWE-79",
            "type": "Cross-Site Scripting",
            "title": "Reflected Cross-Site Scripting via query parameter",
            "start_line": 180,
            "end_line": 195
        }

        score = compute_similarity(attr, xss_finding)
        print(f"[Test Different Bugs Same File] Match Score: {score:.3f}")
        self.assertLess(score, 0.70)

    def test_different_file_hard_filter(self):
        """Ensures findings in different files always receive 0 score."""
        existing_issue = {
            "number": 104,
            "title": "[CodeMender 🔴 CRITICAL] RCE in routes/exec.ts",
            "body": """<!-- codemender-finding-metadata
{
  "file": "routes/exec.ts",
  "vuln_type": "Remote Code Execution",
  "cwe": "CWE-94",
  "start_line": 10,
  "end_line": 15
}
-->"""
        }
        attr = extract_issue_attributes(existing_issue)

        other_finding = {
            "id": "99999999",
            "file": "routes/other.ts",
            "vuln_id": "CWE-94",
            "type": "Remote Code Execution",
            "title": "Remote Code Execution",
            "start_line": 10,
            "end_line": 15
        }

        score = compute_similarity(attr, other_finding)
        self.assertEqual(score, 0.0)

    def test_parallel_multi_app_isolation(self):
        """Ensures findings in different app folders (e.g. dvga vs juice-shop) never match,
        guaranteeing zero crosstalk between parallel workers."""
        dvga_issue = {
            "number": 328,
            "title": "OS Command Injection in systemDiagnostics GraphQL Mutation in dvga/core/views.py (7df9c30a)",
            "body": """<!-- codemender-finding-metadata
{
  "file": "dvga/core/views.py",
  "vuln_type": "Command Injection",
  "cwe": "CWE-78",
  "start_line": 250,
  "end_line": 254,
  "finding_id": "7df9c30a"
}
-->"""
        }
        dvga_attr = extract_issue_attributes(dvga_issue)

        # Finding from a concurrent worker scanning juice-shop
        juice_finding = {
            "id": "a546faa5",
            "file": "juice-shop/routes/login.ts",
            "vuln_id": "CWE-89",
            "type": "SQL Injection",
            "title": "SQL Injection in User Login Route",
            "start_line": 34,
            "end_line": 35
        }

        # Score must be 0.0
        score_cross = compute_similarity(dvga_attr, juice_finding)
        self.assertEqual(score_cross, 0.0)

        # Finding from concurrent worker scanning dvga matching existing dvga issue
        dvga_finding_rerun = {
            "id": "7df9c30a",
            "file": "dvga/core/views.py",
            "vuln_id": "CWE-78",
            "type": "Command Injection",
            "title": "OS Command Injection in systemDiagnostics GraphQL Mutation",
            "start_line": 250,
            "end_line": 254
        }
        score_match = compute_similarity(dvga_attr, dvga_finding_rerun)
        self.assertEqual(score_match, 1.0)

    def test_clean_file_path_preserves_subproject_directories(self):
        """Ensures subproject directory names like dvga and juice-shop are preserved."""
        self.assertEqual(clean_file_path("/workspace/repo/dvga/core/views.py"), "dvga/core/views.py")
        self.assertEqual(clean_file_path("/workspace/repo/juice-shop/routes/login.ts"), "juice-shop/routes/login.ts")
        self.assertEqual(clean_file_path("./dvga/core/views.py"), "dvga/core/views.py")
        self.assertEqual(clean_file_path("./juice-shop/routes/login.ts"), "juice-shop/routes/login.ts")
        self.assertEqual(clean_file_path("juice-shop/routes/login.ts"), "juice-shop/routes/login.ts")

if __name__ == "__main__":
    unittest.main()
