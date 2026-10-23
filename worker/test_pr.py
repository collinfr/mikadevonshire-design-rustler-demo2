#!/usr/bin/env python3
import unittest
from create_pr import (
    build_pr_body,
    format_severity,
    format_cwe_link,
    extract_fix_rationale,
    clean_file_path
)

class TestCreatePR(unittest.TestCase):

    def test_build_pr_body_structure(self):
        finding = {
            "id": "a4058a05",
            "full_id": "a4058a0512345678",
            "severity": "MEDIUM",
            "type": "Open Redirect",
            "vuln_id": "CWE-601",
            "file": "routes/redirect.ts",
            "title": "Open Redirect via Unvalidated `to` Query Parameter",
            "confidence": "100%",
            "analysis": "User input passed to `res.redirect()` is not validated against the whitelist of allowed targets.",
            "start_line": 14,
            "end_line": 20,
            "issue_number": 170,
            "models": ["gemini-3.8-flash", "gemini-3.8-pro"]
        }

        rationale = extract_fix_rationale("/nonexistent", finding)
        body = build_pr_body("cloud-gtm/codemender-actions-demo", "main", "main", finding, rationale, "1 file changed, 4 insertions(+), 2 deletions(-)")

        print("\n--- SAMPLE GENERATED PR BODY ---")
        print(body[:600] + "\n...\n")

        self.assertIn("## 🛡️ CodeMender Automated Security Remediation", body)
        self.assertIn("Closes #170", body)
        self.assertIn("CWE-601", body)
        self.assertIn("routes/redirect.ts", body)
        self.assertIn("### 🔬 Root Cause Analysis", body)
        self.assertIn("### 🛠️ How This Patch Addresses the Core Issue", body)
        self.assertIn("### 🧪 Verification & Security Testing", body)
        self.assertIn("gemini-3.8-flash", body)
        self.assertIn("gemini-3.8-pro", body)

    def test_build_pr_body_default_model(self):
        finding = {
            "id": "b5059b06",
            "full_id": "b5059b0612345678",
            "severity": "HIGH",
            "type": "Command Injection",
            "vuln_id": "CWE-78",
            "file": "utils/diagnostics.py",
            "title": "Command Injection in test_host_connectivity",
            "confidence": "100%",
            "analysis": "Unsanitized user input passed to subprocess.",
            "start_line": 10,
            "end_line": 15
        }
        rationale = extract_fix_rationale("/nonexistent", finding)
        body = build_pr_body("cloud-gtm/codemender-actions-demo", "main", "main", finding, rationale, "1 file changed")
        self.assertIn("gemini-4-argon", body)

if __name__ == "__main__":
    unittest.main()
