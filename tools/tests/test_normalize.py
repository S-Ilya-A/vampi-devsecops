import json
import os
import shutil
import tempfile
import unittest

from nwtelemetry import normalize

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


class SeverityAndShape(unittest.TestCase):
    def test_every_finding_has_the_common_fields(self):
        findings, _ = normalize.normalize_dir(FIX)
        required = {"tool", "scan", "rule_id", "title", "severity", "severity_rank", "fingerprint",
                    "location", "package", "installed_version", "fixed_version", "fix_available",
                    "cve", "instances", "description", "job"}
        self.assertTrue(findings)
        for f in findings:
            self.assertLessEqual(required, set(f), f)
            self.assertIn(f["severity"], normalize.SEVERITY_RANK)
            self.assertEqual(f["severity_rank"], normalize.SEVERITY_RANK[f["severity"]])

    def test_severity_mapping_per_tool(self):
        sev = lambda items: [f["severity"] for f in items]
        self.assertEqual(sev(normalize.semgrep(load("semgrep.json"), "sast")), ["high", "medium", "medium"])
        self.assertEqual(sev(normalize.grype(load("grype.json"), "sca")), ["high", "low"])   # Negligible -> low
        self.assertEqual(sev(normalize.gitleaks(load("gitleaks.json"), "secrets")), ["high"])

    def test_fix_availability(self):
        lodash, moment = normalize.grype(load("grype.json"), "sca")
        self.assertTrue(lodash["fix_available"])
        self.assertEqual(lodash["fixed_version"], "4.17.21")
        self.assertFalse(moment["fix_available"])
        pyjwt = [f for f in normalize.trivy(load("trivy-image-api.json"), "image:api") if f["package"] == "PyJWT"][0]
        self.assertEqual((pyjwt["severity"], pyjwt["fix_available"]), ("critical", False))


class Fingerprints(unittest.TestCase):
    def test_semgrep_ignores_line_moves_but_keeps_duplicates_apart(self):
        data = load("semgrep.json")
        before = [f["fingerprint"] for f in normalize.semgrep(data, "sast")]
        for r in data["results"]:
            r["start"]["line"] += 25            # code inserted above
        after = [f["fingerprint"] for f in normalize.semgrep(data, "sast")]
        self.assertEqual(before, after)
        self.assertEqual(len(set(before)), 3)    # two identical lines in one file stay two findings

    def test_trivy_ignores_the_image_tag(self):
        data = load("trivy-image-api.json")
        before = {f["fingerprint"] for f in normalize.trivy(data, "image:api")}
        for r in data["Results"]:
            r["Target"] = r["Target"].replace("b0bd24b9", "deadbeef")
        self.assertEqual(before, {f["fingerprint"] for f in normalize.trivy(data, "image:api")})

    def test_a_version_bump_is_a_different_finding(self):
        data = load("grype.json")
        before = normalize.grype(data, "sca")[0]["fingerprint"]
        data["matches"][0]["artifact"]["version"] = "4.17.20"
        self.assertNotEqual(before, normalize.grype(data, "sca")[0]["fingerprint"])

    def test_same_finding_in_two_scans_is_two_findings(self):
        data = load("trivy-config-api.json")
        a = normalize.trivy(data, "dockerfile:api")[0]["fingerprint"]
        b = normalize.trivy(data, "dockerfile:frontend")[0]["fingerprint"]
        self.assertNotEqual(a, b)


class Secrets(unittest.TestCase):
    def test_secret_values_are_never_shipped(self):
        findings, _ = normalize.normalize_dir(FIX)
        blob = json.dumps(findings)
        self.assertNotIn("synthetic-value-0001", blob)
        leak = [f for f in findings if f["tool"] == "gitleaks"][0]
        self.assertEqual(leak["location"], "deploy/s3-backup.env@c9c8553d")


class Zap(unittest.TestCase):
    def setUp(self):
        self.templates = normalize.openapi_templates(load("openapi-staging.json"))

    def test_urls_fold_into_openapi_endpoints(self):
        found = normalize.zap(load("zap-api.json"), "dast:api", templates=self.templates)
        by_loc = {(f["rule_id"], f["location"]): f for f in found}
        sqli = by_loc[("40018", "GET /users/v1/{username}")]
        self.assertEqual((sqli["severity"], sqli["instances"], sqli["cve"]), ("high", 2, "CWE-89"))
        self.assertIn(("40018", "PUT /users/v1/{username}/password"), by_loc)
        # the DAST user and a payload in the path both fold into the template
        self.assertEqual(by_loc[("100000", "PUT /users/v1/{username}/email")]["instances"], 2)
        # a payload that replaced a fixed segment matches no template
        self.assertIn(("100000", "POST {outside-definition}"), by_loc)

    def test_fixed_path_wins_over_template(self):
        self.assertEqual(normalize.zap_endpoint("http://h/users/v1/login", templates=self.templates), "/users/v1/login")

    def test_zap_false_positive_flag_is_respected(self):
        found = normalize.zap(load("zap-api.json"), "dast:api", templates=self.templates)
        self.assertNotIn("10021", {f["rule_id"] for f in found})   # confidence 0

    def test_suppression_marks_only_its_endpoint_and_expired_ones_do_not_apply(self):
        sups = normalize.load_suppressions(os.path.join(FIX, "zap-suppressions.json"))
        self.assertEqual([s["id"] for s in sups], ["S-02"])
        found = normalize.zap(load("zap-api.json"), "dast:api", sups, self.templates)
        marks = {f["location"]: f.get("suppressed") for f in found if f["rule_id"] == "40018"}
        self.assertEqual(marks, {"GET /users/v1/{username}": None, "PUT /users/v1/{username}/password": "S-02"})

    def test_without_a_definition_payload_and_user_are_placeholders(self):
        self.assertEqual(normalize.zap_path("http://h/users/v1/dast1a2b3c4d/email?x=1"), "/users/v1/{dast-user}/email")
        self.assertEqual(normalize.zap_path("http://h/search/%27%20OR%201=1", "' OR 1=1"), "/search/{attack}")


class Scans(unittest.TestCase):
    def test_missing_and_unreadable_reports_are_not_zero_findings(self):
        tmp = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(FIX, "grype.json"), tmp)
            with open(os.path.join(tmp, "semgrep.json"), "w") as f:
                f.write("{not json")
            findings, scans = normalize.normalize_dir(tmp)
            status = {s["scan"]: s["status"] for s in scans}
            self.assertEqual(status["sca"], "reported")
            self.assertEqual(status["sast"], "unreadable")
            self.assertEqual(status["secrets"], "missing")
            self.assertEqual({f["tool"] for f in findings}, {"grype"})
            self.assertEqual(len(scans), len(normalize.SCANS))
        finally:
            shutil.rmtree(tmp)

    def test_semgrep_timeout_marks_the_scan_incomplete(self):
        tmp = tempfile.mkdtemp()
        try:
            data = load("semgrep.json")
            data["errors"] = [{"type": "Timeout", "path": "frontend/public/app.js"}]
            with open(os.path.join(tmp, "semgrep.json"), "w") as f:
                json.dump(data, f)
            _, scans = normalize.normalize_dir(tmp)
            self.assertEqual([s["status"] for s in scans if s["scan"] == "sast"], ["incomplete"])
        finally:
            shutil.rmtree(tmp)

    def test_counts_by_severity(self):
        _, scans = normalize.normalize_dir(FIX)
        sast = [s for s in scans if s["scan"] == "sast"][0]
        self.assertEqual((sast["findings"], sast["by_severity"]), (3, {"high": 1, "medium": 2}))


if __name__ == "__main__":
    unittest.main()
