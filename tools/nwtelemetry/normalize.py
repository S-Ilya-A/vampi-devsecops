"""Turn each scanner's report into findings of one common shape.

Every finding has:
  tool, scan, rule_id, title, severity (critical|high|medium|low|info),
  severity_rank (4..0), fingerprint, location, package, installed_version,
  fixed_version, fix_available, cve, instances, description

The fingerprint identifies "the same finding" across pipeline runs, so it leaves
out whatever changes when nothing about the finding did: line numbers, image tags,
the random user name the DAST session registers, ZAP's attack payloads.

  semgrep   rule | file | matched code (whitespace collapsed) | n-th identical match
  gitleaks  gitleaks' own fingerprint (commit:file:rule:line; history does not move)
  grype     vulnerability | package | version | package type
  trivy     vulnerability | package | version | package type (| path in the image)
            misconfiguration: check id | file;  secret: rule | file
  zap       alert | method | endpoint. For the API scan the endpoint is the OpenAPI
            path template the URL matches (/users/v1/{username}); active rules put
            payloads into every segment, so concrete URLs never repeat. URLs that
            match no template (a payload replaced a fixed segment) are counted
            under "{outside-definition}". Without a definition (the web client),
            the attack payload and DAST user name are replaced by placeholders.
            One finding per endpoint; its instances are counted.

Secret values never leave this module: gitleaks' Secret/Match fields are dropped.
"""
import hashlib
import json
import os
import re
import urllib.parse

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# (report file in reports/, tool, scan, CI job that writes it)
SCANS = [
    ("semgrep.json", "semgrep", "sast", "sast-semgrep"),
    ("gitleaks.json", "gitleaks", "secrets", "secrets-gitleaks"),
    ("grype.json", "grype", "sca", "sca-grype"),
    ("trivy-image-api.json", "trivy", "image:api", "scan-image-api"),
    ("trivy-image-frontend.json", "trivy", "image:frontend", "scan-image-frontend"),
    ("trivy-config-api.json", "trivy", "dockerfile:api", "scan-image-api"),
    ("trivy-config-frontend.json", "trivy", "dockerfile:frontend", "scan-image-frontend"),
    ("zap-baseline.json", "zap", "dast:web", "dast-zap-baseline"),
    ("zap-api.json", "zap", "dast:api", "dast-zap-api"),
]

_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_ZAP_SEV = {3: "high", 2: "medium", 1: "low", 0: "info"}
_DAST_USER = re.compile(r"dast[0-9a-f]{8}")


def _sev(value, default="info"):
    v = str(value or "").strip().lower()
    if v in SEVERITY_RANK:
        return v
    return {"negligible": "low", "unknown": "info", "moderate": "medium"}.get(v, default)


def _fp(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:20]


def _finding(tool, scan, rule_id, title, severity, key, **kw):
    f = {
        "tool": tool, "scan": scan, "rule_id": str(rule_id), "title": (title or str(rule_id))[:500],
        "severity": severity, "severity_rank": SEVERITY_RANK[severity],
        "fingerprint": _fp(tool, scan, *key),
        "location": "", "package": "", "installed_version": "", "fixed_version": "",
        "fix_available": False, "cve": "", "instances": 1, "description": "",
    }
    f.update({k: v for k, v in kw.items() if v is not None})
    f["description"] = (f["description"] or "")[:1000]
    return f


def semgrep(data, scan):
    out, seen = [], {}
    for r in data.get("results", []):
        extra = r.get("extra", {})
        code = " ".join((extra.get("lines") or "").split())
        base = (r["check_id"], r["path"], code)
        n = seen.get(base, 0)
        seen[base] = n + 1
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        out.append(_finding(
            "semgrep", scan, r["check_id"], extra.get("message", "").split("\n")[0],
            _SEMGREP_SEV.get(extra.get("severity"), "low"), base + (n,),
            location="%s:%s" % (r["path"], r.get("start", {}).get("line", "")),
            cve=(cwe[0] if isinstance(cwe, list) and cwe else cwe or "")[:200]))
    return out


def gitleaks(data, scan):
    out = []
    for r in data or []:
        out.append(_finding(
            "gitleaks", scan, r.get("RuleID"), r.get("Description"), "high",
            (r.get("Fingerprint") or "%s:%s:%s" % (r.get("Commit"), r.get("File"), r.get("RuleID")),),
            location="%s@%s" % (r.get("File"), (r.get("Commit") or "")[:8])))
    return out


def grype(data, scan):
    out = []
    for m in data.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        fix = v.get("fix", {})
        fixed = ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else ""
        locs = a.get("locations") or [{}]
        out.append(_finding(
            "grype", scan, v["id"], "%s in %s %s" % (v["id"], a["name"], a["version"]),
            _sev(v.get("severity")), (v["id"], a["name"], a["version"], a.get("type")),
            location=locs[0].get("path", ""), package=a["name"], installed_version=a["version"],
            fixed_version=fixed, fix_available=bool(fixed), cve=v["id"],
            description=v.get("description")))
    return out


def trivy(data, scan):
    out = []
    for res in data.get("Results") or []:
        target, rtype = res.get("Target", ""), res.get("Type") or res.get("Class", "")
        # Image targets carry the tag ("...api:b0bd24b9 (alpine 3.24.4)"): keep only the OS part.
        where = re.sub(r"^\S+:\S+ \((.*)\)$", r"\1", target)
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or ""
            out.append(_finding(
                "trivy", scan, v["VulnerabilityID"], v.get("Title") or v["VulnerabilityID"],
                _sev(v.get("Severity")),
                (v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion"), rtype, v.get("PkgPath", "")),
                location=v.get("PkgPath") or where, package=v["PkgName"],
                installed_version=v.get("InstalledVersion", ""), fixed_version=fixed,
                fix_available=bool(fixed), cve=v["VulnerabilityID"], description=v.get("Description")))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            out.append(_finding(
                "trivy", scan, m.get("AVDID") or m["ID"], m.get("Title"), _sev(m.get("Severity")),
                (m["ID"], target), location=target, fix_available=True,
                description=m.get("Resolution") or m.get("Description")))
        for s in res.get("Secrets") or []:
            out.append(_finding(
                "trivy", scan, s.get("RuleID"), s.get("Title"), _sev(s.get("Severity")),
                (s.get("RuleID"), target), location="%s:%s" % (target, s.get("StartLine", ""))))
    return out


def zap_path(uri, attack=""):
    """Path of a ZAP instance URL with what varies between runs replaced:
    the attack payload -> {attack}, the DAST user -> {dast-user}; no query string."""
    path = urllib.parse.urlsplit(uri).path
    plain = urllib.parse.unquote(path)
    if attack and attack.strip() and attack in plain:
        plain = plain.replace(attack, "{attack}")
    return _DAST_USER.sub("{dast-user}", plain) or "/"


def openapi_templates(spec):
    """[(compiled regex, template)] for the paths of an OpenAPI definition, most
    specific first (fewer parameters wins: /users/v1/login before /users/v1/{username})."""
    out = []
    for tmpl in (spec or {}).get("paths", {}):
        rx = "".join("[^/]+" if re.fullmatch(r"\{[^}]+\}", seg) else re.escape(seg)
                     for seg in re.split(r"(\{[^}]+\}|/)", tmpl) if seg)
        out.append((re.compile("^" + rx + "/?$"), tmpl, tmpl.count("{")))
    out.sort(key=lambda t: (t[2], -len(t[1])))
    return [(rx, t) for rx, t, _ in out]


def zap_endpoint(uri, attack="", templates=None):
    if not templates:
        return zap_path(uri, attack)
    path = urllib.parse.unquote(urllib.parse.urlsplit(uri).path)
    for rx, tmpl in templates:
        if rx.match(path):
            return tmpl
    return "{outside-definition}"


def zap(data, scan, suppressions=(), templates=None):
    groups = {}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            if int(a.get("confidence", 1)) == 0:   # marked false positive in ZAP
                continue
            for inst in a.get("instances") or [{}]:
                method, uri = inst.get("method", ""), inst.get("uri", "")
                key = (a.get("alertRef") or a["pluginid"], method, zap_endpoint(uri, inst.get("attack", ""), templates))
                g = groups.setdefault(key, {"alert": a, "uris": [], "suppressed": []})
                g["uris"].append(uri)
                g["suppressed"].append(next(
                    (s["id"] for s in suppressions
                     if s["pluginid"] == str(a["pluginid"]) and re.search(s["uri_regex"], uri)), None))
    out = []
    for (ref, method, path), g in sorted(groups.items()):
        a = g["alert"]
        f = _finding(
            "zap", scan, a["pluginid"], a.get("name") or a.get("alert"), _ZAP_SEV.get(int(a["riskcode"]), "info"),
            (ref, method, path), location="%s %s" % (method, path), instances=len(g["uris"]),
            cve=("CWE-%s" % a["cweid"]) if str(a.get("cweid", "")) not in ("", "-1", "0") else "",
            description=re.sub(r"<[^>]+>", "", a.get("desc", "")))
        # Suppressed only when the gate's suppression covers every instance.
        if all(g["suppressed"]):
            f["suppressed"] = g["suppressed"][0]
        out.append(f)
    return out


PARSERS = {"semgrep": semgrep, "gitleaks": gitleaks, "grype": grype, "trivy": trivy, "zap": zap}


def load_suppressions(path):
    """Active ZAP suppressions (the same file ci/zap_gate.py reads)."""
    import datetime
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        entries = json.load(f).get("suppressions", [])
    today = datetime.date.today().isoformat()
    return [e for e in entries if e.get("expires", "") >= today]


# The API scan imports this definition (written by ci/dast_session.py).
API_DEFINITION = "openapi-staging.json"


def normalize_dir(report_dir, zap_suppressions=()):
    """-> (findings, scans). A scan whose report is missing or unreadable is
    reported with status "missing", so a trend never mistakes "did not run" for
    "found nothing"."""
    findings, scans = [], []
    templates = None
    try:
        with open(os.path.join(report_dir, API_DEFINITION), encoding="utf-8") as f:
            templates = openapi_templates(json.load(f))
    except (OSError, ValueError):
        pass
    for fname, tool, scan, job in SCANS:
        path = os.path.join(report_dir, fname)
        entry = {"tool": tool, "scan": scan, "job": job, "report": fname,
                 "status": "missing", "findings": 0, "by_severity": {}}
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if tool == "zap":
                    items = zap(data, scan, zap_suppressions, templates if scan == "dast:api" else None)
                else:
                    items = PARSERS[tool](data, scan)
            except (ValueError, KeyError, TypeError) as e:
                entry["status"], entry["error"] = "unreadable", "%s: %s" % (type(e).__name__, e)
            else:
                for i in items:
                    i["job"] = job
                findings.extend(items)
                entry["status"] = "reported"
                # A Semgrep rule that timed out skipped (part of) a file: what it
                # did not report is unknown, not resolved.
                if tool == "semgrep" and any(
                        (e.get("type")[0] if isinstance(e.get("type"), list) else e.get("type")) == "Timeout"
                        for e in data.get("errors", [])):
                    entry["status"] = "incomplete"
                entry["findings"] = len(items)
                for i in items:
                    entry["by_severity"][i["severity"]] = entry["by_severity"].get(i["severity"], 0) + 1
        scans.append(entry)
    return findings, scans
