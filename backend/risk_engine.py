import json
import csv
from datetime import datetime

# ============================================================
# PART 1: LOAD ALL DATA FILES
# ============================================================
def load_data():
    with open("../data/applications.json") as f:
        applications = json.load(f)
    with open("../data/vulnerability_db.json") as f:
        vuln_db = json.load(f)
    with open("../data/license_rules.json") as f:
        license_rules = json.load(f)
    with open("../data/sbom_dependencies.csv") as f:
        deps = list(csv.DictReader(f))
    return applications, vuln_db, license_rules, deps


# ============================================================
# PART 2: CHECK IF A LIBRARY VERSION IS VULNERABLE
# ============================================================
def version_is_affected(version, affected_expr):
    # affected_expr looks like "<3.0.0" - means "any version below 3.0.0 is vulnerable"
    try:
        op = affected_expr[0]
        target = tuple(int(x) for x in affected_expr[1:].split("."))
        current = tuple(int(x) for x in version.split("."))
        if op == "<":
            return current < target
        return True
    except Exception:
        return True  # if unparseable, assume vulnerable to be safe


# ============================================================
# PART 3: SCORE ONE DEPENDENCY
# ============================================================
def evaluate_dependency(dep, apps_by_id, vuln_lookup, license_lookup):
    app = apps_by_id[dep["app_id"]]
    score = 0.0
    findings = []

    # ---- Check 1: Vulnerability ----
    matched_cve = None
    for v in vuln_lookup.get(dep["library_name"], []):
        if version_is_affected(dep["version"], v["affected_versions"]):
            if matched_cve is None or v["cvss_score"] > matched_cve["cvss_score"]:
                matched_cve = v

    if matched_cve:
        score += matched_cve["cvss_score"]
        if not matched_cve["patch_available"]:
            score += 1.5
        if matched_cve.get("exploit_known_in_wild"):
            score += 2.5
        findings.append({
            "type": "vulnerability",
            "detail": f"{matched_cve['cve_id']} (CVSS {matched_cve['cvss_score']})"
        })

    # ---- Check 2: License Conflict ----
    rule = license_lookup.get(dep["license"])
    if rule and not rule["compatible_with_proprietary"] and app["distributed_externally"] == True:
        score += 8.0
        findings.append({
            "type": "license_conflict",
            "detail": f"{dep['license']} not safe for external distribution"
        })
    elif dep["license"] == "UNKNOWN":
        score += 5.0
        findings.append({"type": "license_unknown", "detail": "No license declared"})

    # ---- Check 3: Unmaintained Library ----
    days_old = (datetime.today() - datetime.strptime(dep["last_updated"], "%Y-%m-%d")).days
    if days_old > 730:
        score += 3.0
        findings.append({
            "type": "unmaintained",
            "detail": f"No updates in {days_old} days"
        })

    # ---- Apply business criticality multiplier ----
    crit_multiplier = {"high": 1.3, "medium": 1.0, "low": 0.8}.get(app["criticality"], 1.0)
    final_score = round(score * crit_multiplier, 2)

    return {
        "dependency_id": dep["dependency_id"],
        "app_id": dep["app_id"],
        "app_name": app["name"],
        "library_name": dep["library_name"],
        "version": dep["version"],
        "risk_score": final_score,
        "findings": findings,
        "status": "risky" if findings else "clean"
    }


# ============================================================
# PART 4: MAIN FUNCTION - THIS IS WHAT MEMBER 2 WILL USE
# ============================================================
def get_ranked_report(top_n=20):
    applications, vuln_db, license_rules, deps = load_data()
    apps_by_id = {a["app_id"]: a for a in applications}

    vuln_lookup = {}
    for v in vuln_db:
        vuln_lookup.setdefault(v["library_name"], []).append(v)

    license_lookup = {r["license"]: r for r in license_rules}

    all_findings = [evaluate_dependency(d, apps_by_id, vuln_lookup, license_lookup) for d in deps]
    risky = [f for f in all_findings if f["status"] == "risky"]
    risky.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "top_risky_dependencies": risky[:top_n],
        "summary": {
            "total_applications": len(applications),
            "total_dependencies": len(all_findings),
            "total_risky": len(risky),
            "total_clean": len(all_findings) - len(risky)
        }
    }


# ============================================================
# PART 5: TEST IT WHEN RUN DIRECTLY
# ============================================================
if __name__ == "__main__":
    report = get_ranked_report()
    print("Summary:", report["summary"])
    print("\nTop 5 riskiest dependencies:")
    for r in report["top_risky_dependencies"][:5]:
        print(f"  {r['app_name']:20s} {r['library_name']:20s} score={r['risk_score']:6.2f}  {[f['type'] for f in r['findings']]}")