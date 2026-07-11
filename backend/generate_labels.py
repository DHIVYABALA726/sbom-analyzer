import json
import csv
from datetime import datetime

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


def version_is_affected(version, affected_expr):
    try:
        op = affected_expr[0]
        target = tuple(int(x) for x in affected_expr[1:].split("."))
        current = tuple(int(x) for x in version.split("."))
        if op == "<":
            return current < target
        return True
    except Exception:
        return True


def build_ground_truth():
    applications, vuln_db, license_rules, deps = load_data()
    apps_by_id = {a["app_id"]: a for a in applications}

    vuln_lookup = {}
    for v in vuln_db:
        vuln_lookup.setdefault(v["library_name"], []).append(v)

    license_lookup = {r["license"]: r for r in license_rules}

    labels = []
    for dep in deps:
        app = apps_by_id[dep["app_id"]]

        # same detection logic as risk_engine.py - this IS the "correct answer"
        is_vulnerable = any(
            version_is_affected(dep["version"], v["affected_versions"])
            for v in vuln_lookup.get(dep["library_name"], [])
        )

        rule = license_lookup.get(dep["license"])
        is_license_issue = (
            (rule and not rule["compatible_with_proprietary"] and app["distributed_externally"] == True)
            or dep["license"] == "UNKNOWN"
        )

        days_old = (datetime.today() - datetime.strptime(dep["last_updated"], "%Y-%m-%d")).days
        is_unmaintained = days_old > 730

        is_risky = is_vulnerable or is_license_issue or is_unmaintained

        labels.append({
            "dependency_id": dep["dependency_id"],
            "risk_status": "risky" if is_risky else "clean"
        })

    with open("../data/dependency_labels.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["dependency_id", "risk_status"])
        writer.writeheader()
        writer.writerows(labels)

    print(f"Generated {len(labels)} ground truth labels")


if __name__ == "__main__":
    build_ground_truth()