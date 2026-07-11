import json
import csv
import os
from datetime import datetime


# ============================================================
# LOAD SBOM DATA
# ============================================================

def load_data():

    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "..", "data")

    with open(os.path.join(data_dir, "applications.json")) as f:
        applications = json.load(f)

    with open(os.path.join(data_dir, "vulnerability_db.json")) as f:
        vulnerabilities = json.load(f)

    with open(os.path.join(data_dir, "license_rules.json")) as f:
        licenses = json.load(f)

    with open(os.path.join(data_dir, "sbom_dependencies.csv")) as f:
        dependencies = list(csv.DictReader(f))


    return (
        applications,
        vulnerabilities,
        licenses,
        dependencies
    )



# ============================================================
# VERSION CHECK
# ============================================================

def version_is_affected(version, affected):

    try:

        operator = affected[0]

        target = tuple(
            int(x)
            for x in affected[1:].split(".")
        )

        current = tuple(
            int(x)
            for x in version.split(".")
        )


        if operator == "<":
            return current < target


        return True


    except:

        return True




# ============================================================
# SEVERITY CALCULATION
# ============================================================

def get_severity(score):

    if score >= 25:
        return "CRITICAL"

    elif score >= 15:
        return "HIGH"

    elif score >= 8:
        return "MEDIUM"

    else:
        return "LOW"





# ============================================================
# SECURITY RECOMMENDATION
# ============================================================

def generate_recommendation(findings):

    recommendations = []


    for item in findings:

        if item["type"] == "vulnerability":

            recommendations.append(
                "Upgrade dependency to patched version"
            )


        elif item["type"] == "license_conflict":

            recommendations.append(
                "Review open-source license compliance"
            )


        elif item["type"] == "unmaintained":

            recommendations.append(
                "Replace outdated dependency with maintained alternative"
            )


        elif item["type"] == "license_unknown":

            recommendations.append(
                "Verify dependency license information"
            )


    return list(set(recommendations))





# ============================================================
# ANALYZE DEPENDENCY
# ============================================================

def evaluate_dependency(
        dep,
        apps,
        vuln_lookup,
        license_lookup
):


    app = apps[dep["app_id"]]


    risk_score = 0

    findings = []



    # ---------------- Vulnerability ----------------


    matched = None


    for vuln in vuln_lookup.get(
            dep["library_name"],
            []
    ):


        if version_is_affected(
                dep["version"],
                vuln["affected_versions"]
        ):

            if (
                matched is None
                or vuln["cvss_score"]
                >
                matched["cvss_score"]
            ):

                matched = vuln



    if matched:


        risk_score += matched["cvss_score"]


        if not matched["patch_available"]:
            risk_score += 1.5


        if matched.get(
                "exploit_known_in_wild"
        ):

            risk_score += 2.5



        findings.append({

            "type":
            "vulnerability",

            "detail":
            f"{matched['cve_id']} CVSS {matched['cvss_score']}"

        })





    # ---------------- License ----------------


    license = dep["license"]


    rule = license_lookup.get(
        license
    )


    if (
        rule
        and
        not rule["compatible_with_proprietary"]
        and
        app["distributed_externally"]
    ):


        risk_score += 8


        findings.append({

            "type":
            "license_conflict",

            "detail":
            f"{license} compliance risk"

        })



    elif license == "UNKNOWN":


        risk_score += 5


        findings.append({

            "type":
            "license_unknown",

            "detail":
            "License information unavailable"

        })






    # ---------------- Maintenance ----------------


    last_update = datetime.strptime(
        dep["last_updated"],
        "%Y-%m-%d"
    )


    days_old = (
        datetime.today()
        -
        last_update
    ).days



    if days_old > 730:


        risk_score += 3


        findings.append({

            "type":
            "unmaintained",

            "detail":
            f"No update for {days_old} days"

        })





    # ---------------- Business Criticality ----------------


    multiplier = {

        "high":1.3,

        "medium":1,

        "low":0.8

    }.get(
        app["criticality"],
        1
    )



    final_score = round(
        risk_score * multiplier,
        2
    )



    severity = get_severity(
        final_score
    )



    return {


        "app_name":
        app["name"],


        "library_name":
        dep["library_name"],


        "version":
        dep["version"],


        "risk_score":
        final_score,


        "severity":
        severity,


        "findings":
        findings,


        "recommendations":
        generate_recommendation(
            findings
        ),


        "status":
        "risky"
        if findings
        else
        "clean"

    }





# ============================================================
# GENERATE REPORT
# ============================================================


# ============================================================
# GENERATE REPORT
# ============================================================

def get_ranked_report(top_n=20):

    applications, vuln_db, licenses, deps = load_data()

    apps = {
        a["app_id"]: a
        for a in applications
    }

    vuln_lookup = {}

    for v in vuln_db:
        vuln_lookup.setdefault(
            v["library_name"],
            []
        ).append(v)

    license_lookup = {
        l["license"]: l
        for l in licenses
    }

    results = []

    for dep in deps:

        results.append(

            evaluate_dependency(
                dep,
                apps,
                vuln_lookup,
                license_lookup
            )

        )

    risky = [

        r

        for r in results

        if r["status"] == "risky"

    ]

    risky.sort(

        key=lambda x: x["risk_score"],

        reverse=True

    )

    # ===========================================
    # APPLICATION RISK RANKING
    # ===========================================

    application_scores = {}

    for item in risky:

        app = item["app_name"]

        application_scores.setdefault(app, 0)

        application_scores[app] += item["risk_score"]

    application_ranking = []

    for app, score in application_scores.items():

        application_ranking.append({

            "app_name": app,

            "total_risk": round(score, 2)

        })

    application_ranking.sort(

        key=lambda x: x["total_risk"],

        reverse=True

    )

    # ===========================================
    # FINAL REPORT
    # ===========================================

    return {

        "top_risky_dependencies": risky[:top_n],

        "application_ranking": application_ranking,

        "summary": {

            "total_applications": len(applications),

            "total_dependencies": len(results),

            "total_risky": len(risky),

            "total_clean": len(results) - len(risky)

        }

    }


# ============================================================
# TEST





# ============================================================
# TEST
# ============================================================


if __name__=="__main__":


    report=get_ranked_report()


    print(report["summary"])



    for item in report["top_risky_dependencies"][:5]:


        print(

            item["app_name"],

            item["library_name"],

            item["risk_score"],

            item["severity"]

        )