from flask import Flask, render_template
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from risk_engine import get_ranked_report

app = Flask(__name__)


@app.route("/")
def home():

    report = get_ranked_report(top_n=10)


    # Calculate application wise risk

    app_risk = {}


    for dep in report["top_risky_dependencies"]:

        app_name = dep["app_name"]

        if app_name not in app_risk:
            app_risk[app_name] = 0


        app_risk[app_name] += dep["risk_score"]



    applications = []


    for name, score in app_risk.items():

        if score >= 80:
            severity = "CRITICAL"

        elif score >= 50:
            severity = "HIGH"

        else:
            severity = "MEDIUM"


        applications.append({

            "name": name,

            "score": round(score,2),

            "severity": severity

        })


    # Sort highest risk first

    applications.sort(
        key=lambda x:x["score"],
        reverse=True
    )


    return render_template(

        "index.html",

        summary=report["summary"],

        dependencies=report["top_risky_dependencies"],

        applications=applications

    )

@app.route("/applications")
def applications():

    report = get_ranked_report(top_n=20)

    app_risk = {}


    for dep in report["top_risky_dependencies"]:

        name = dep["app_name"]

        if name not in app_risk:
            app_risk[name] = 0


        app_risk[name] += dep["risk_score"]



    applications = []


    for name, score in app_risk.items():

        if score >= 80:
            severity = "CRITICAL"

        elif score >= 50:
            severity = "HIGH"

        else:
            severity = "MEDIUM"


        applications.append({

            "name": name,

            "score": round(score,2),

            "severity": severity

        })



    applications.sort(
        key=lambda x:x["score"],
        reverse=True
    )



    return render_template(
        "applications.html",
        applications=applications
    )
@app.route("/dependencies")
def dependencies():

    report = get_ranked_report(top_n=100)

    return render_template(
        "dependencies.html",
        dependencies=report["top_risky_dependencies"]
    )
@app.route("/vulnerabilities")
def vulnerabilities():

    report = get_ranked_report(top_n=30)

    return render_template(
        "vulnerabilities.html",
        dependencies=report["top_risky_dependencies"]
    )
@app.route("/compliance")
def compliance():

    report = get_ranked_report(top_n=20)

    return render_template(
        "compliance.html",
        summary=report["summary"],
        dependencies=report["top_risky_dependencies"]
    )
@app.route("/reports")
def reports():

    report = get_ranked_report(top_n=20)

    return render_template(
        "reports.html",
        summary=report["summary"],
        application_ranking=report["application_ranking"]
    )
if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000)