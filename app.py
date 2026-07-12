from flask import Flask, render_template, send_file
import sys
import os
import time
import io
import csv

sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from risk_engine import get_ranked_report

app = Flask(__name__)


@app.route("/")
def home():

    report = get_ranked_report(top_n=10)

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
            "score": round(score, 2),
            "severity": severity
        })

    applications.sort(key=lambda x: x["score"], reverse=True)

    # ---- Chart data (Chart.js) ----
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for dep in report["top_risky_dependencies"]:
        sev = dep.get("severity", "MEDIUM")
        if sev in severity_counts:
            severity_counts[sev] += 1

    chart_data = {
        "pie_labels": ["Risky", "Clean"],
        "pie_values": [report["summary"]["total_risky"], report["summary"]["total_clean"]],
        "severity_labels": list(severity_counts.keys()),
        "severity_values": list(severity_counts.values()),
        "bar_labels": [a["name"] for a in applications[:8]],
        "bar_values": [a["score"] for a in applications[:8]],
    }

    return render_template(
        "index.html",
        summary=report["summary"],
        dependencies=report["top_risky_dependencies"],
        applications=applications,
        chart_data=chart_data
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
            "score": round(score, 2),
            "severity": severity
        })

    applications.sort(key=lambda x: x["score"], reverse=True)

    return render_template("applications.html", applications=applications)


@app.route("/dependencies")
def dependencies():
    report = get_ranked_report(top_n=100)
    return render_template("dependencies.html", dependencies=report["top_risky_dependencies"])


@app.route("/vulnerabilities")
def vulnerabilities():
    report = get_ranked_report(top_n=30)
    return render_template("vulnerabilities.html", dependencies=report["top_risky_dependencies"])


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


# ---- Real-time alert dashboard (Level 1 bonus) ----
@app.route("/api/live-alert")
def live_alert():
    report = get_ranked_report(top_n=500)
    risky_deps = [
        d for d in report["top_risky_dependencies"]
        if d["status"] == "risky" or d["status"] == "RISKY"
    ]

    if not risky_deps:
        return {"alert": None}

    index = int(time.time() // 8) % len(risky_deps)
    dep = risky_deps[index]

    return {
        "alert": {
            "id": index,
            "app_name": dep["app_name"],
            "library_name": dep["library_name"],
            "version": dep["version"],
            "risk_score": dep["risk_score"],
            "time": time.strftime("%H:%M:%S")
        }
    }


# ---- Dependency Graph page ----
@app.route("/graph")
def graph_page():
    return render_template("graph.html")


@app.route("/api/graph-data")
def graph_data():
    report = get_ranked_report(top_n=500)
    nodes = []
    edges = []
    seen = set()

    for dep in report["top_risky_dependencies"]:
        app_id = dep["app_name"]
        lib_id = f'{dep["library_name"]}@{dep["version"]}'

        if app_id not in seen:
            nodes.append({"id": app_id, "label": app_id, "color": "#2563eb", "shape": "box"})
            seen.add(app_id)

        if lib_id not in seen:
            is_risky = dep["status"] == "risky" or dep["status"] == "RISKY"
            color = "#ef4444" if is_risky else "#16a34a"
            nodes.append({"id": lib_id, "label": dep["library_name"], "color": color})
            seen.add(lib_id)

        edges.append({"from": app_id, "to": lib_id})

    return {"nodes": nodes, "edges": edges}


# ---- Blast Radius Simulator ----
@app.route("/api/simulate-cve/<library_name>")
def simulate_cve(library_name):
    report = get_ranked_report(top_n=500)

    affected = []
    for dep in report["top_risky_dependencies"]:
        if dep["library_name"].lower() == library_name.lower():
            affected.append({
                "app_name": dep["app_name"],
                "library_name": dep["library_name"],
                "version": dep["version"],
                "risk_score": dep["risk_score"],
                "path_type": "direct"
            })

    direct_count = len(affected)
    est_hours = direct_count * 2

    return {
        "library": library_name,
        "affected_apps": affected,
        "total_affected": direct_count,
        "estimated_remediation_hours": est_hours
    }


# ---- PDF Export ----
@app.route("/export/pdf")
def export_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as pdfcanvas

    report = get_ranked_report(top_n=50)
    buffer = io.BytesIO()
    c = pdfcanvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, height - 50, "Software Supply Chain Risk Report")

    c.setFont("Helvetica", 10)
    y = height - 90
    summary = report["summary"]
    c.drawString(40, y, f"Total Applications: {summary['total_applications']}")
    c.drawString(40, y - 15, f"Total Dependencies: {summary['total_dependencies']}")
    c.drawString(40, y - 30, f"Risky: {summary['total_risky']}   Clean: {summary['total_clean']}")

    y -= 60
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, y, "App")
    c.drawString(160, y, "Library")
    c.drawString(320, y, "Score")
    c.drawString(390, y, "Status")
    y -= 15
    c.setFont("Helvetica", 9)

    for dep in report["top_risky_dependencies"]:
        if y < 60:
            c.showPage()
            y = height - 50
        c.drawString(40, y, str(dep["app_name"])[:20])
        c.drawString(160, y, str(dep["library_name"])[:22])
        c.drawString(320, y, str(dep["risk_score"]))
        c.drawString(390, y, str(dep["status"]))
        y -= 14

    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="risk_report.pdf", mimetype="application/pdf")


# ---- CSV Export ----
@app.route("/export/csv")
def export_csv():
    report = get_ranked_report(top_n=500)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["app_name", "library_name", "version", "risk_score", "status"])
    writer.writeheader()
    for dep in report["top_risky_dependencies"]:
        writer.writerow({k: dep[k] for k in ["app_name", "library_name", "version", "risk_score", "status"]})

    mem = io.BytesIO(buffer.getvalue().encode())
    return send_file(mem, as_attachment=True, download_name="risk_report.csv", mimetype="text/csv")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)