from flask import Flask, render_template
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from risk_engine import get_ranked_report

app = Flask(__name__)

@app.route("/")
def home():

    report = get_ranked_report(top_n=10)

    return render_template(
        "index.html",
        summary=report["summary"],
        dependencies=report["top_risky_dependencies"]
    )

if __name__ == "__main__":
    app.run(debug=True)