import csv
from risk_engine import get_ranked_report, load_data, evaluate_dependency

def load_labels():
    with open("../data/dependency_labels.csv") as f:
        return {row["dependency_id"]: row["risk_status"] for row in csv.DictReader(f)}


def run_full_engine():
    """Re-run the engine on every single dependency (not just top N)."""
    applications, vuln_db, license_rules, deps = load_data()
    apps_by_id = {a["app_id"]: a for a in applications}

    vuln_lookup = {}
    for v in vuln_db:
        vuln_lookup.setdefault(v["library_name"], []).append(v)
    license_lookup = {r["license"]: r for r in license_rules}

    all_findings = [evaluate_dependency(d, apps_by_id, vuln_lookup, license_lookup) for d in deps]
    return all_findings


def evaluate():
    labels = load_labels()
    all_findings = run_full_engine()

    tp = fp = fn = tn = 0

    for f in all_findings:
        actual = labels[f["dependency_id"]]
        predicted = f["status"]

        if predicted == "risky" and actual == "risky":
            tp += 1
        elif predicted == "risky" and actual == "clean":
            fp += 1
        elif predicted == "clean" and actual == "risky":
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0

    print("=== Self-Evaluation Results ===")
    print(f"True Positives:  {tp}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Negatives:  {tn}")
    print()
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1 Score:  {f1:.2%}")
    print(f"False Positive Rate: {false_positive_rate:.2%}  (target from problem statement: <20%)")


if __name__ == "__main__":
    evaluate()