import json
import random

random.seed(42)  # keeps results same every time you run this

# Fake library names - keep this list, you'll reuse it in Step 4
LIBRARIES = [
    "log-core", "json-parser", "http-client", "crypto-lib", "auth-kit",
    "yaml-loader", "xml-reader", "cache-engine", "queue-manager", "orm-toolkit",
    "template-engine", "config-loader", "validator-lib", "data-parser", "serializer-kit",
    "scheduler-core", "router-lib", "middleware-kit", "session-manager", "util-commons",
    "log-adapter", "json-bridge", "http-connector", "crypto-engine", "auth-connector",
    "yaml-parser", "xml-adapter", "cache-client", "queue-connector", "orm-bridge"
]

def get_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

vuln_db = []

# Plant ONE deliberate "Log4j-style" critical vulnerability - this is your demo story
vuln_db.append({
    "cve_id": "CVE-2024-10001",
    "library_name": "log-core",
    "affected_versions": "<4.0.0",
    "cvss_score": 10.0,
    "severity": "CRITICAL",
    "patch_available": True,
    "exploit_known_in_wild": True
})

# Generate 149 more random CVEs
for i in range(1, 150):
    score = round(random.uniform(2.0, 10.0), 1)
    vuln_db.append({
        "cve_id": f"CVE-2024-{10000+i}",
        "library_name": random.choice(LIBRARIES),
        "affected_versions": "<3.0.0",
        "cvss_score": score,
        "severity": get_severity(score),
        "patch_available": random.choice([True, True, True, False]),
        "exploit_known_in_wild": score >= 9.0 and random.choice([True, False])
    })

with open("../data/vulnerability_db.json", "w") as f:
    json.dump(vuln_db, f, indent=2)

print(f"Generated {len(vuln_db)} vulnerabilities successfully")