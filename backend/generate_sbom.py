import csv
import random
from datetime import datetime, timedelta

random.seed(42)

APP_IDS = ["APP-001", "APP-002", "APP-003", "APP-004", "APP-005",
           "APP-006", "APP-007", "APP-008", "APP-009", "APP-010"]

# Same library list as generate_vulns.py - MUST match exactly
LIBRARIES = [
    "log-core", "json-parser", "http-client", "crypto-lib", "auth-kit",
    "yaml-loader", "xml-reader", "cache-engine", "queue-manager", "orm-toolkit",
    "template-engine", "config-loader", "validator-lib", "data-parser", "serializer-kit",
    "scheduler-core", "router-lib", "middleware-kit", "session-manager", "util-commons",
    "log-adapter", "json-bridge", "http-connector", "crypto-engine", "auth-connector",
    "yaml-parser", "xml-adapter", "cache-client", "queue-connector", "orm-bridge"
]

LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "LGPL-2.1",
            "LGPL-3.0", "MPL-2.0", "GPL-2.0", "GPL-3.0", "AGPL-3.0", "UNKNOWN"]

def random_version():
    return f"{random.randint(0,4)}.{random.randint(0,9)}.{random.randint(0,9)}"

def random_date():
    # some libraries will be 1-1000 days old, crossing the 2-year (730 day) "unmaintained" line
    days_ago = random.randint(1, 1000)
    return (datetime.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")

rows = []
dep_counter = 1

for app_id in APP_IDS:
    # each app gets 50 dependencies
    chosen_libs = [random.choice(LIBRARIES) for _ in range(50)]

    # make sure "log-core" (our planted critical vuln) appears in every app at least once
    if "log-core" not in chosen_libs:
        chosen_libs[0] = "log-core"

    for idx, lib in enumerate(chosen_libs):
        rows.append({
            "dependency_id": f"DEP-{dep_counter:04d}",
            "app_id": app_id,
            "library_name": lib,
            "version": random_version(),
            "license": random.choice(LICENSES),
            "is_transitive": idx >= 15,   # first 15 = direct deps, rest = transitive
            "last_updated": random_date()
        })
        dep_counter += 1

with open("../data/sbom_dependencies.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} dependency rows successfully")