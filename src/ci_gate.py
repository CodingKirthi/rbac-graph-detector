import csv
import sys
from pathlib import Path

summary_file = Path("results/summary.csv")

if not summary_file.exists():
    print("summary.csv not found")
    sys.exit(1)

critical_found = False

with summary_file.open("r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get("detected_overall_severity") == "CRITICAL":
            critical_found = True
            print(f"CRITICAL finding in scenario: {row.get('scenario')}")

if critical_found:
    print("Build failed: CRITICAL RBAC findings detected.")
    sys.exit(1)

print("No CRITICAL findings detected.")
sys.exit(0)