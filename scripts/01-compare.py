#!/usr/bin/env python3
"""Build before-after.csv from two Prowler CSV exports.

Usage: python3 scripts/01-compare.py
Reads  evidence/01-posture/prowler-before/prowler-before.csv
       evidence/01-posture/prowler-after/prowler-after.csv
Writes evidence/01-posture/before-after.csv          (one row per check)
       evidence/01-posture/before-after-findings.csv (one row per check + resource)

Three things the first version got wrong, kept here so they are not reintroduced:
  1. It read raw-<phase>/, but the scans live in prowler-<phase>/.
  2. Prowler 5 CSV is semicolon-delimited. Parsed with commas, the whole header
     becomes one column, no CHECK_ID is found, and the script reports 0 checks.
  3. Prowler writes one row per (check, resource). Keying on CHECK_ID alone let the
     last resource read overwrite the others, so a check failing on one bucket and
     passing on another could show PASS. A check now FAILs if any resource fails.
"""
import csv
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = ROOT / "evidence" / "01-posture"

# Worst status wins when rolling resources up to one check.
RANK = {"FAIL": 3, "MANUAL": 2, "PASS": 1}


def load(phase):
    path = BASE / f"prowler-{phase}" / f"prowler-{phase}.csv"
    if not path.exists():
        sys.exit(f"missing file: {path}")
    checks, findings = {}, {}
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle, delimiter=";"):
            check = (row.get("CHECK_ID") or "").strip()
            status = (row.get("STATUS") or "").strip().upper()
            if not check or not status:
                continue
            resource = (row.get("RESOURCE_UID") or row.get("RESOURCE_NAME") or "").strip()
            region = (row.get("REGION") or "").strip()
            findings[(check, resource, region)] = status
            meta = {
                "service": row.get("SERVICE_NAME", ""),
                "severity": (row.get("SEVERITY") or "").upper(),
            }
            prev = checks.get(check)
            if prev is None or RANK.get(status, 0) > RANK.get(prev["status"], 0):
                checks[check] = {"status": status, **meta}
    if not checks:
        sys.exit(f"no findings parsed from {path} - wrong delimiter or empty export?")
    return checks, findings


def change_of(before, after):
    if before == "FAIL" and after == "PASS":
        return "fixed"
    if before == "PASS" and after == "FAIL":
        return "regressed"
    if before and not after:
        return "gone"        # resource deleted, or check not run
    if after and not before:
        return "new"
    if before != after:
        return "changed"
    return ""


before, before_f = load("before")
after, after_f = load("after")

ids = sorted(set(before) | set(after))
check_changes = Counter()
with (BASE / "before-after.csv").open("w", newline="") as handle:
    w = csv.writer(handle)
    w.writerow(["check_id", "service", "severity", "status_before", "status_after", "change"])
    for c in ids:
        b, a = before.get(c, {}), after.get(c, {})
        ch = change_of(b.get("status", ""), a.get("status", ""))
        check_changes[ch] += 1
        w.writerow([c, a.get("service") or b.get("service"),
                    a.get("severity") or b.get("severity"),
                    b.get("status", ""), a.get("status", ""), ch])

keys = sorted(set(before_f) | set(after_f))
finding_changes = Counter()
with (BASE / "before-after-findings.csv").open("w", newline="") as handle:
    w = csv.writer(handle)
    w.writerow(["check_id", "resource", "region", "status_before", "status_after", "change"])
    for k in keys:
        ch = change_of(before_f.get(k, ""), after_f.get(k, ""))
        finding_changes[ch] += 1
        w.writerow([*k, before_f.get(k, ""), after_f.get(k, ""), ch])


def tally(data, status):
    return sum(1 for v in data.values() if v == status)


def pct(data):
    p, f = tally(data, "PASS"), tally(data, "FAIL")
    return f"{100 * p / (p + f):.1f}%" if p + f else "n/a"


print("Findings (one per check + resource), MANUAL excluded from pass rate")
for label, data in (("before", before_f), ("after", after_f)):
    print(f"  {label:6}: {tally(data, 'FAIL'):4} FAIL  {tally(data, 'PASS'):4} PASS  "
          f"{tally(data, 'MANUAL'):3} MANUAL  pass rate {pct(data)}")
print("  changes:", dict(finding_changes))
print()
print("Checks (worst resource wins)")
bs = {k: v["status"] for k, v in before.items()}
as_ = {k: v["status"] for k, v in after.items()}
for label, data in (("before", bs), ("after", as_)):
    print(f"  {label:6}: {tally(data, 'FAIL'):4} FAIL  {tally(data, 'PASS'):4} PASS  "
          f"of {len(data)} checks")
print("  changes:", dict(check_changes))
print()
print("Written: evidence/01-posture/before-after.csv, before-after-findings.csv")
