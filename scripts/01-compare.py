#!/usr/bin/env python3
"""Build before-after.csv from two Prowler CSV exports.

Usage: python3 scripts/01-compare.py
Reads  evidence/01-posture/raw-before/*.csv
       evidence/01-posture/raw-after/*.csv
Writes evidence/01-posture/before-after.csv
"""
import csv
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = ROOT / "evidence" / "01-posture"


def load(phase):
    findings = {}
    directory = BASE / f"raw-{phase}"
    if not directory.exists():
        sys.exit(f"missing directory: {directory}")
    for path in sorted(directory.glob("*.csv")):
        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            for row in csv.DictReader(handle):
                row = {(k or "").strip().upper(): (v or "").strip() for k, v in row.items()}
                check = row.get("CHECK_ID") or row.get("CHECKID") or row.get("CHECK")
                status = row.get("STATUS") or row.get("STATUS_EXTENDED")
                if not check or not status:
                    continue
                findings[check] = {
                    "status": status.upper(),
                    "severity": (row.get("SEVERITY") or "").upper(),
                    "service": row.get("SERVICE_NAME") or row.get("SERVICE") or "",
                    "title": row.get("CHECK_TITLE") or row.get("CHECK") or "",
                }
    return findings


before = load("before")
after = load("after")
checks = sorted(set(before) | set(after))

out = BASE / "before-after.csv"
closed = opened = 0
with out.open("w", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(["check_id", "service", "severity", "status_before", "status_after", "change"])
    for check in checks:
        b = before.get(check, {})
        a = after.get(check, {})
        sb, sa = b.get("status", ""), a.get("status", "")
        change = ""
        if sb == "FAIL" and sa == "PASS":
            change, closed = "fixed", closed + 1
        elif sb == "PASS" and sa == "FAIL":
            change, opened = "regressed", opened + 1
        elif sb and sa and sb != sa:
            change = "changed"
        writer.writerow([check, a.get("service") or b.get("service"),
                         a.get("severity") or b.get("severity"), sb, sa, change])


def tally(data, status):
    return sum(1 for v in data.values() if v["status"] == status)


print(f"checks compared : {len(checks)}")
print(f"PASS before     : {tally(before, 'PASS')}")
print(f"PASS after      : {tally(after, 'PASS')}")
print(f"FAIL before     : {tally(before, 'FAIL')}")
print(f"FAIL after      : {tally(after, 'FAIL')}")
print(f"fixed           : {closed}")
print(f"regressed       : {opened}")
print(f"written         : {out}")
