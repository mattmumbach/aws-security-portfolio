#!/usr/bin/env python3
"""Pull one GuardDuty finding and the CloudTrail activity behind it, and print a triage sheet.

This does by script what an analyst otherwise does by hand in two consoles: read the finding, take
the access key and API name from it, find the matching CloudTrail record, compare the two, and list
everything else that credential did around the same time. It gathers evidence; the verdict is still
the analyst's.

    python3 scripts/02-triage.py Stealth:IAMUser/CloudTrailLoggingDisabled
    python3 scripts/02-triage.py latest
    python3 scripts/02-triage.py <finding-type> --window 10 > evidence/02-detection/triage-sheet.txt

The argument is a finding type, or "latest" for the most recently created finding. --window is the
number of minutes either side of the event to search in CloudTrail (default 5).

Read-only. Uses the AWS CLI with whatever profile and region the shell has. Everything printed is
masked the same way as scripts/02-redact.py (account ID, key IDs, role IDs, IP addresses), so the
output can be saved as evidence. IP addresses are compared before they are masked.
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone


def aws(*args):
    out = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"aws {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return json.loads(out.stdout or "null")


def mask(s):
    s = str(s)
    s = re.sub(r"(?<![0-9])[0-9]{12}(?![0-9])", "58********27", s)
    s = re.sub(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", r"\1****************", s)
    s = re.sub(r"\b(AIDA|AROA)[A-Z0-9]{16,17}\b", r"\1****************", s)
    s = re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
               lambda m: m.group(0) if m.group(0).startswith(("192.0.2.", "198.51.100.", "203.0.113.")) else "x.x.x.x", s)
    return s


def row(label, value):
    print(f"  {label:<26} {mask(value)}")


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("finding", help='finding type, or "latest"')
    ap.add_argument("--window", type=int, default=5, help="minutes either side of the event (default 5)")
    a = ap.parse_args()

    detector = aws("guardduty", "list-detectors")["DetectorIds"][0]
    if a.finding == "latest":
        ids = aws("guardduty", "list-findings", "--detector-id", detector,
                  "--sort-criteria", '{"AttributeName":"createdAt","OrderBy":"DESC"}')["FindingIds"]
    else:
        crit = json.dumps({"Criterion": {"type": {"Eq": [a.finding]}}})
        ids = aws("guardduty", "list-findings", "--detector-id", detector, "--finding-criteria", crit,
                  "--sort-criteria", '{"AttributeName":"createdAt","OrderBy":"DESC"}')["FindingIds"]
    if not ids:
        sys.exit(f"no finding matches {a.finding!r}")
    f = aws("guardduty", "get-findings", "--detector-id", detector, "--finding-ids", ids[0])["Findings"][0]

    svc, res = f["Service"], f["Resource"]
    key = res.get("AccessKeyDetails", {})
    call = svc.get("Action", {}).get("AwsApiCallAction", {})
    remote_ip = call.get("RemoteIpDetails", {}).get("IpAddressV4")
    sample = "sample" in (svc.get("AdditionalInfo", {}).get("Value") or "").lower()

    print("TRIAGE SHEET")
    print(f"generated {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} by scripts/02-triage.py\n")

    print("1. What happened, and how bad (GuardDuty finding)")
    row("type", f["Type"])
    row("title", f.get("Title", ""))
    row("severity", f["Severity"])
    row("sample finding", "yes" if sample else "no")
    row("api called", f"{call.get('Api')} on {call.get('ServiceName')}")
    row("event first seen", svc.get("EventFirstSeen"))
    row("finding created", f["CreatedAt"])
    if svc.get("EventFirstSeen"):
        delay = parse_time(f["CreatedAt"]) - parse_time(svc["EventFirstSeen"])
        row("time to detect", f"{int(delay.total_seconds() // 60)} min {int(delay.total_seconds() % 60)} s")

    print("\n2. Who and from where, according to the finding")
    row("principal", key.get("UserName"))
    row("principal type", key.get("UserType"))
    row("access key id", key.get("AccessKeyId"))
    row("remote ip", remote_ip)

    if not key.get("AccessKeyId") or not svc.get("EventFirstSeen"):
        print("\nNo access key or event time in the finding; nothing to look up in CloudTrail.")
        return

    t0 = parse_time(svc["EventFirstSeen"])
    start, end = t0 - timedelta(minutes=a.window), t0 + timedelta(minutes=a.window)
    events = aws("cloudtrail", "lookup-events",
                 "--lookup-attributes", f"AttributeKey=AccessKeyId,AttributeValue={key['AccessKeyId']}",
                 "--start-time", start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ"))["Events"]
    records = sorted((json.loads(e["CloudTrailEvent"]) for e in events), key=lambda r: r["eventTime"])

    print(f"\n3. The matching CloudTrail record ({call.get('Api')})")
    match = [r for r in records if r["eventName"] == call.get("Api")]
    if not match:
        print(f"  NOT FOUND: CloudTrail has no {call.get('Api')} call by this access key within "
              f"{a.window} minutes of the event. The finding is not corroborated.")
    for r in match:
        u = r.get("userIdentity", {})
        row("event time", r["eventTime"])
        row("caller", u.get("arn"))
        row("session name", (u.get("arn") or "").split("/")[-1])
        row("identity center user", "recorded (onBehalfOf present)" if "onBehalfOf" in u else "not recorded")
        row("source ip", r.get("sourceIPAddress"))
        row("source ip = finding ip", "YES" if r.get("sourceIPAddress") == remote_ip else "NO")
        row("tool (user agent)", (r.get("userAgent") or "")[:38])
        row("command (user agent)", ((r.get("userAgent") or "").split("md/command#") + [""])[1])
        row("result", r.get("errorCode") or "succeeded (no error code)")
        row("request", json.dumps(r.get("requestParameters")))

    print(f"\n4. Everything this access key did, {start:%H:%M:%S} to {end:%H:%M:%S} UTC ({len(records)} calls)")
    ips = {r.get("sourceIPAddress") for r in records}
    users = {(r.get("userIdentity", {}).get("arn") or "").split("/")[-1] for r in records}
    for r in records:
        flag = "" if r.get("readOnly", True) else "   <- changes something"
        print(f"  {r['eventTime'][11:19]}  {r['eventName']:<28} {r['eventSource'].split('.')[0]:<12}{flag}")
    row("distinct source ips", len(ips))
    row("distinct session names", ", ".join(sorted(users)))
    row("calls that change something", ", ".join(r["eventName"] for r in records if not r.get("readOnly", True)) or "none")

    print("\nVerdict (analyst): ______  true positive / benign or expected / false positive")


if __name__ == "__main__":
    main()
