#!/usr/bin/env python3
"""Mask identifying values in GuardDuty findings and CloudTrail records before they become evidence.

Reads JSON on stdin, writes masked JSON on stdout. Real findings, unlike samples, carry the caller's
public IP address, where that address is, a temporary access key ID, the role's unique ID and the
Identity Center directory - none of which belongs in a public repository.

    aws guardduty get-findings ... --output json | python3 scripts/02-redact.py > evidence/.../finding.json

What is masked, and how it reads afterwards:
  12-digit account ID                 58********27
  access key IDs (AKIA/ASIA)          ASIA****************
  IAM unique IDs (AROA/AIDA/...)      AROA****************
  IPv4 addresses, except the ranges reserved for documentation     x.x.x.x
  Identity Center directory, instance and user IDs                 d-**********, ssoins-****, ****
  location and network owner of an IP address (city, coordinates, ISP, ASN)   "masked"
"""
import json
import re
import sys

DOC_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")
GEO_KEYS = {"city", "cityname", "lat", "lon", "geolocation", "isp", "org", "asn", "asnorg"}
ID_KEYS = {"userid"}  # Identity Center user ID inside onBehalfOf


def mask_text(s: str) -> str:
    s = re.sub(r"(?<![0-9])[0-9]{12}(?![0-9])", "58********27", s)
    s = re.sub(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", r"\1****************", s)
    s = re.sub(r"\b(AIDA|AROA|AGPA|ANPA|AIPA|APKA|ASCA)[A-Z0-9]{16,17}\b", r"\1****************", s)
    s = re.sub(r"\bd-[0-9a-f]{10}\b", "d-**********", s)
    s = re.sub(r"\bssoins-[0-9a-f]{16}\b", "ssoins-****************", s)

    def ip(m):
        return m.group(0) if m.group(0).startswith(DOC_RANGES) else "x.x.x.x"

    return re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", ip, s)


def walk(node, key=""):
    k = key.lower()
    if isinstance(node, dict):
        return {a: walk(b, a) for a, b in node.items()}
    if isinstance(node, list):
        return [walk(x, key) for x in node]
    if k in GEO_KEYS or k in ID_KEYS:
        return "masked" if not isinstance(node, dict) else node
    if isinstance(node, str):
        # Some fields hold JSON as a string (CloudTrailEvent, AdditionalInfo.Value): mask inside it too.
        if node[:1] in "{[":
            try:
                return json.dumps(walk(json.loads(node)))
            except ValueError:
                pass
        return mask_text(node)
    return node


def main():
    data = json.load(sys.stdin)
    # Location blocks are dicts; replace the whole block rather than each coordinate.
    def drop_geo(n):
        if isinstance(n, dict):
            return {a: ("masked" if a.lower() in ("geolocation", "city", "organization") else drop_geo(b))
                    for a, b in n.items()}
        if isinstance(n, list):
            return [drop_geo(x) for x in n]
        return n
    json.dump(walk(drop_geo(data)), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
