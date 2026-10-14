#!/usr/bin/env python3
"""Rebuild the sweep CSV from the archived raw NVD responses and check it matches.

    python3 scripts/verify_from_raw.py

Applies the same filter as fetch_nvd_sweep.py (English description matches \\bmcp\\b|model context
protocol, case-insensitive; Rejected records dropped; published 2026-01-01..2026-09-25) to
data/raw_2026-09-26/*.json and compares id, published, cvss, cwe and query with
data/mcp_cves_nvd_2026-01-01_to_2026-09-25.csv. The product column comes from CVE.org, not NVD,
so it is not checked here. Exits non-zero on any mismatch.
"""
import csv, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw_2026-09-26")
CSV = os.path.join(ROOT, "data", "mcp_cves_nvd_2026-01-01_to_2026-09-25.csv")
START, END = "2026-01-01", "2026-09-25"
RX = re.compile(r"\bmcp\b|model context protocol", re.I)

recs = {}
for kw in ["MCP", "Model Context Protocol"]:
    for v in json.load(open(os.path.join(RAW, "raw_" + kw.replace(" ", "_") + ".json"))):
        recs.setdefault(v["cve"]["id"], {"c": v["cve"], "kw": set()})["kw"].add(kw)

rebuilt = {}
for i, x in recs.items():
    c = x["c"]
    if c.get("vulnStatus") == "Rejected":
        continue
    d = " ".join(z["value"] for z in c["descriptions"] if z["lang"] == "en")
    if not RX.search(d):
        continue
    pub = c["published"][:10]
    if not (START <= pub <= END):
        continue
    m = c.get("metrics", {})
    cv = ""
    for k in ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30"]:
        if m.get(k):
            cv = str(m[k][0]["cvssData"]["baseScore"]); break
    cw = "/".join(z["value"] for w in c.get("weaknesses", []) for z in w["description"] if z["value"].startswith("CWE-"))
    rebuilt[i] = (pub, cv, cw, "+".join(sorted(x["kw"])))

stored = {}
for r in csv.DictReader(open(CSV)):
    stored[r["id"]] = (r["published"], r["cvss"], r["cwe"], r["query"])

bad = 0
for i in sorted(set(rebuilt) | set(stored)):
    a, b = rebuilt.get(i), stored.get(i)
    if a != b:
        bad += 1
        print("MISMATCH", i, "raw:", a, "csv:", b)
print(f"raw keyword hits after filter: {len(rebuilt)}; CSV rows: {len(stored)}; mismatches: {bad}")
sys.exit(1 if bad else 0)
