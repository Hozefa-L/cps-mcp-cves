#!/usr/bin/env python3
"""Reproduce every number in Sec. 4.2 / Fig. 2 / Table 2 (T2 row) from the NVD sweep.

    python3 scripts/make_fig2.py

Inputs : data/mcp_cves_nvd_2026-01-01_to_2026-09-25.csv   (the sweep; see RECIPE below)
         data/nvd_sweep_exclusions.csv                     (keyword hits that are not the protocol)
         data/cwe_families.csv                             (explicit CWE -> family mapping)
Outputs: results/fig2_counts.csv                           (family x period table)
         results/fig2_summary.txt                          (all prose numbers)
         results/component_classes.csv                     (per-product component decisions)
         results/fig2_cve_families.pdf/.png                (the figure)

RECIPE (re-run 2026-09-26; the same recipe reproduces the 3 Sep sweep's 408 records exactly):
  1. NVD API 2.0, /rest/json/cves/2.0, keywordSearch=MCP and, separately,
     keywordSearch="Model Context Protocol", pubStartDate/pubEndDate in windows of at most
     120 days (1 Jan-30 Apr, 1 May-28 Aug, 29 Aug-25 Sep 2026), union of the two result sets.
     (The 3 Sep sweep ran the MCP query only, which misses records that write out the name.)
  2. Keep records whose English description matches  \bmcp\b|model context protocol
     (case-insensitive), drop Rejected records, then drop the ids in nvd_sweep_exclusions.csv.
  3. cvss = first-listed CVSS v3.1 base score, else first-listed v4.0, else v3.0 (NVD field order).
     cwe  = every CWE-* in the weaknesses array, in NVD order, joined by "/".
     product = first containers.cna.affected vendor:product in the CVE.org record
     (https://cveawg.mitre.org/api/cve/<id>); "undefined:undefined" when the CNA gave none.

Rule (as stated in the Fig. 2 caption): each record is assigned to the family of
its FIRST-listed CWE; the family membership is the table in cwe_families.csv.
"""
import logging
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
HERE = os.path.join(ROOT, "results")   # all outputs
os.makedirs(HERE, exist_ok=True)
CSV = os.path.join(DATA, "mcp_cves_nvd_2026-01-01_to_2026-09-25.csv")
EXCL = os.path.join(DATA, "nvd_sweep_exclusions.csv")
FAM = os.path.join(DATA, "cwe_families.csv")
FIGDIR = HERE

df = pd.read_csv(CSV)
excl = pd.read_csv(EXCL)
n_raw = len(df)
df = df[~df["id"].isin(excl["id"])].copy()
df["published"] = pd.to_datetime(df["published"])
df["month"] = df["published"].dt.month
df["first_cwe"] = df["cwe"].fillna("").str.split("/").str[0].str.strip()

fam = pd.read_csv(FAM)
order = fam["family"].tolist()
lookup = {}
for _, r in fam.iterrows():
    if isinstance(r["cwes"], str):
        for c in r["cwes"].split(";"):
            assert c not in lookup, f"{c} listed twice"
            lookup[c] = r["family"]
df["family"] = df["first_cwe"].map(lookup).fillna("Other")

PERIODS = [("Jan-Apr", 1, 4), ("May-Aug", 5, 8), ("1-25 Sep", 9, 9)]
parts = {name: df[(df.month >= a) & (df.month <= b)] for name, a, b in PERIODS}
tab = pd.DataFrame({name: p.family.value_counts().reindex(order, fill_value=0) for name, p in parts.items()})
tab["Total"] = tab.sum(axis=1)
tab.to_csv(os.path.join(HERE, "fig2_counts.csv"))
for name, p in parts.items():
    assert tab[name].sum() == len(p)
assert tab["Total"].sum() == len(df)

# ------------------------------------------------------------------ prose numbers
def sev(c):
    if pd.isna(c):
        return "unscored"
    return "critical" if c >= 9.0 else "high" if c >= 7.0 else "medium" if c >= 4.0 else "low"
sevc = df.cvss.apply(sev).value_counts()
official = df[df["product"].str.startswith("modelcontextprotocol:")]
old_window = df[df.published <= "2026-08-28"]
lines = []
P = lines.append
P(f"records total: {len(df)}  (raw keyword hits {n_raw}, excluded {n_raw - len(df)} non-protocol hits)")
P("by period: " + ", ".join(f"{k}={len(v)}" for k, v in parts.items()))
P(f"1 Jan-28 Aug under this recipe: {len(old_window)} (3 Sep sweep: 408)")
P("by query: " + ", ".join(f"{k}={v}" for k, v in df["query"].value_counts().items()))
P("monthly: " + ", ".join(f"{m}={n}" for m, n in df.month.value_counts().sort_index().items()))
P("severity: " + ", ".join(f"{k}={sevc.get(k,0)}" for k in ["critical", "high", "medium", "low", "unscored"]))
P(f"official modelcontextprotocol:* records: {len(official)}  ({official['product'].value_counts().to_dict()})")
P("official records by month: " + ", ".join(f"{m}={n}" for m, n in official.month.value_counts().sort_index().items()))
P("")
P("family table (first-listed CWE rule, membership in cwe_families.csv):")
P(tab.to_string())
P("")
e = parts["Jan-Apr"]
P("Sec. 4.2 prose: Jan-Apr injection={} of {}, SSRF={}, AuthN/AuthZ={}, traversal={}".format(
    tab.loc["Injection", "Jan-Apr"], len(e), tab.loc["SSRF", "Jan-Apr"], tab.loc["AuthN/AuthZ", "Jan-Apr"], tab.loc["Traversal", "Jan-Apr"]))
P("            full window: AuthN/AuthZ={} vs injection={}".format(tab.loc["AuthN/AuthZ", "Total"], tab.loc["Injection", "Total"]))
P("Table 2 T2 row (injection / traversal / SSRF / query inj.): {} / {} / {} / {}".format(
    tab.loc["Injection", "Total"], tab.loc["Traversal", "Total"], tab.loc["SSRF", "Total"], tab.loc["Query inj.", "Total"]))
P("")
oth = df[df.family == "Other"].first_cwe.value_counts().sort_index().sort_values(ascending=False, kind="stable")  # ties by CWE id
P("records whose first CWE fell into Other: " + ", ".join(f"{k or 'none'}({v})" for k, v in oth.items()))

# ------------------------------------------------------------------ component split (stated rule)
# Rule: (1) unusable product strings -> "unclassifiable"; (2) SDKs, frameworks, gateways,
# routers, proxies, registries -> "sdk/framework/gateway"; (3) anything else whose product
# name contains "mcp" -> "MCP server"; (4) the rest -> "host/client/agent platform".
# Per-product decisions are written to component_classes.csv so they can be overridden by hand.
p = df["product"]
unk = p.str.match(r"^(n/a:n/a|undefined:undefined|Unknown:|Linux:Linux)")
sdk = p.str.contains(r"sdk|framework|gateway|registry|router|proxy|bridge|fastmcp|mcp-go$|mcp-use|spring ai|mcp-security|litellm|inspector",
                     case=False, regex=True) & ~unk
srv = p.str.contains("mcp", case=False) & ~sdk & ~unk
df["component"] = "host/client/agent platform"
df.loc[srv, "component"] = "MCP server"
df.loc[sdk, "component"] = "sdk/framework/gateway"
df.loc[unk, "component"] = "unclassifiable"
comp = df.groupby(["product", "component"]).size().reset_index(name="records").sort_values(["component", "records"], ascending=[True, False])
comp.to_csv(os.path.join(HERE, "component_classes.csv"), index=False)
P("")
P("component split under the stated keyword rule:")
P("  " + ", ".join(f"{k}={v}" for k, v in df.component.value_counts().items()))
open(os.path.join(HERE, "fig2_summary.txt"), "w").write("\n".join(lines) + "\n")
print("\n".join(lines))

# ------------------------------------------------------------------ figure
for f in ["/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
          "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"]:
    if os.path.exists(f):
        font_manager.fontManager.addfont(f)
plt.rcParams.update({"font.family": ["Liberation Sans", "Arial", "Helvetica", "DejaVu Sans"], "font.size": 9,
                     "axes.edgecolor": "#1f2937", "axes.linewidth": 0.8, "pdf.fonttype": 42})
COLORS, INK = ["#2f6db5", "#d9731a", "#6b7280"], "#1f2937"
LABELS = {"Jan-Apr": "Jan–Apr 2026", "May-Aug": "May–Aug 2026", "1-25 Sep": "1–25 Sep 2026"}
fig, ax = plt.subplots(figsize=(7.2, 2.8))
x = range(len(order)); k = len(PERIODS); w = 0.8 / k
for j, (name, _, _) in enumerate(PERIODS):
    bars = ax.bar([i + (j - (k - 1) / 2) * w for i in x], tab[name], w, color=COLORS[j], edgecolor=INK,
                  linewidth=0.6, label=f"{LABELS[name]} (n = {len(parts[name])})")
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{int(b.get_height())}",
                ha="center", va="bottom", fontsize=6.5, color=INK)
ax.set_xticks(list(x)); ax.set_xticklabels(order, rotation=35, ha="right", fontsize=8.5)
ax.set_ylabel("NVD records (2026)", fontsize=9)
ax.set_ylim(0, tab[[n for n, _, _ in PERIODS]].values.max() * 1.15)
ax.yaxis.grid(True, color="#d1d5db", linewidth=0.5); ax.set_axisbelow(True)
for s in ("top", "right"): ax.spines[s].set_visible(False)
ax.legend(frameon=False, fontsize=8, loc="upper right")
fig.tight_layout()
os.makedirs(FIGDIR, exist_ok=True)
fig.savefig(os.path.join(FIGDIR, "fig2_cve_families.pdf"))
fig.savefig(os.path.join(FIGDIR, "fig2_cve_families.png"), dpi=300)
print("wrote", os.path.join(FIGDIR, "fig2_cve_families.pdf"))
