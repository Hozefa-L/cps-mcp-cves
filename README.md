# NVD records mentioning the Model Context Protocol, 1 January – 25 September 2026

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23572880.svg)](https://doi.org/10.5281/zenodo.23572880)

Data and code behind the NVD analysis in Section 4.2 and Figure 2 of *Securing AI Agents in Cyber-Physical Systems: A Survey of Environmental Interactions, Deepfake Threats, and Defenses* (submitted to ACM Computing Surveys). The repository contains:

- the query parameters
- the archived raw API responses
- the record list
- the exclusions
- the CWE-to-family classification rules
- the scripts that reproduce every count the paper reports

The result is a **dated, keyword-derived sample of 561 CVE records**. It is not a census of MCP vulnerabilities (see [Limitations](#limitations)).

## Contents

| Path | What it is |
|------|------------|
| `data/raw_2026-09-26/raw_MCP.json`, `raw_Model_Context_Protocol.json` | Complete NVD API 2.0 responses for the two keyword queries, retrieved 26 Sep 2026 |
| `data/mcp_cves_nvd_2026-01-01_to_2026-09-25.csv` | The 564 records that pass the inclusion filter: `id, published, cvss, cwe, product, query` |
| `data/nvd_sweep_exclusions.csv` | The 3 records removed by inspection, with the reason for each |
| `data/cwe_families.csv` | The explicit CWE → family mapping and the MCP threat class (T1/T2/T6) of each family |
| `scripts/fetch_nvd_sweep.py` | Runs the sweep against the live NVD and CVE.org APIs |
| `scripts/verify_from_raw.py` | Rebuilds the record list from the archived raw responses and checks it against the CSV |
| `scripts/make_fig2.py` | Applies exclusions and classification, writes every reported number and the figure |
| `results/fig2_counts.csv` | Family × period table (Figure 2) |
| `results/fig2_summary.txt` | Every number quoted in the paper, plus supporting breakdowns |
| `results/fig2_cve_families.pdf/.png` | Reference rendering of Figure 2 (the paper uses a redrawn version with identical counts) |
| `results/component_classes.csv` | Per-product component class (server / host / SDK). Not used in the journal version |

## Method

### 1. Query (NVD API 2.0)

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Two separate keyword queries; the result is the union of both:
  - `keywordSearch=MCP`
  - `keywordSearch=Model Context Protocol`
- Publication-date windows of at most 120 days (the API limit):
  - 2026-01-01 → 2026-04-30
  - 2026-05-01 → 2026-08-28
  - 2026-08-29 → 2026-09-25
- Paging: `pubStartDate=<start>T00:00:00.000`, `pubEndDate=<end>T23:59:59.999`, `resultsPerPage=2000`, `startIndex` paged to `totalResults`.
- Retrieved 26 September 2026 without an API key, with a 7 s pause between requests (the public rate limit).

### 2. Inclusion filter

A record is kept if all three hold:
1. Its English description matches `\bmcp\b|model context protocol`, case-insensitive. This drops records where "mcp" appears only inside a longer token.
2. Its `vulnStatus` is not `Rejected`.
3. Its `published` date falls between 2026-01-01 and 2026-09-25.

This gives **564 records**.

### 3. Exclusions

Three records match the filter but use "mcp" as a Linux-kernel C struct name, not the protocol. They are listed with reasons in `data/nvd_sweep_exclusions.csv` and removed. This gives **561 records**.

### 4. Fields

| Field | Rule |
|---|---|
| `cvss` | First-listed CVSS v3.1 base score; if absent, v4.0; if absent, v3.0 (NVD field order) |
| `cwe` | Every `CWE-*` in the NVD `weaknesses` array, in NVD order, joined by `/` |
| `product` | First `vendor:product` in `containers.cna.affected` of the CVE.org record (`https://cveawg.mitre.org/api/cve/<id>`); `undefined:undefined` when the CNA gave none |
| `query` | Which keyword query (or both) returned the record |

### 5. Classification

- **Family.** Each record is assigned to the family of its **first-listed CWE**, using the explicit lists in `data/cwe_families.csv`. Any other CWE, or no CWE, goes to "Other". Every record therefore gets exactly one family, and the family columns sum to 561.
- **Severity.** Based on `cvss`:
  - critical ≥ 9.0
  - high ≥ 7.0
  - medium ≥ 4.0
  - low otherwise
  - unscored when NVD lists no score
- **Periods.** Jan–Apr, May–Aug, 1–25 Sep 2026, by `published` date.

## Results (as reported in the paper)

| Family | Jan–Apr | May–Aug | 1–25 Sep | Total |
|---|---:|---:|---:|---:|
| Injection | 43 | 56 | 13 | 112 |
| AuthN/AuthZ | 15 | 90 | 32 | 137 |
| SSRF | 20 | 39 | 21 | 80 |
| Traversal | 10 | 33 | 28 | 71 |
| Origin/CSRF | 7 | 23 | 0 | 30 |
| Info leak | 6 | 15 | 10 | 31 |
| DoS | 3 | 9 | 5 | 17 |
| XSS | 3 | 6 | 1 | 10 |
| Query inj. | 4 | 4 | 1 | 9 |
| Other | 12 | 31 | 21 | 64 |
| **Total** | **123** | **306** | **132** | **561** |

Other figures quoted in the paper:
- **Monthly:** 16 in January, rising to 132 in 1–25 September.
- **Severity:** 99 critical, 243 high, 198 medium, 19 low, 2 unscored.

## Reproduce

```bash
pip install -r requirements.txt
python3 scripts/verify_from_raw.py   # raw NVD responses -> CSV, expect "mismatches: 0"
python3 scripts/make_fig2.py         # CSV -> results/ (counts, summary, figure)
```

`verify_from_raw.py` checks every field except `product`, which comes from CVE.org rather than NVD.

To re-run the sweep against the live APIs:

```bash
python3 scripts/fetch_nvd_sweep.py 2026-09-25
```

NVD records are updated after publication (for example, CWE and CVSS assignments change), so a live re-run can differ from the archived snapshot. The archived responses in `data/raw_2026-09-26/` are the reference for the paper.

## Limitations

- **Records, not root causes.** The sweep counts CVE records. Attacks with no CVE assignment are not counted, which includes most semantic tool-poisoning attacks (T3).
- **Keyword matching misses records.** NVD's keyword search does not match "MCP" inside longer package names such as `gemini-mcp-tool`, so the counts are a lower bound even for CVE records.
- **Keyword matching also retrieves unrelated records.** It can match unrelated uses of the acronym; the three found by inspection are excluded.
- **One family per record.** Classification uses only the first-listed CWE, so a record with several CWEs counts once.

## Data sources and terms

- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- Product names come from CVE® records. CVE® is a registered trademark of The MITRE Corporation; CVE records are used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).

## License

- **Code** (`scripts/`): MIT License, see [`LICENSE`](LICENSE).
- **Data and results** (`data/`, `results/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The raw NVD responses and CVE.org fields remain subject to the NVD and CVE terms above.

## Archived version

Release `v1.0.0` of this repository is the snapshot the paper cites. It is archived on Zenodo as [10.5281/zenodo.23572880](https://doi.org/10.5281/zenodo.23572880); cite this version DOI. The concept DOI [10.5281/zenodo.23572879](https://doi.org/10.5281/zenodo.23572879) always resolves to the latest version. This GitHub repository is the living mirror, and later commits do not change the archived snapshot.

## Contact

Hozefa Lakadawala, Binghamton University (hlakada1@binghamton.edu)
