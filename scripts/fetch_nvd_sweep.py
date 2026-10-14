#!/usr/bin/env python3
"""Fetch the NVD MCP sweep and write data/mcp_cves_nvd_2026-01-01_to_<end>.csv (recipe: see README.md).

    python3 scripts/fetch_nvd_sweep.py 2026-09-25     # end date; query windows are extended automatically
Raw NVD responses go to data/raw_<today>/. To analyse a new sweep, point CSV in make_fig2.py at the new file.
"""
import json, re, urllib.request, urllib.parse, time, sys, csv, os, datetime
from concurrent.futures import ThreadPoolExecutor
END = sys.argv[1] if len(sys.argv) > 1 else "2026-09-25"
HERE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
RAW = os.path.join(HERE, "raw_" + datetime.date.today().isoformat()); os.makedirs(RAW, exist_ok=True)
def windows(a="2026-01-01", end=END):
    d = datetime.date.fromisoformat(a); e = datetime.date.fromisoformat(end)
    while d <= e:
        w = min(d + datetime.timedelta(days=119), e); yield d.isoformat(), w.isoformat(); d = w + datetime.timedelta(days=1)
def get(params):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    for i in range(6):
        try:
            return json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "survey-sweep"}), timeout=120))
        except Exception as e:
            print("retry", i, e, file=sys.stderr); time.sleep(8)
    raise SystemExit("failed " + url)
recs = {}
for kw in ["MCP", "Model Context Protocol"]:
    allv = []
    for a, b in windows():
        start = 0
        while True:
            d = get({"keywordSearch": kw, "pubStartDate": a + "T00:00:00.000", "pubEndDate": b + "T23:59:59.999", "resultsPerPage": 2000, "startIndex": start})
            allv += d["vulnerabilities"]; start += d["resultsPerPage"]; time.sleep(7)   # public rate limit
            if start >= d["totalResults"]: break
    json.dump(allv, open(os.path.join(RAW, "raw_" + kw.replace(" ", "_") + ".json"), "w"))
    for v in allv:
        recs.setdefault(v["cve"]["id"], {"c": v["cve"], "kw": set()})["kw"].add(kw)
RX=re.compile(r'\bmcp\b|model context protocol',re.I)
rows=[]
for i,x in recs.items():
    c=x['c']
    if c.get('vulnStatus')=='Rejected': continue
    d=' '.join(z['value'] for z in c['descriptions'] if z['lang']=='en')
    if not RX.search(d): continue
    pub=c['published'][:10]
    if not ('2026-01-01'<=pub<=END): continue
    m=c.get('metrics',{})
    cv=None
    for k in ['cvssMetricV31','cvssMetricV40','cvssMetricV30']:
        if m.get(k): cv=m[k][0]['cvssData']['baseScore']; break
    cw='/'.join(z['value'] for w in c.get('weaknesses',[]) for z in w['description'] if z['value'].startswith('CWE-'))
    rows.append(dict(id=i,published=pub,cvss=cv,cwe=cw,query='+'.join(sorted(x['kw']))))
def prod(i):
    for t in range(4):
        try:
            j=json.load(urllib.request.urlopen('https://cveawg.mitre.org/api/cve/'+i,timeout=30))
            a=j['containers']['cna'].get('affected',[])
            return f"{a[0].get('vendor') or 'undefined'}:{a[0].get('product') or 'undefined'}" if a else 'undefined:undefined'
        except Exception as e: time.sleep(3)
    return 'FETCH-FAILED'
with ThreadPoolExecutor(4) as ex: ps=list(ex.map(prod,[r['id'] for r in rows]))
for r,p in zip(rows,ps): r['product']=p
rows.sort(key=lambda r:(r['published'],r['id']))
with open(os.path.join(HERE, f'mcp_cves_nvd_2026-01-01_to_{END}.csv'),'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['id','published','cvss','cwe','product','query']); w.writeheader(); w.writerows(rows)
print(len(rows),'rows; fetch failures',ps.count('FETCH-FAILED'),'no cvss',sum(r['cvss'] is None for r in rows))
