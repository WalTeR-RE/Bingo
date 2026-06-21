import json

d = json.load(open("output/scan_20260429_021001.json"))

print("FINDINGS:", len(d.get("findings", [])))
print("DISCOVERY vulns:", len(d.get("discovery", {}).get("potential_vulns", [])))
print()

wa = d.get("web_analysis", {})
print("WEB_ANALYSIS title:", wa.get("title", ""))
print("WEB_ANALYSIS forms:", len(wa.get("forms", [])))
print("WEB_ANALYSIS links:", len(wa.get("links", [])))
for i, f in enumerate(wa.get("forms", [])):
    print(f"  Form {i}: action={f.get('action')} method={f.get('method')} inputs={[inp.get('name') for inp in f.get('inputs',[])]}")
print()

print("DISCOVERY:")
for v in d.get("discovery", {}).get("potential_vulns", []):
    print(f"  {v['vuln_type']} @ {v['location']} param={v['parameter']}")
print()

rs = d.get("recon_summary", {})
print("RECON techs:", rs.get("technologies", []))
print("RECON dirs:", rs.get("directories", []))
print()

pt = wa.get("page_text", "")[:500]
print("PAGE TEXT (first 500):", pt)
