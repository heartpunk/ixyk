"""Inventory raw upstream decoder patterns by catalog family, with provenance.

Includes all source files; does not assert build admission or macro expansion.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from inventory.xed_family_forms import ALIASES

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('source','catalog','out'):p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args();families=[x['name'] for x in json.loads(a.catalog.read_text())['instructions']]
    lookup={}
    for f in families:
        names={f,ALIASES.get(f,f)}
        if f in ('CALL','RET'):names={f+'_NEAR',f+'_FAR'}
        if f in ('STOS','CMPS'):names={f+x for x in 'BWDQ'}
        for n in names:lookup[n]=f
    rows=[];hashes={}
    for path in sorted((a.source/'datafiles').rglob('*.txt')):
        content=path.read_text();iclass=None
        for line_no,line in enumerate(content.splitlines(),1):
            if line.strip() in ('{','}'):iclass=None
            m=re.match(r'\s*ICLASS\s*:\s*(\w+)',line)
            if m:iclass=m[1]
            m=re.match(r'\s*PATTERN\s*:\s*(.*)',line)
            if m and iclass in lookup:
                rel=str(path.relative_to(a.source));hashes[rel]=hashlib.sha256(content.encode()).hexdigest()
                rows.append({'family':lookup[iclass],'iclass':iclass,'pattern':m[1],'source':rel,'line':line_no})
    a.out.write_text(json.dumps({'scope':'Raw source patterns; build admission and macro expansion not yet established','source_hashes':hashes,'patterns':rows,'missing_families':sorted(set(families)-{r['family'] for r in rows})},indent=2)+'\n')
    print(len(rows),'patterns;',len({r['family'] for r in rows}),'families')

if __name__=='__main__':main()
