"""Tabulate Soufflé scope sites against existing model applicability results."""
import argparse
import collections
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('sites','matches','out'):p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args();matches=json.loads(a.matches.read_text())['matches']
    counts=collections.defaultdict(collections.Counter);gaps=collections.defaultdict(collections.Counter)
    opcodes=collections.defaultdict(set);missing=set()
    for line in a.sites.read_text().splitlines():
        family,_,address,h,opcode=line.split('\t')
        if h not in matches:missing.add(h);continue
        m=matches[h];counts[family][m['status']]+=1;opcodes[family].add(opcode)
        if m['status']!='generalized_recipe':gaps[family][(m['status'],m['form'])]+=1
    if missing:raise ValueError(f'{len(missing)} site encodings missing from matching evidence')
    result={'scope':'Candidate envelopes for valid family inputs; all record modes retained. Source admission, target exhaustiveness, and domain restriction are proof obligations. Counts are applicability, not completed proofs.',
            'families':{f:{'sites':sum(c.values()),'opcode_mnemonics':sorted(opcodes[f]),'status_counts':dict(c),'gaps':[{'status':s,'form':form,'sites':n} for (s,form),n in gaps[f].most_common()]} for f,c in sorted(counts.items())}}
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('families',len(counts));print(sorted((sum(c.values()),f) for f,c in counts.items())[:15])

if __name__=='__main__':main()
