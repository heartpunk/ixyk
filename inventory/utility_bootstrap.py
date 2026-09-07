"""Bochs-only fact export for conditional utility bootstrap experiments.

No graph traversal occurs here. Imported code is excluded; external calls and
unknown transfers remain explicit obligations in the Souffle results.
"""
import argparse
import csv
import json
from pathlib import Path
from inventory.bootstrap import canonical
from inventory.utility_analysis import digest


def export(source,out,matches=None):
    data=json.loads(source.read_text());out.mkdir(parents=True,exist_ok=True)
    nodes={int(b):n for b,n in data['nodes'].items() if n['module']=='bochs'}
    groups=list(dict.fromkeys(tuple(t['roots']) for t in data['targets']))
    ids={r:i for i,r in enumerate(groups)}
    def write(name,rows):
        with (out/(name+'.facts')).open('w') as f:
            csv.writer(f,delimiter='\t',lineterminator='\n',quoting=csv.QUOTE_NONE).writerows(rows)
    write('FunctionName',((b,s) for s,b,k in data['exports'] if b in nodes))
    if matches:
        matched=json.loads(matches.read_text())
        write('Match',((h,v['status']) for h,v in matched['matches'].items()))
    write('Root',((i,b) for i,rs in enumerate(groups) for b in rs))
    write('Member',((int(e),b) for e,bs in data['members'].items() if int(e) in nodes for b in bs if b in nodes))
    write('Block',((b,) for b in nodes))
    write('Encoding',((b,s['hex'],canonical(s['opcode'])) for b,n in nodes.items() for s in n['instructions']))
    write('Edge',((b,v) for b,n in nodes.items() for v in n['successors'] if v in nodes and v not in {x['target'] for x in n['recovered_transfers'] if x['kind']=='continuation'}))
    write('Unknown',((b,r) for b,n in nodes.items() for r in n['unknown']))
    write('Import',((b,s) for b,s in data['imports'] if b in nodes))
    write('Supply',sorted({(ids[tuple(t['roots'])],canonical(t['mnemonic'])) for t in data['targets'] if t['roots'] and not t['unresolved_handlers'] and all(b in nodes for b in t['roots'])}))
    with (out/'Site.csv').open('w') as f:
        writer=csv.writer(f,delimiter='\t',lineterminator='\n')
        for b,n in nodes.items():
            for s in n['instructions']:
                writer.writerow(('bochs','bochs',s['address'],s['hex'],canonical(s['opcode'])))
    (out/'targets.json').write_text(json.dumps({'groups':groups,'targets':data['targets']}))
    (out/'manifest.json').write_text(json.dumps({'inventory_sha256':digest(source),'scope':'Bochs executable only; no imported library code','blocks':len(nodes),'conditional_supply':'A completed handler group supplies its mnemonic only as an optimistic form-generalization/projection hypothesis.'},indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--matches',type=Path)
    a=p.parse_args();export(a.inventory,a.out,a.matches)

if __name__=='__main__':main()
