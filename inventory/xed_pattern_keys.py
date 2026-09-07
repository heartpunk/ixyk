"""Translate explicit raw pattern map/opcode prefixes into candidate dispatch keys.

All unresolved syntax is reported, never silently omitted. This is a source
candidate envelope: compiled membership and valid-mode admission are separate.
"""
import argparse
import json
import re
from pathlib import Path

def keys(pattern):
    t=pattern.split();vv=0;map_id=0;pos=0
    if t[0] in ('EVV','VV1','VV2','VV3'):
        vv={'EVV':2,'VV1':1,'VV2':2,'VV3':3}[t[0]];pos=1
        maps={'V0F':1,'V0F38':2,'V0F3A':3,**{f'MAP{i}':i for i in range(8)}}
        found={maps[x] for x in t if x in maps}
        if len(found)!=1:raise ValueError('ambiguous or missing vector map')
        map_id=found.pop()
    elif t[0].lower()=='0x0f':
        pos=1;map_id=1
        if t[1].lower() in ('0x38','0x3a'):pos=2;map_id={'0x38':2,'0x3a':3}[t[1].lower()]
    token=t[pos].replace('_','')
    if re.fullmatch('0x[0-9a-fA-F]{2}',token):opcodes=[int(token,16)]
    elif re.fullmatch('0b[01]{1,8}',token):
        bits=len(token)-2;start=int(token,2)<<(8-bits);opcodes=range(start,start+(1<<(8-bits)))
    else:raise ValueError('unrecognized opcode token: '+token)
    space={0:'legacy',1:'vex',2:'evex',3:'xop'}[vv]
    return [(space,map_id,o,vv) for o in opcodes]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--patterns',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(exist_ok=True,parents=True)
    rows=set();errors=[]
    for r in json.loads(a.patterns.read_text())['patterns']:
        try:
            for space,m,o,vv in keys(r['pattern']):rows.add((r['family'],f'xed3_phash_find_map{space}_map{m}_opcode0x{o:x}_vv{vv}'))
        except ValueError as e:errors.append({**r,'error':str(e)})
    (a.out/'FamilyLookup.facts').write_text(''.join(f'{f}\t{s}\n' for f,s in sorted(rows)))
    (a.out/'unresolved-patterns.json').write_text(json.dumps(errors,indent=2)+'\n')
    print(len(rows),'keys;',len(errors),'unresolved patterns')

if __name__=='__main__':main()
