"""Map the canonical top-100 catalog to XED record forms, without traversal.

This is an all-record envelope, not a claim that every record admits long mode.
"""
import argparse
import json
from pathlib import Path

ALIASES={'JE':'JZ','JNE':'JNZ','JA':'JNBE','JAE':'JNB','JG':'JNLE','JGE':'JNL',
         'SETE':'SETZ','SETNE':'SETNZ','SETA':'SETNBE','SETAE':'SETNB','SETG':'SETNLE',
         'CMOVE':'CMOVZ','CMOVNE':'CMOVNZ','CMOVA':'CMOVNBE','CMOVAE':'CMOVNB',
         'CMOVG':'CMOVNLE','CMOVGE':'CMOVNL'}

def admitted(family,form):
    if family in ('STOS','CMPS'):
        return form in {family+x for x in 'BWDQ'}
    return form.split('_')[0] in {family,ALIASES.get(family,family)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('catalog','records','out'):p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args()
    families=[x['name'] for x in json.loads(a.catalog.read_text())['instructions']]
    forms={line.split('\t')[1] for line in a.records.read_text().splitlines()}
    rows=[(f,form) for f in families for form in sorted(forms) if admitted(f,form)]
    if set(families)!={f for f,_ in rows}:raise ValueError('catalog family without XED records')
    a.out.write_text(''.join(f'{f}\t{form}\n' for f,form in rows))

if __name__=='__main__':main()
