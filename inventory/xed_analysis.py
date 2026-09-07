"""Census a decoder harness using existing Ddisasm and AU artifacts.

The source-identified dispatch-table candidate set is a separate scope from
ordinary entry reachability. External implementations remain contracts.
"""
import argparse
import collections
import json
from pathlib import Path
import subprocess
import sys
from inventory.utility_analysis import digest,match_sites


def run(a):
    a.out.mkdir(parents=True,exist_ok=True);facts=a.out/'facts';query=a.out/'query';query.mkdir(exist_ok=True)
    command=[sys.executable,'-m','inventory.utility_facts','--module',f'xed={a.binary}={a.gtirb}','--root','decoder=ixyk_decode_bytes','--root','initialization=xed_tables_init','--out',str(facts)]
    if a.relations:command += ['--relations',str(a.relations)]
    subprocess.run(command,check=True)
    callbacks=[r.split('\t') for r in (a.tables/'Callback.csv').read_text().splitlines()]
    roots=[r.split('\t') for r in (facts/'Root.facts').read_text().splitlines()]
    if {u for u,_ in roots}!={'decoder','initialization'}:raise ValueError('missing scope root')
    with (facts/'Root.facts').open('a') as f:
        for u,b in roots:
            if u=='decoder':f.write('decoder_with_tables\t'+b+'\n')
        for b in sorted({int(r[2])+(1<<40) for r in callbacks}):f.write('decoder_with_tables\t'+str(b)+'\n')
    subprocess.run([str(a.souffle),'-j','1','-F',str(facts),'-D',str(query),str(Path(__file__).with_name('utility_reach.dl'))],check=True)
    match_sites(a.index,query/'Site.csv',a.native,a.out/'matches.json')
    match=json.loads((a.out/'matches.json').read_text())
    def rows(name):return [r.split('\t') for r in (query/(name+'.csv')).read_text().splitlines()]
    block_addresses={r.split('\t')[0] for r in (facts/'Module.facts').read_text().splitlines()}
    report={'scope':'XED x86-64 decode with initialized tables; initialization reported separately; no runtime-library bodies.','invocation':sys.argv,'provenance':{'facts_manifest':json.loads((facts/'manifest.json').read_text()),'binary_sha256':digest(a.binary),'gtirb_sha256':digest(a.gtirb),'au_index_sha256':digest(a.index),'native_sha256':digest(a.native),'table_callbacks_sha256':digest(a.tables/'Callback.csv'),'table_unresolved_sha256':digest(a.tables/'UnresolvedPointer.csv'),'driver_sha256':digest(Path(__file__))},'matches':match['summary'],'table_candidates_by_root':dict(collections.Counter(r[0] for r in callbacks)),'unique_table_candidate_functions':len({r[2] for r in callbacks}),'unresolved_table_pointers':(a.tables/'UnresolvedPointer.csv').read_text().splitlines(),'table_candidates_missing_ddisasm_blocks':[r for r in callbacks if str(int(r[2])+(1<<40)) not in block_addresses],'opcodes':{},'external_contracts':{},'unresolved_control_flow':{},'limitations':['Recipe matching checks encoding/domain/alias applicability, not AU instantiation or semantic validity.','The table-inclusive scope unions all candidates from five source-identified tables; it is not specialized to only valid x86-64 inputs.','Other unresolved indirect transfers remain explicit. Static table contents and runtime initialization are distinct obligations.','Static initialized data and output-structure layout are part of the eventual decoder STS state.']}
    for u in match['summary']:
        report['opcodes'][u]={op:int(n) for uu,op,n in rows('OpcodeCount') if uu==u}
        report['external_contracts'][u]=sorted({r[3] for r in rows('Boundary') if r[0]==u})
        report['unresolved_control_flow'][u]=dict(collections.Counter(r[2] for r in rows('Unresolved') if r[0]==u))
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({u:r['status_counts'] for u,r in match['summary'].items()}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('binary','gtirb','index','native','souffle','tables','out'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--relations',type=Path)
    run(p.parse_args())

if __name__=='__main__':main()
