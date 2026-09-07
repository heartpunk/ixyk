"""Tabulate Souffle requirements, run conditional waves, and retain provenance."""
import argparse
import collections
import csv
import json
from pathlib import Path
import subprocess
from inventory.utility_analysis import digest


def solve(facts,out,souffle,planned,scenarios_path=None):
    out.mkdir(parents=True,exist_ok=True)
    def read(name):
        with (facts/(name+'.csv')).open() as f:return list(csv.reader(f,delimiter='\t'))
    def write(name,rows):
        with (out/(name+'.facts')).open('w') as f:csv.writer(f,delimiter='\t',lineterminator='\n',quoting=csv.QUOTE_NONE).writerows(rows)
    body={int(g) for g, in read('HasBody')};missing={int(g) for g, in read('MissingMember')}
    supplies=[(int(g),op) for g,op in csv.reader((facts/'Supply.facts').open(),delimiter='\t') if int(g) in body-missing]
    groups={g for g,_ in supplies}; modes=('handler','executable')
    needs=collections.defaultdict(set)
    for m,g,op in read('Need'):needs[m,int(g)].add(op)
    write('Mode',((m,) for m in modes))
    write('Supply',supplies)
    write('Group',((m,g,len(needs[m,g])) for m in modes for g in sorted(groups)))
    write('Req',((m,g,i,op) for m in modes for g in sorted(groups) for i,op in enumerate(sorted(needs[m,g]))))
    write('Seed',[])
    scenarios={'base':[],'push_pop_not':['PUSH','POP','NOT'],'planned':['PUSH','POP','NOT',*planned]}
    if scenarios_path: scenarios=json.loads(scenarios_path.read_text())
    write('Scenario',((s,) for s in scenarios))
    write('Extra',((s,op) for s,ops in scenarios.items() for op in sorted(set(ops))))
    query=Path(__file__).with_name('utility_bootstrap_waves.dl')
    subprocess.run([str(souffle),'-j','1','-F',str(out),'-D',str(out),str(query)],check=True)
    def result(name):return list(csv.reader((out/(name+'.csv')).open(),delimiter='\t'))
    if set(map(tuple,result('Known'))) != set(map(tuple,result('LastAt'))):raise RuntimeError('bounded wave trace did not reach unbounded fixed point')
    report={'scope':'Conditional mnemonic supply; actual AU recipe applicability seeds individual host encodings. No runtime libraries.','conditions':['Recipe reconstruction, instantiation and semantic validity are not established by the matcher. Exact direct-model encodings are excluded from initial seeds until relocation is justified.','A guest handler supplies all uses of its mnemonic only as an optimistic form-generalization and state-projection hypothesis.','Handler mode assumes contracts for all calls leaving each handler body; executable mode follows internal Bochs code and assumes external contracts.','Unknown control flow and contracts remain obligations, not established proofs.','Residual graph cycles combine alternative handlers and do not prove that every implementation is cyclic.'],'provenance':{'need_sha256':digest(facts/'Need.csv'),'match_sha256':digest(facts/'Match.facts'),'query_sha256':digest(query)},'scenarios':scenarios,'results':{}}
    for s in scenarios:
        report['results'][s]={}
        for m in modes:
            waves=collections.defaultdict(list)
            for ss,mm,op,w in result('FirstOpcode'):
                if (ss,mm)==(s,m):waves[int(w)].append(op)
            residual=collections.Counter(op for ss,mm,g,op in result('Residual') if (ss,mm)==(s,m))
            report['results'][s][m]={'eligible_handler_groups':len(groups),'complete_groups':sum((ss,mm)==(s,m) for ss,mm,g in result('Complete')),'known_opcodes':sorted(op for ss,mm,op in result('Known') if (ss,mm)==(s,m)),'opcode_waves':dict(sorted(waves.items())),'residual_groups_per_opcode':dict(residual.most_common()),'cycle_members':sorted(op for ss,mm,op in result('CycleMember') if (ss,mm)==(s,m))}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({s:{m:{k:r[k] for k in ('eligible_handler_groups','complete_groups')} for m,r in modes.items()} for s,modes in report['results'].items()}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('facts','out','souffle'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--planned',action='append',default=[])
    p.add_argument('--scenarios',type=Path,help='JSON map of scenario names to complete extra opcode seed lists')
    a=p.parse_args();solve(a.facts,a.out,a.souffle,a.planned,a.scenarios)

if __name__=='__main__':main()
