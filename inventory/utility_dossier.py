"""Join measured utility gaps to AU evidence and Souffle handler frontiers.

This is report tabulation only; dependency closure/minimal frontiers are queried
in Souffle. Family fuzz findings are context, never assigned as case verdicts.
"""
import argparse
import collections
import json
from pathlib import Path
from inventory.bootstrap import canonical
from inventory.utility_analysis import digest


def build(args):
    index=json.loads(args.index.read_text()); matches=json.loads(args.matches.read_text())
    cases={c['id']:c for c in index['cases']};byform=collections.defaultdict(list)
    for c in cases.values():byform[c['form']['form']].append(c['id'])
    targets=json.loads(args.targets.read_text()); groups={tuple(rs):g for g,rs in enumerate(targets['groups'])}
    target_groups=collections.defaultdict(list)
    for t in targets['targets']:target_groups[groups[tuple(t['roots'])]].append(t)
    best=collections.defaultdict(list);needs=collections.defaultdict(list)
    for line in (args.frontier/'BestNeed.csv').read_text().splitlines():
        s,m,op,g,need=line.split('\t');needs[s,m,op,int(g)].append(need)
    for line in (args.frontier/'BestHandler.csv').read_text().splitlines():
        s,m,op,g,n=line.split('\t');g=int(g)
        best[op].append({'scenario':s,'mode':m,'group':g,'missing_opcodes':sorted(needs[s,m,op,g]),'targets':[t for t in target_groups[g] if canonical(t['mnemonic'])==op]})
    obligations=collections.defaultdict(lambda:collections.defaultdict(list))
    for name in ('HandlerExit','HandlerContract','HandlerImport','Open'):
        for line in (args.frontier/(name+'.csv')).read_text().splitlines():
            g,*rest=line.split('\t');obligations[int(g)][name].append(rest)
    rows=[r.split('\t') for r in args.sites.read_text().splitlines()]
    report={'scope':'Utility code plus explicit callback roots; imported functions are contracts. Static discovered control flow is not proved exhaustive.','provenance':{key:digest(getattr(args,key)) for key in ('index','matches','sites','targets')},'utilities':{},'emulator_frontiers':dict(best),'handler_obligations':dict(obligations)}
    used_cases=set()
    for u in sorted({r[0] for r in rows}):
        gaps={};validation=collections.Counter()
        for _,module,a,h,opcode in (r for r in rows if r[0]==u):
            match=matches['matches'][h];status=match['status'];form=match.get('form',opcode)
            if status=='generalized_recipe':
                contexts={index['fuzz'].get(cases[c]['family'],{}).get('status','missing') for c in match['cases']}
                validation['+'.join(sorted(contexts))]+=1
                continue
            key=(status,form)
            if key not in gaps:gaps[key]={'status':status,'form':form,'opcode':canonical(match.get('iclass',opcode)),'sites':[],'matching_cases':set(),'candidate_cases':byform[form]}
            gaps[key]['sites'].append({'address':int(a)-(1<<40),'hex':h})
            gaps[key]['matching_cases'].update(match['cases'])
            used_cases.update(byform[form])
        for gap in gaps.values():
            gap['matching_cases']=sorted(gap['matching_cases']);gap['site_count']=len(gap['sites'])
            gap['frontier_opcode']=gap['opcode']
        report['utilities'][u]={'sites':sum(r[0]==u for r in rows),'recipe_family_validation_context':dict(validation),'gaps':sorted(gaps.values(),key=lambda g:(-g['site_count'],g['form']))}
    report['cases']={cid:{'form':cases[cid]['form'],'domains':cases[cid]['domains'],'groups':cases[cid]['groups'],'generalized':cases[cid]['generalized'],'comparable':cases[cid]['comparable'],'member':cases[cid]['member'],'index':cases[cid]['index'],'observation_hex':[o['hex'] for o in cases[cid]['observations']],'family_validation':index['fuzz'].get(cases[cid]['family'])} for cid in sorted(used_cases)}
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(args.out)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('index','matches','sites','targets','frontier','out'):p.add_argument('--'+key,type=Path,required=True)
    build(p.parse_args())

if __name__=='__main__':main()
