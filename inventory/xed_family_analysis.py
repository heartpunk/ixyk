"""Reproduce family scopes and requirement queries from existing XED artifacts.

No builds or model extraction. Run under the caller's resource limits.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('facts','tables','records','patterns','catalog','matches','souffle','out'):
        p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);facts=a.out/'facts';facts.mkdir(exist_ok=True)
    def module(n,*args):subprocess.run([sys.executable,'-m','inventory.'+n,*map(str,args)],check=True)
    def query(n,out):
        out.mkdir(exist_ok=True)
        subprocess.run([str(a.souffle),'-j','1','-F',str(facts),'-D',str(out),str(Path(__file__).with_name(n+'.dl'))],check=True)
    for n in ('Edge','Insn','Unknown','Root'):
        shutil.copyfile(a.facts/(n+'.facts'),facts/(n+'.facts'))
    shutil.copyfile(a.records,facts/'RecordCapture.facts')
    shutil.copyfile(a.tables/'XedFunction.facts',facts/'XedFunction.facts')
    shutil.copyfile(a.tables/'Callback.csv',facts/'Callback.facts')
    module('xed_family_forms','--catalog',a.catalog,'--records',a.records,'--out',facts/'FamilyForm.facts')
    module('xed_pattern_keys','--patterns',a.patterns,'--out',facts)
    if json.loads((facts/'unresolved-patterns.json').read_text()):raise ValueError('unresolved source patterns')
    scope=a.out/'scope';query('xed_family_scope',scope)
    if (scope/'MissingLookup.csv').stat().st_size:raise ValueError('source lookup absent from binary')
    module('xed_scope_summary','--sites',scope/'ScopeSite.csv','--matches',a.matches,'--out',a.out/'family-summary.json')
    m=json.loads(a.matches.read_text())['matches']
    (facts/'Model.facts').write_text(''.join(f"{h}\t{r['status']}\t{r.get('form','decode_error')}\n" for h,r in sorted(m.items())))
    shutil.copyfile(scope/'ScopeSite.csv',facts/'ScopeSite.facts')
    requirements=a.out/'requirements';query('xed_requirements',requirements)
    shutil.copyfile(requirements/'Need.csv',facts/'Need.facts')
    summaries=json.loads((a.out/'family-summary.json').read_text())['families']
    order=sorted(summaries,key=lambda f:(len(summaries[f]['gaps']),summaries[f]['sites'],f))
    (facts/'Order.facts').write_text(''.join(f'{f}\t{i}\n' for i,f in enumerate(order,1)))
    query('xed_marginal',a.out/'marginal')
    import hashlib
    paths=[a.records,a.patterns,a.catalog,a.matches]+list(facts.glob('*.facts'))
    (a.out/'manifest.json').write_text(json.dumps({'invocation':sys.argv,'input_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'scope':'Candidate envelopes; semantic and domain obligations remain explicit'},indent=2)+'\n')

if __name__=='__main__':main()
