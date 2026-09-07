"""Reusable utility gap analysis. Artifact I/O/matching here; graph queries in Souffle.

index reads an AU archive without extracting files. match admits a saved case
only after constructor encoding reproduces the exact instruction bytes and its
argument domains/alias partition hold. A recipe match is not a semantic proof.
"""
import argparse
import collections
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile


def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1048576),b''): h.update(block)
    return h.hexdigest()


def index_archive(archive,out):
    result={'schema':'ixyk.utility_au_index.v1','archive':str(archive),'archive_sha256':digest(archive),'cases':[],'fuzz':{},'acquisitions':{},'metadata':{},'direct':[]}
    proc=subprocess.Popen(['zstd','-dc',str(archive)],stdout=subprocess.PIPE)
    with tarfile.open(fileobj=proc.stdout,mode='r|') as tar:
        for member in tar:
            if not member.isfile(): continue
            name=member.name.rsplit('/',1)[-1]
            if name.endswith('.acquisition.json'):
                data=json.load(tar.extractfile(member))
                family=name.split('.',1)[0]
                result['acquisitions'][family]={k:data.get(k) for k in ('status','model_route','error')}
                for j,retained in enumerate(data.get('retained_models',[])):
                    model=retained['model']
                    result['direct'].append({'hex':retained['instruction_hex'],'source':model['source'],'member':member.name,'retained_index':j,'family':family})
                for i,case in enumerate(data.get('prepared_cases',[])):
                    item={k:case[k] for k in ('form','domains','groups','generalized','comparable')}
                    item.update(id=family+':'+str(i),member=member.name,index=i,family=family)
                    item['observations']=[{'hex':o['instruction_hex'],'decoded':o['decoded'],'source':o['model']['source'],'model_sha256':hashlib.sha256(json.dumps(o['model'],sort_keys=True,separators=(',',':')).encode()).hexdigest()} for o in case['observations']]
                    result['cases'].append(item)
            elif name.endswith('.fuzz.json'):
                data=json.load(tar.extractfile(member))
                result['fuzz'][name.split('.',1)[0]]={k:data.get(k) for k in ('status','processing','executions','agreements','disagreements','unusable','reason','instruction_hex')}
            elif name.endswith('.metadata.txt'):
                result['metadata'][name]=tar.extractfile(member).read().decode()
    if proc.wait(): raise RuntimeError('archive decompression failed')
    out.write_text(json.dumps(result,separators=(',',':')))
    print(json.dumps({'cases':len(result['cases']),'generalized':sum(c['generalized'] for c in result['cases']),'families':len(result['acquisitions']),'archive_sha256':result['archive_sha256']}),flush=True)


class Xed:
    def __init__(self,path):
        self.lib=ctypes.CDLL(str(path))
        self.lib.ixyk_native_init()
        self.lib.ixyk_analysis_decode.argtypes=[ctypes.c_char_p,ctypes.c_uint]
        self.lib.ixyk_analysis_decode.restype=ctypes.c_void_p
        self.lib.ixyk_native_encode.argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_uint64),ctypes.c_uint]
        self.lib.ixyk_native_encode.restype=ctypes.c_void_p
        self.lib.ixyk_native_free.argtypes=[ctypes.c_void_p]
    def read(self,ptr):
        if not ptr: return None
        try: return json.loads(ctypes.string_at(ptr))
        finally: self.lib.ixyk_native_free(ptr)
    def decode(self,h):
        raw=bytes.fromhex(h)
        return self.read(self.lib.ixyk_analysis_decode(raw,len(raw)))
    def encode(self,form,values):
        v=(ctypes.c_uint64*len(values))(*(x%(1<<64) for x in values))
        return self.read(self.lib.ixyk_native_encode(form,v,len(values)))


def arguments(case,decoded):
    regs=[o['register'] for o in decoded['operands'] if o['visibility']=='EXPLICIT' and o['register']['name']!='INVALID']
    values=[]; parents={}; regindex=0
    for i,(arg,domain) in enumerate(zip(case['form']['args'],case['domains'],strict=True)):
        name=arg['name']; kind=arg['kind']
        if domain['register']:
            if name=='base': reg=decoded['base']
            elif name=='index': reg=decoded['index']
            else:
                if regindex>=len(regs): return None
                reg=regs[regindex]; regindex+=1
            value=reg['value']; parents[i]=reg['parent']
        elif name=='scale': value=decoded['scale']
        elif name.startswith(('relb','relbr')): value=decoded['branch']
        elif 'disp' in name: value=decoded['displacement']
        elif 'imm' in name: value=decoded['immediate']
        else: return None
        choices=domain['choices']
        if 'imm' in name and not choices and domain['low']<0 and value>domain['high']:
            width=(domain['high']-domain['low']+1).bit_length()-1
            if value<(1<<width): value-=1<<width
        if choices:
            if value not in choices: return None
        elif not domain['low']<=value<=domain['high']: return None
        values.append(value)
    group_parents=[]
    for group in case['groups']:
        same={parents[i] for i in group}
        if len(same)!=1: return None
        group_parents.append(next(iter(same)))
    if len(set(group_parents))!=len(group_parents): return None
    return values


def match_sites(index_path,sites,native,out):
    index=json.loads(index_path.read_text()); xed=Xed(native)
    byform=collections.defaultdict(list)
    direct_bytes=collections.defaultdict(list)
    for item in index.get('direct',[]): direct_bytes[item['hex']].append(item)
    for case in index['cases']:
        for obs in case['observations']: direct_bytes[obs['hex']].append({'source':obs['source'],'case':case['id'],'family':case['family']})
    for case in index['cases']: byform[case['form']['form']].append(case)
    # Validate constructor IDs against saved concrete observations before reuse.
    checked=set(); invalid=[]
    for case in index['cases']:
        fid=case['form']['id']
        if fid in checked: continue
        for obs in case['observations']:
            values=arguments(case,obs['decoded'])
            if values is None: continue
            encoded=xed.encode(fid,values)
            if not encoded or encoded['hex']!=obs['hex']:
                invalid.append(case['id'])
            else: checked.add(fid)
            break
    if invalid: raise ValueError('constructor package mismatch: '+str(invalid[:12]))
    rows=[line.split('\t') for line in sites.read_text().splitlines()]
    unique={r[3] for r in rows}; matches={}
    for h in sorted(unique):
        d=xed.decode(h)
        if not d:
            matches[h]={'status':'decode_error'};continue
        candidates=byform.get(d['form'],[]); admitted=[]; direct=[]
        for case in candidates:
            values=arguments(case,d)
            if values is None or case['form']['id'] not in checked: continue
            encoded=xed.encode(case['form']['id'],values)
            if not encoded or encoded['hex']!=h: continue
            (admitted if case['generalized'] else direct).append(case['id'])
        matches[h]={'status':'generalized_recipe' if admitted else 'direct_encoding' if h in direct_bytes else 'ungeneralized_case' if direct else 'unmatched_case' if candidates else 'missing_form','iclass':d['iclass'],'form':d['form'],'cases':admitted or direct,'direct_models':direct_bytes.get(h,[]) if not admitted else []}
    summary={}
    for u in sorted({r[0] for r in rows}):
        selected=[r for r in rows if r[0]==u]
        counts=collections.Counter(matches[r[3]]['status'] for r in selected)
        gaps=collections.Counter((matches[r[3]]['status'],matches[r[3]].get('form',r[4])) for r in selected if matches[r[3]]['status']!='generalized_recipe')
        summary[u]={'sites':len(selected),'status_counts':dict(counts),'gaps':[{'status':s,'form':f,'sites':n} for (s,f),n in gaps.most_common()]}
    result={'schema':'ixyk.utility_case_matches.v1','scope':'constructor/domain/alias/exact-encoding applicability; templates not instantiated by this matcher','au_index_sha256':digest(index_path),'sites_sha256':digest(sites),'native_sha256':digest(native),'checked_constructor_ids':len(checked),'matches':matches,'summary':summary,'family_validation':index['fuzz']}
    out.write_text(json.dumps(result,separators=(',',':')))
    print(json.dumps(summary),flush=True)


def run_analysis(args):
    args.out.mkdir(parents=True,exist_ok=True)
    facts=args.out/'facts'; query=args.out/'query'; query.mkdir(exist_ok=True)
    command=[sys.executable,'-m','inventory.utility_facts','--module',f'{args.name}={args.binary}={args.gtirb}','--out',str(facts)]
    for root in args.root: command += ['--root',root]
    subprocess.run(command,check=True)
    subprocess.run([str(args.souffle),'-F',str(facts),'-D',str(query),str(Path(__file__).with_name('utility_reach.dl'))],check=True)
    match_sites(args.index,query/'Site.csv',args.native,args.out/'matches.json')
    matches=json.loads((args.out/'matches.json').read_text())
    contracts=json.loads(args.contracts.read_text()) if args.contracts else {}
    planned=set(args.planned)
    report={'scope':'utility code only; external calls are contracts; no runtime closure','invocation':sys.argv,'provenance':{'facts':json.loads((facts/'manifest.json').read_text()),'query_sha256':digest(Path(__file__).with_name('utility_reach.dl')),'analysis_sha256':digest(Path(__file__)),'au_index_sha256':matches['au_index_sha256'],'native_sha256':matches['native_sha256']},'matches':matches['summary'],'contracts':{},'planned_sites':{},'unresolved_control_flow':{},'limitations':['Recipe matches establish encoded-case applicability, not template instantiation or semantic correctness.','Function-entry analysis assumes a valid initialized process; startup/dispatch is a separate embedding obligation.','Unknown indirect targets remain unresolved; discovered targets are not an exhaustiveness proof.','External contract bodies must be supplied/proved or assumed explicitly; this report does not synthesize them.']}
    sites=[r.split('\t') for r in (query/'Site.csv').read_text().splitlines()]
    boundaries=[r.split('\t') for r in (query/'Boundary.csv').read_text().splitlines()]
    unknown=[r.split('\t') for r in (query/'Unresolved.csv').read_text().splitlines()]
    for u in sorted(matches['summary']):
        report['contracts'][u]={symbol:contracts.get(symbol,{'status':'required','obligation':'Specify state effects, return/error behavior, and any callbacks.'}) for symbol in sorted({r[3] for r in boundaries if r[0]==u})}
        report['planned_sites'][u]=dict(collections.Counter(r[4] for r in sites if r[0]==u and r[4] in planned))
        report['unresolved_control_flow'][u]=dict(collections.Counter(r[2] for r in unknown if r[0]==u))
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Report:',args.out/'report.json',flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('index');a.add_argument('--archive',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('match');a.add_argument('--index',type=Path,required=True);a.add_argument('--sites',type=Path,required=True);a.add_argument('--native',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('run')
    for key in ('binary','gtirb','index','native','souffle','out'): a.add_argument('--'+key,type=Path,required=True)
    a.add_argument('--name',default='utility')
    a.add_argument('--root',action='append',required=True,help='UTILITY=SYMBOL')
    a.add_argument('--contracts',type=Path)
    a.add_argument('--planned',action='append',default=[])
    a=p.parse_args()
    if a.command=='index': index_archive(a.archive,a.out)
    elif a.command=='match': match_sites(a.index,a.sites,a.native,a.out)
    else: run_analysis(a)

if __name__=='__main__': main()
