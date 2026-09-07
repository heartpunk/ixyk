"""Export verified Ddisasm code and ELF linkage as Souffle facts; no traversal."""
import argparse
import hashlib
import json
from pathlib import Path


def retained_successors(node):
    restored = {x['target'] for x in node['recovered_transfers'] if x['kind']=='continuation'}
    return [other for other in node['successors'] if other not in restored]


def sidecar_relations(directory):
    result={};provenance={}
    for name in ('instruction','code_in_refined_block'):
        candidates=[directory/'disassembly'/(name+suffix) for suffix in ('.csv','.facts')]
        path=next((p for p in candidates if p.is_file()),None)
        if path is None:raise ValueError('missing Ddisasm sidecar: '+name)
        contents=path.read_text()
        result['disassembly.'+name]=('',contents)
        provenance[name]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    return result,provenance


def main():
    import gtirb
    from elftools.elf.elffile import ELFFile
    from inventory.binary import read_binary
    p = argparse.ArgumentParser()
    p.add_argument('--module', action='append', required=True, help='NAME=ELF=GTIRB')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--root', action='append', default=[], help='UTILITY=SYMBOL')
    p.add_argument('--relations',type=Path,help='Ddisasm debug directory for a single module')
    args = p.parse_args()
    if args.relations and len(args.module)!=1:raise ValueError('sidecars require exactly one module')
    args.out.mkdir(parents=True, exist_ok=True)
    roots = dict(x.split('=',1)[::-1] for x in args.root) if args.root else {'single_binary_main_sort':'sort','single_binary_main_chroot':'chroot'}
    facts = {k: [] for k in ('Edge','Insn','Root','Import','Export','Unknown','Function','Member','Module')}
    manifest = {'modules': [], 'scope': 'utility function entries; process initialization remains separate'}
    for index, item in enumerate(args.module, 1):
        name, elfpath, irpath = item.split('=', 2)
        shift = index << 40
        ir = gtirb.IR.load_protobuf(irpath)
        module = ir.modules[0]
        relation_provenance={}
        if args.relations:
            data,relation_provenance=sidecar_relations(args.relations)
            module.aux_data['souffleOutputs']=gtirb.AuxData(data,'mapping<string,tuple<string,string>>')
        nodes, symbols = read_binary(Path(irpath), Path(elfpath), ir_override=ir)
        entries = module.aux_data.get('functionEntries')
        members = module.aux_data.get('functionBlocks')
        for symbol, addresses in symbols.items():
            for address in addresses:
                facts['Function'].append((address+shift, name, symbol))
                if symbol in roots:
                    facts['Root'].append((roots[symbol], address+shift))
        if entries and members:
            for fid, entry_blocks in entries.data.items():
                for root in entry_blocks:
                    if not isinstance(root, gtirb.CodeBlock) or root.address is None: continue
                    for block in members.data.get(fid, []):
                        if isinstance(block, gtirb.CodeBlock) and block.address is not None:
                            facts['Member'].append((root.address+shift, block.address+shift))
        reloc = {}
        with open(elfpath, 'rb') as stream:
            elf = ELFFile(stream)
            needed = []
            for section in elf.iter_sections():
                if section['sh_type'] == 'SHT_DYNAMIC':
                    needed = [tag.needed for tag in section.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
                if section['sh_type'] in ('SHT_REL','SHT_RELA'):
                    syms = elf.get_section(section['sh_link'])
                    for relocation in section.iter_relocations():
                        symbol = syms.get_symbol(relocation['r_info_sym'])
                        if symbol.name: reloc[relocation['r_offset']] = symbol.name
                if section['sh_type'] == 'SHT_DYNSYM':
                    for symbol in section.iter_symbols():
                        if symbol['st_shndx'] != 'SHN_UNDEF' and symbol['st_value']:
                            facts['Export'].append((name,symbol.name,symbol['st_value']+shift,str(symbol['st_info']['type'])))
        for address, node in nodes.items():
            b = int(address)+shift
            facts['Module'].append((b,name))
            # The legacy Bochs auditor restores every CALL continuation. Preserve
            # Ddisasm's noreturn analysis rather than walking into adjacent functions.
            facts['Edge'].extend((b, other+shift) for other in retained_successors(node))
            facts['Unknown'].extend((b,reason) for reason in node['unknown'])
            for site in node['instructions']:
                facts['Insn'].append((b,site['address']+shift,site['hex'],site['opcode']))
                raw=bytes.fromhex(site['hex'])
                start=1 if raw.startswith(b'\xf2') else 0
                if raw[start:start+2] in (b'\xff\x25',b'\xff\x15') and len(raw)==start+6:
                    slot=site['address']+len(raw)+int.from_bytes(raw[start+2:], 'little',signed=True)
                    if slot in reloc: facts['Import'].append((b,name,reloc[slot]))
        forwarding=module.aux_data.get('symbolForwarding')
        if forwarding:
            for src,dst in forwarding.data.items():
                if isinstance(src.referent,gtirb.CodeBlock) and src.referent.address is not None:
                    facts['Import'].append((src.referent.address+shift,name,dst.name))
        manifest['modules'].append({'name':name,'relations':relation_provenance,'elf':elfpath,'gtirb':irpath,'shift':shift,'blocks':len(nodes),'needed':needed,'elf_sha256':hashlib.sha256(Path(elfpath).read_bytes()).hexdigest(),'gtirb_sha256':hashlib.sha256(Path(irpath).read_bytes()).hexdigest()})
    for name,rows in facts.items():
        with (args.out/(name+'.facts')).open('w') as f:
            for row in sorted(set(rows)):
                if any('\t' in str(x) or '\n' in str(x) for x in row): raise ValueError('invalid TSV symbol')
                f.write('\t'.join(map(str,row))+'\n')
    manifest['fact_counts']={name:len(set(rows)) for name,rows in facts.items()}
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest),flush=True)

if __name__ == '__main__': main()
