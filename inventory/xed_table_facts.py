"""Read XED's five source-identified decoder dispatch tables from its ELF.

ELF words and relocation addends are facts. Souffle follows table pointers.
"""
import argparse
import csv
from pathlib import Path
from elftools.elf.elffile import ELFFile

TABLES=('xed3_phash_lu','xed3_chain_fptr_lu','xed3_op_chain_fptr_lu',
        'xed_ild_disp_width_table','xed_ild_imm_width_table')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    with a.elf.open('rb') as f:
        elf=ELFFile(f);syms=list(elf.get_section_by_name('.symtab').iter_symbols())
        functions=[(s['st_value'],s.name) for s in syms if s['st_info']['type']=='STT_FUNC' and s['st_shndx']!='SHN_UNDEF']
        objects=[s for s in syms if s['st_info']['type']=='STT_OBJECT' and isinstance(s['st_shndx'],int) and s['st_size']]
        relative={}
        for sec in elf.iter_sections():
            if sec['sh_type']=='SHT_RELA':
                for r in sec.iter_relocations():
                    if r['r_info_type']==8:relative[r['r_offset']]=r['r_addend']
        words=[];section_data={}
        for s in objects:
            sec=elf.get_section(s['st_shndx'])
            if sec['sh_type']=='SHT_NOBITS':continue
            offset=s['st_value']-sec['sh_addr']
            if s['st_shndx'] not in section_data:section_data[s['st_shndx']]=sec.data()
            data=section_data[s['st_shndx']][offset:offset+s['st_size']]
            for i in range(0,len(data)-7,8):
                addr=s['st_value']+i
                words.append((s['st_value'],addr,relative.get(addr,int.from_bytes(data[i:i+8],'little'))))
        roots=[(s.name,s['st_value']) for s in objects if s.name in TABLES]
        if {n for n,_ in roots}!=set(TABLES):raise ValueError('missing decoder table symbols')
        facts={'XedFunction':functions,'XedObject':[(s['st_value'],s.name) for s in objects], 'XedWord':words,'XedTableRoot':roots}
    for name,rows in facts.items():
        with (a.out/(name+'.facts')).open('w') as f:csv.writer(f,delimiter='\t',lineterminator='\n').writerows(rows)
    print({k:len(v) for k,v in facts.items()},flush=True)

if __name__=='__main__':main()
