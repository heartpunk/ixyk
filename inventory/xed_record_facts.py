"""Read XED instruction records and their indexed capture targets; no traversal."""
import argparse
import ctypes
import csv
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('elf','native','out'):p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    native=ctypes.CDLL(str(a.native))
    name=native.xed_iform_enum_t2str;name.argtypes=[ctypes.c_int];name.restype=ctypes.c_char_p
    with a.elf.open('rb') as f:
        elf=ELFFile(f);symbols={s.name:s for s in elf.get_section_by_name('.symtab').iter_symbols()}
        def data(n):
            s=symbols[n];sec=elf.get_section(s['st_shndx']);off=s['st_value']-sec['sh_addr']
            return sec.data()[off:off+s['st_size']]
        records=data('xed_inst_table')
        # xed-inst.h: four uint8 fields, then four uint16 fields.
        if len(records)%12:raise ValueError('unexpected instruction record size')
        count=len(records)//12
        # Reject a mismatched native XED package, including enum/table drift.
        live=(ctypes.c_ubyte*len(records)).in_dll(native,'xed_inst_table')
        if bytes(live)!=records:raise ValueError('native and analyzed instruction tables differ')
        relatives={r['r_offset']:r['r_addend'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_RELA' for r in sec.iter_relocations() if r['r_info_type']==8}
        rows=[]
        for table in ('xed3_chain_fptr_lu','xed3_op_chain_fptr_lu'):
            raw=data(table);base=symbols[table]['st_value']
            if len(raw)!=count*8:raise ValueError('capture table/record cardinality mismatch')
            for i in range(count):
                form_id=int.from_bytes(records[i*12+6:i*12+8],'little')
                form=name(form_id).decode()
                target=relatives.get(base+i*8,int.from_bytes(raw[i*8:i*8+8],'little'))
                rows.append((i,form,table,target))
    with (a.out/'RecordCapture.facts').open('w') as f:csv.writer(f,delimiter='\t',lineterminator='\n').writerows(rows)
    (a.out/'record-manifest.json').write_text(json.dumps({'records':count,'rows':len(rows),'record_stride':12,'iform_offset':6,'native_table_equality':True,'elf_sha256':hashlib.sha256(a.elf.read_bytes()).hexdigest()},indent=2)+'\n')
    print(count,len(rows))

if __name__=='__main__':main()
