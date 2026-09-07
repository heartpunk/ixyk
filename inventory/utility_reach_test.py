"""Regression for grouped opcode counts at repeated-site scale."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class CountTest(unittest.TestCase):
    def test_repeated_sites_count_once_per_scope_and_opcode(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            for n in ('Edge','Import','Export','Unknown','Function','Member'):
                (p/(n+'.facts')).write_text('')
            (p/'Root.facts').write_text('a\t1\nb\t1\n')
            (p/'Module.facts').write_text('1\txed\n')
            (p/'Insn.facts').write_text(''.join(f'1\t{i}\t90\tNOP\n' for i in range(10000))+'1\t10000\tc3\tRET\n')
            subprocess.run([os.environ.get('IXYK_SOUFFLE','souffle'),'-j','1','-F',tmp,'-D',tmp,str(Path(__file__).with_name('utility_reach.dl'))],check=True,timeout=30)
            self.assertEqual(set((p/'OpcodeCount.csv').read_text().splitlines()),{'a\tNOP\t10000','b\tNOP\t10000','a\tRET\t1','b\tRET\t1'})

if __name__=='__main__':unittest.main()
