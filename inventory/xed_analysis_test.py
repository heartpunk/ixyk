import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class TableTest(unittest.TestCase):
    def test_nested_tables_cycles_null_and_unknown_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            data={'XedFunction':'300\tcallee\n','XedObject':'100\troot\n200\tnested\n',
                  'XedTableRoot':'decode\t100\n','XedWord':'100\t100\t200\n200\t200\t300\n200\t208\t0\n200\t216\t999\n200\t224\t100\n'}
            for name,rows in data.items():(p/(name+'.facts')).write_text(rows)
            subprocess.run([os.environ.get('IXYK_SOUFFLE','souffle'),'-F',tmp,'-D',tmp,str(Path(__file__).with_name('xed_tables.dl'))],check=True)
            self.assertEqual(set((p/'Table.csv').read_text().splitlines()),{'decode\t100','decode\t200'})
            self.assertEqual((p/'Callback.csv').read_text(),'decode\tcallee\t300\n')
            self.assertEqual((p/'UnresolvedPointer.csv').read_text(),'decode\t216\t999\n')

class GeneratedTableTest(unittest.TestCase):
    def test_key_words_are_not_pointers_and_invalid_target_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            data={'XedFunction':'300\txed3_phash_find_map0_1_l1\n400\txed_phash_invalid\n',
                  'XedObject':'100\tlu_table.1\n200\tlu_table.2\n',
                  'XedTableRoot':'',
                  'XedWord':'100\t100\t999\n100\t108\t300\n100\t116\t888\n100\t124\t400\n100\t132\t777\n100\t140\t12345\n200\t200\t300\n200\t208\t42\n'}
            for name,rows in data.items():(p/(name+'.facts')).write_text(rows)
            subprocess.run([os.environ.get('IXYK_SOUFFLE','souffle'),'-F',tmp,'-D',tmp,str(Path(__file__).with_name('xed_tables.dl'))],check=True)
            self.assertEqual((p/'NestedTable.csv').read_text(),'100\tlu_table.1\n')
            self.assertEqual(set((p/'Callback.csv').read_text().splitlines()),{'nested_phash\txed3_phash_find_map0_1_l1\t300','nested_phash\txed_phash_invalid\t400'})
            self.assertEqual((p/'UnresolvedPointer.csv').read_text(),'nested_phash\t140\t12345\n')

if __name__=='__main__':unittest.main()
