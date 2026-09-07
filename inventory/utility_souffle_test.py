"""Semantic regression fixtures for the analysis queries; requires Souffle."""
import csv
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class QueryTest(unittest.TestCase):
    def query(self,program,facts):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,rows in facts.items():
                with (root/(name+'.facts')).open('w') as f:csv.writer(f,delimiter='\t',lineterminator='\n').writerows(rows)
            subprocess.run([os.environ.get('IXYK_SOUFFLE','souffle'),'-j','1','-F',tmp,'-D',tmp,str(Path(__file__).with_name(program))],check=True)
            return {p.stem:set(map(tuple,csv.reader(p.open(),delimiter='\t'))) for p in root.glob('*.csv')}

    def test_contract_boundary_and_missing_host_encoding(self):
        result=self.query('utility_bootstrap_requirements.dl',{
            'Root':[(0,1)],'Member':[(1,1),(1,2)],'Block':[(1,),(2,),(99,)],
            'Encoding':[(1,'aa','A'),(2,'bb','B'),(99,'cc','LIB')],
            'Match':[('aa','generalized_recipe'),('bb','ungeneralized_case')],
            'Edge':[(1,2)],'Import':[(2,'external')],'Unknown':[(2,'callback_unresolved')]})
        self.assertEqual(result['Need'],{('handler','0','B'),('executable','0','B')})
        self.assertEqual(result['Boundary'],{('0','external')})
        self.assertEqual(result['Open'],{('0','callback_unresolved')})

    def test_alternative_handler_frontier(self):
        # A two-requirement implementation must not hide a cheaper alternative.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'Known.csv').write_text('')
            (root/'Residual.csv').write_text('base\ttest\t0\tX\nbase\ttest\t0\tY\nbase\ttest\t1\tZ\n')
            (root/'Supply.facts').write_text('0\tA\n1\tA\n')
            subprocess.run([os.environ.get('IXYK_SOUFFLE','souffle'),'-F',tmp,'-D',tmp,str(Path(__file__).with_name('utility_bootstrap_frontier.dl'))],check=True)
            self.assertEqual((root/'BestHandler.csv').read_text(),'base\ttest\tA\t1\t1\n')
            self.assertEqual((root/'BestNeed.csv').read_text(),'base\ttest\tA\t1\tZ\n')

    def test_helper_contract_exits(self):
        result=self.query('utility_handler_contracts.dl',{
            'Root':[(0,1)],'Member':[(1,1),(1,2)],'Edge':[(1,2),(2,3)],
            'Import':[],'FunctionName':[(3,'helper')]})
        self.assertEqual(result['HandlerExit'],{('0','2','3')})
        self.assertEqual(result['HandlerContract'],{('0','2','3','helper')})

    def test_waves_and_cycle_breaker(self):
        result=self.query('utility_bootstrap_waves.dl',{
            'Mode':[('test',)],'Group':[('test',0,0),('test',1,1),('test',2,1)],
            'Req':[('test',1,0,'A'),('test',2,0,'C')],
            'Supply':[(0,'A'),(1,'B'),(2,'C')], 'Seed':[],
            'Scenario':[('base',),('cut',)],'Extra':[('cut','C')]})
        self.assertEqual(result['Known'],{('base','test','A'),('base','test','B'),('cut','test','A'),('cut','test','B'),('cut','test','C')})
        self.assertEqual(result['Known'],result['LastAt'])
        self.assertIn(('base','test','B','2'),result['FirstOpcode'])
        self.assertEqual(result['CycleMember'],{('base','test','C')})

if __name__=='__main__':unittest.main()
