import unittest
from inventory.utility_analysis import arguments

class ArgumentsTest(unittest.TestCase):
    def test_relative_branch_is_not_memory_displacement(self):
        case={'form':{'args':[{'name':'relb_disp8','kind':'int8'}]},'domains':[{'register':False,'choices':[],'low':-128,'high':127}],'groups':[]}
        self.assertEqual(arguments(case,{'operands':[],'branch':-7,'displacement':0}),[-7])
        self.assertIsNone(arguments(case,{'operands':[],'branch':128,'displacement':0}))

    def test_auditor_cannot_restore_noreturn_continuation(self):
        from inventory.utility_facts import retained_successors
        node={'successors':[20,30,40], 'recovered_transfers':[
            {'kind':'continuation','target':30},
            {'kind':'direct','target':40}]}
        self.assertEqual(retained_successors(node),[20,40])

    def test_alias_partition(self):
        case={'form':{'args':[{'name':'reg0','kind':'gpr64'},{'name':'reg1','kind':'gpr64'}]},'domains':[{'register':True,'choices':[98,99],'low':0,'high':0}]*2,'groups':[[0],[1]]}
        def reg(value,parent): return {'visibility':'EXPLICIT','register':{'value':value,'name':parent,'parent':parent}}
        same={'operands':[reg(98,'RAX'),reg(98,'RAX')]}
        different={'operands':[reg(98,'RAX'),reg(99,'RCX')]}
        self.assertIsNone(arguments(case,same))
        self.assertEqual(arguments(case,different),[98,99])
        case['groups']=[[0,1]]
        self.assertEqual(arguments(case,same),[98,98])
        self.assertIsNone(arguments(case,different))

if __name__=='__main__': unittest.main()
