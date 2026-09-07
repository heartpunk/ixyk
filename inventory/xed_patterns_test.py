import unittest
from inventory.xed_pattern_keys import keys
from inventory.xed_family_forms import admitted

class PatternTest(unittest.TestCase):
    def test_maps_and_partial_opcodes(self):
        self.assertEqual(keys('0x0F 0x0B'),[('legacy',1,11,0)])
        self.assertEqual(keys('EVV 0x10 VNP MAP4 MOD=3'),[('evex',4,16,2)])
        self.assertEqual(keys('VV1 0x58 VF2 V0F'),[('vex',1,88,1)])
        self.assertEqual(keys('0b1001_0 SRM[rrr]'),[('legacy',0,x,0) for x in range(144,152)])
    def test_unrecognized_syntax_fails(self):
        with self.assertRaises(ValueError):keys('EVV 0x10 UNKNOWNMAP')
        with self.assertRaises(ValueError):keys('MACRO_OPCODE()')
    def test_family_aliases_and_string_distinction(self):
        self.assertTrue(admitted('JE','JZ_RELBRb'))
        self.assertTrue(admitted('CMPS','CMPSD'))
        self.assertFalse(admitted('CMPS','CMPSD_XMM_XMMsd_XMMsd_IMMb'))
        self.assertTrue(admitted('MOVSD','MOVSD'))
        self.assertTrue(admitted('MOVSD','MOVSD_XMM_MEMsd_XMMsd'))
        self.assertFalse(admitted('MOV','MOVSD'))

if __name__=='__main__':unittest.main()
