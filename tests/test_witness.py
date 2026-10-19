import importlib
import unittest
from dataclasses import replace
from pathlib import Path
from hidwire.parser import parse_descriptor
from hidwire.model import ReportKey
from tests.helpers import simple

ROOT = Path(__file__).resolve().parents[1]
KEY = ReportKey('input', None)

def parse(text):
    return parse_descriptor(bytes.fromhex(text))

class WitnessTests(unittest.TestCase):
    def api(self):
        api = importlib.import_module('hidwire')
        self.assertTrue(hasattr(api, 'decode_report'), 'decoder API missing')
        self.assertTrue(hasattr(api, 'verify_witness'), 'witness verifier API missing')
        return api

    def test_signed_one_bit_and_cross_byte(self):
        api = self.api()
        one = parse('050115ff2500750195010930810275078101')
        self.assertEqual(api.decode_report(one,KEY,b'\x01').values[0].value,-1)
        cross = parse('05017503950181011600f826ff07750c0930810275018101')
        self.assertEqual(cross.status,'supported')
        self.assertEqual(api.decode_report(cross,KEY,b'\xf8\x7f').values[0].value,-1)

    def test_exact_length_prefix_and_blocked_refusal(self):
        api = self.api()
        d = parse(simple(prefix='8502'))
        for wire in [b'', b'\x02', b'\x01\x00', b'\x02\x00\x00']:
            with self.assertRaises(ValueError):
                api.decode_report(d,ReportKey('input',2),wire)
        self.assertEqual(api.decode_report(parse(simple()),KEY,b'\x00').values[0].value,0)
        blocked = parse(simple(flags='00'))
        with self.assertRaises(ValueError):
            api.decode_report(blocked,KEY,b'\x00')

    def test_whole_report_range_labels_and_tamper_detection(self):
        api = self.api()
        # X/Y change positions; unrelated Z has positive logical minimum 1.
        old = parse('0501150025ff750895020930093181021501250a950109328102')
        new = parse('0501150025ff750895020931093081021501250a950109328102')
        result = api.compare_descriptors(old,new)
        for w in result.witnesses:
            self.assertFalse(w.old_range_valid)
            self.assertFalse(w.new_range_valid)
            self.assertTrue(api.verify_witness(old,new,w))
            for altered in [replace(w,old_hash='0'*64), replace(w,new_hash='0'*64),
                            replace(w,old_value=w.old_value+1), replace(w,new_value=w.new_value+1),
                            replace(w,old_range_valid=True), replace(w,new_range_valid=True),
                            replace(w,wire_hex='000000'), replace(w,wire_hex='zz'),
                            replace(w,wire_hex='00010000')]:
                self.assertFalse(api.verify_witness(old,new,altered))

    def test_real_report_values(self):
        api = self.api()
        d = parse_descriptor((ROOT/'fixtures/real/circuitpython-mouse.bin').read_bytes())
        decoded = api.decode_report(d,ReportKey('input',2),bytes.fromhex('020550a0ff'))
        self.assertEqual([v.value for v in decoded.values],[1,0,1,0,0,80,-96,-1])
        self.assertTrue(decoded.all_fields_in_range)

    def test_signedness_change_has_separating_witness(self):
        api = self.api()
        old = parse(simple(bounds='150025ff'))
        new = parse(simple(bounds='1580257f'))
        result = api.compare_descriptors(old,new)
        self.assertEqual(result.witnesses[0].wire_hex, '80')
        self.assertEqual((result.witnesses[0].old_value,result.witnesses[0].new_value),(128,-128))
        self.assertTrue(api.verify_witness(old,new,result.witnesses[0]))
