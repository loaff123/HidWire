import importlib
import unittest
from pathlib import Path
from hidwire.parser import parse_descriptor
from hidwire.model import ReportKey
from tests.helpers import simple

ROOT = Path(__file__).resolve().parents[1]

def parse(text):
    return parse_descriptor(bytes.fromhex(text))

class CompareTests(unittest.TestCase):
    def api(self):
        api = importlib.import_module('hidwire')
        self.assertTrue(hasattr(api, 'compare_descriptors'), 'comparison API missing')
        return api.compare_descriptors

    def test_equivalent_encodings(self):
        compare = self.api()
        base = simple()
        for other in [base, base.replace('7508', '760800'), base.replace('7508','7708000000'),
                      base.replace('7508', '75087508'), base.replace('7508', 'a475087508b47508')]:
            with self.subTest(other=other):
                result = compare(parse(base), parse(other))
                self.assertEqual(result.status, 'equal')
                self.assertEqual(result.differences, ())

    def test_usage_lists_ranges_and_main_splits(self):
        compare = self.api()
        base = '0501150025ff75089502093009318102'
        for other in ['0501150025ff75089502193029318102',
                      '0501150025ff750895010930810209318102']:
            self.assertEqual(compare(parse(base), parse(other)).status, 'equal')

    def test_padding_regrouping(self):
        compare = self.api()
        old = '750195088101'
        new = '750295048103'
        self.assertEqual(compare(parse(old), parse(new)).status, 'equal')
        self.assertEqual(compare(parse(old), parse('751095018101')).status, 'different')

    def test_real_swap_and_deterministic_lowest_bit(self):
        compare = self.api()
        raw = (ROOT / 'fixtures/real/circuitpython-mouse.bin').read_bytes()
        changed = bytearray(raw)
        self.assertEqual(changed[36:40], bytes.fromhex('09300931'))
        changed[36:40] = bytes.fromhex('09310930')
        result = compare(parse_descriptor(raw), parse_descriptor(bytes(changed)))
        self.assertEqual(result.status, 'different')
        self.assertEqual(len(result.witnesses), 2)
        self.assertEqual({w.wire_hex for w in result.witnesses}, {'0200010000'})
        self.assertEqual({(w.old_value, w.new_value) for w in result.witnesses}, {(1,0),(0,1)})

    def test_metadata_has_no_fabricated_value_witness(self):
        compare = self.api()
        result = compare(parse(simple()), parse(simple(flags='06')))
        self.assertEqual(result.status, 'different')
        self.assertEqual({d.kind for d in result.differences}, {'metadata'})
        self.assertEqual(result.witnesses, ())

    def test_report_shape_and_identity_changes(self):
        compare = self.api()
        for new in [simple(prefix='8501'), simple().replace('8102','9102'),
                    simple(usages='0931'), simple(suffix='750895018101')]:
            result = compare(parse(simple()), parse(new))
            self.assertEqual(result.status, 'different')
            self.assertTrue(any(d.kind == 'schema' for d in result.differences))
            self.assertEqual(result.witnesses, ())

    def test_blocked_identical_no_byte_fast_path_and_partial_results(self):
        compare = self.api()
        raw = (ROOT / 'fixtures/real/circuitpython-keyboard.bin').read_bytes()
        old = parse_descriptor(raw)
        self.assertEqual(compare(old,old).status, 'blocked')
        self.assertEqual(compare(old,old,(ReportKey('output',1),)).status, 'equal')
        changed = bytes(raw).replace(bytes.fromhex('9102'), bytes.fromhex('9106'))
        result = compare(old,parse_descriptor(changed))
        self.assertEqual(result.status, 'blocked')
        self.assertTrue(any(d.kind == 'metadata' for d in result.differences))

    def test_missing_selected_report_rules(self):
        compare = self.api()
        old, new = parse(simple()), parse(simple(prefix='8501'))
        self.assertEqual(compare(old,new,(ReportKey('input',None),)).status, 'different')
        with self.assertRaises(ValueError):
            compare(old,new,(ReportKey('output',9),))

    def test_invalid_precedes_blocked(self):
        compare = self.api()
        self.assertEqual(compare(parse('fe0199aa'),parse('75')).status, 'invalid')

    def test_empty_collection_schema(self):
        compare = self.api()
        self.assertEqual(compare(parse(simple()), parse(simple()+'05010903a101c0')).status, 'different')
