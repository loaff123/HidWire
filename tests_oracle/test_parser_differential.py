"""External parser/value differential checks; no product-derived expectations."""
import importlib
import unittest
from pathlib import Path
from tests_oracle.adapter import ReferenceDescriptor
from tests_oracle.cases import CASES, scalar_descriptor, slow_bit_value

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'real'


class ParserDifferential(unittest.TestCase):
    def parse(self, data):
        parser = importlib.import_module('hidwire.parser')
        self.assertTrue(hasattr(parser, 'parse_descriptor'), 'parser tests require parse_descriptor')
        return parser.parse_descriptor(data)

    def check_case(self, data, expected_usages=None):
        actual = self.parse(data)
        self.assertEqual(actual.status, 'supported', actual.diagnostics)
        reference = ReferenceDescriptor(data)
        product_reports = {(r.key.kind, r.key.report_id): r for r in actual.reports}
        self.assertEqual(set(product_reports), set(reference.keys))
        observed_usages = []
        for key in reference.keys:
            ref = reference.report(key)
            prod = product_reports[key]
            self.assertEqual(prod.diagnostics, ())
            self.assertEqual((prod.payload_bits, prod.wire_bytes), (ref.payload_bits, ref.wire_bytes))
            self.assertEqual(len(prod.fields), len(ref.fields))
            for p, r in zip(prod.fields, ref.fields):
                self.assertEqual((p.key.page << 16) | p.key.usage, r.usage)
                observed_usages.append(r.usage)
                self.assertEqual((p.bit_offset, p.width, p.signed, p.logical_min, p.logical_max,
                                  p.flags, p.unit, p.unit_exponent),
                                 (r.bit_offset, r.width, r.signed, r.logical_min, r.logical_max,
                                  r.flags, r.unit, r.unit_exponent))
                # The oracle exposes raw zeros for absent physical bounds. Test
                # only its known both-zero default here; partial defaults have
                # independent hand-authored expectations in the metadata tests.
                if r.physical_min_raw == r.physical_max_raw == 0:
                    expected_physical = (r.logical_min, r.logical_max)
                else:
                    expected_physical = (r.physical_min_raw, r.physical_max_raw)
                self.assertEqual((p.physical_min, p.physical_max), expected_physical)
            for byte in (0, 1, 0x7f, 0x80, 0xa5, 0xff):
                payload = bytes([byte]) * (ref.payload_bits // 8)
                wire = payload if key[1] is None else bytes([key[1]]) + payload
                values = reference.decode_values(key, wire)
                for p, value in zip(prod.fields, values):
                    self.assertEqual(slow_bit_value(payload, p.bit_offset, p.width, p.signed),
                                     value)
        if expected_usages is not None:
            self.assertEqual(tuple(observed_usages), expected_usages)
        return actual

    def test_every_accepted_grammar_category(self):
        for case in CASES:
            with self.subTest(case=case.name):
                self.check_case(bytes.fromhex(case.hex), case.expected_usages)

    def test_real_mouse_and_waratah_fields(self):
        for name in ('circuitpython-mouse.bin', 'waratah-mouse.bin'):
            with self.subTest(name=name):
                self.check_case((FIXTURES / name).read_bytes())

    def test_every_scalar_width_and_cross_byte_start(self):
        for signed in (False, True):
            for width in range(1 + int(signed), 33):
                for start in (0, 1, 3, 7):
                    with self.subTest(signed=signed, width=width, start=start):
                        self.check_case(scalar_descriptor(width, signed, start), (0x10030,))

    def test_all_canonical_unit_exponents(self):
        for nibble in range(16):
            data = bytes.fromhex('05010902a1011500257f75089501093055') + bytes([nibble]) + bytes.fromhex('8102c0')
            with self.subTest(nibble=nibble):
                desc = self.check_case(data)
                self.assertEqual(desc.reports[0].fields[0].unit_exponent,
                                 nibble if nibble < 8 else nibble - 16)

    def test_all_supported_unit_system_values(self):
        for system in (0,1,2,3,4,15):
            data = bytes.fromhex('05010902a1011500257f75089501093065') + bytes([system]) + bytes.fromhex('8102c0')
            with self.subTest(system=system):
                desc = self.check_case(data)
                self.assertEqual(desc.reports[0].fields[0].unit, system)

    def test_all_supported_collection_types(self):
        for kind in range(4):
            data = bytes.fromhex('05010902a1') + bytes([kind]) + bytes.fromhex('1500257f7508950109308102c0')
            with self.subTest(kind=kind):
                desc = self.check_case(data)
                self.assertEqual([(c.kind, c.page, c.usage) for c in desc.reports[0].fields[0].key.path],
                                 [(kind, 1, 2)])

    def test_one_two_four_byte_item_encodings(self):
        # All of these represent the same simple scalar (local usages with four
        # bytes explicitly include page 1, unlike ordinary one/two-byte usages).
        descriptors = [
            '05010902a1011500257f7508950109308102c0',
            '0601000a0200a20100160000267f007608009601000a3000820200c0',
            '07010000000b02000100a3010000001700000000277f000000770800000097010000000b300001008302000000c0',
        ]
        for h in descriptors:
            with self.subTest(hex=h):
                self.check_case(bytes.fromhex(h), (0x10030,))

    def test_deterministic_representation_preserving_rewrites(self):
        original = (FIXTURES / 'circuitpython-mouse.bin').read_bytes()
        redundant = bytes.fromhex('0501') + original
        wide = original.replace(bytes.fromhex('7508'), bytes.fromhex('760800'))
        range_buttons = bytes.fromhex('19012905')
        explicit = original.replace(range_buttons, bytes.fromhex('09010902090309040905'))
        split_axes = original.replace(bytes.fromhex('093009311581257f750895028106'),
                                      bytes.fromhex('1581257f750895010930810609318106'))
        padding_split = original.replace(bytes.fromhex('950175038101'),
                                         bytes.fromhex('95017501810175028103'))
        for data in (original, redundant, wide, explicit, split_axes, padding_split):
            with self.subTest(hex=data.hex()):
                actual = self.check_case(data)
                report = actual.reports[0]
                self.assertEqual((report.payload_bits, report.wire_bytes), (32, 5))
                self.assertEqual([(f.key.page, f.key.usage, f.bit_offset) for f in report.fields],
                    [(9, i, i-1) for i in range(1, 6)] + [(1, 0x30, 8), (1, 0x31, 16), (1, 0x38, 24)])

    def test_cross_byte_12bit_signed_exhaustive_16bit_payload(self):
        data = scalar_descriptor(12, True, 3)
        actual = self.check_case(data)
        scalar = actual.reports[0].fields[0]
        ref = ReferenceDescriptor(data).report(('input', None)).fields[0]._oracle
        for raw in range(65536):
            payload = raw.to_bytes(2, 'little')
            expected_unsigned = (raw // 8) % 4096
            expected = expected_unsigned if expected_unsigned < 2048 else expected_unsigned - 4096
            self.assertEqual(slow_bit_value(payload, scalar.bit_offset, scalar.width, scalar.signed), expected)
            self.assertEqual(ref.get_values(list(payload)), [expected])

    def test_product_mouse_matches_full_recorded_sweeps(self):
        data = (FIXTURES / 'circuitpython-mouse.bin').read_bytes()
        product = self.check_case(data)
        fields = {(f.key.page << 16) | f.key.usage: f for f in product.reports[0].fields}
        reference = {f.usage: f._oracle for f in ReferenceDescriptor(data).report(('input', 2)).fields}
        for x in range(256):
            for y in range(256):
                payload = bytes([0, x, y, 0])
                for usage in (0x10030, 0x10031):
                    f = fields[usage]
                    self.assertEqual(slow_bit_value(payload, f.bit_offset, f.width, f.signed),
                                     reference[usage].get_values([2, 0, x, y, 0])[0])
        for buttons in range(32):
            for i in range(5):
                f = fields[0x90001+i]
                self.assertEqual(slow_bit_value(bytes([buttons,0,0,0]), f.bit_offset, f.width, f.signed),
                                 (buttons >> i) & 1)
        for wheel in range(256):
            f = fields[0x10038]
            self.assertEqual(slow_bit_value(bytes([0,0,0,wheel]), f.bit_offset, f.width, f.signed),
                             reference[0x10038].get_values([2,0,0,0,wheel])[0])


if __name__ == '__main__':
    unittest.main()
