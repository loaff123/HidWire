"""Goldens authored from the descriptor bytes and HID wire rules, not HidWire."""
import importlib.util
import unittest
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'real'
MOUSE_VALUES = {0x90001: 1, 0x90002: 0, 0x90003: 1, 0x90004: 0,
                0x90005: 0, 0x10030: 80, 0x10031: -96, 0x10038: -1}
PLAIN = bytes.fromhex('05010902a101150025ff7508950109308102c0')


class AdapterGoldens(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('tests_oracle.adapter'),
                             'independent oracle adapter is required, never skipped')
        from tests_oracle.adapter import ReferenceDescriptor
        self.ReferenceDescriptor = ReferenceDescriptor

    def reference(self, filename):
        return self.ReferenceDescriptor((FIXTURES / filename).read_bytes())

    def test_adapter_has_no_product_import(self):
        import ast
        module = ast.parse((Path(__file__).with_name('adapter.py')).read_text())
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                self.assertFalse(any(alias.name.startswith('hidwire') for alias in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or '').startswith('hidwire'))

    def test_pinned_versions(self):
        from tests_oracle.adapter import oracle_versions
        self.assertEqual(oracle_versions(), {'hid-tools': '0.12', 'parse': '1.22.3'})

    def test_mouse_numeric_golden(self):
        ref = self.reference('circuitpython-mouse.bin')
        self.assertEqual(ref.decode(('input', 2), bytes.fromhex('020550a0ff')), MOUSE_VALUES)
        report = ref.report(('input', 2))
        self.assertEqual((report.payload_bits, report.wire_bytes), (32, 5))
        self.assertEqual([(f.usage, f.bit_offset, f.width, f.signed) for f in report.fields],
                         [(0x90000+i, i-1, 1, False) for i in range(1, 6)] +
                         [(0x10030, 8, 8, True), (0x10031, 16, 8, True),
                          (0x10038, 24, 8, True)])

    def test_waratah_numeric_golden(self):
        ref = self.reference('waratah-mouse.bin')
        self.assertEqual(ref.decode(('input', 1), bytes.fromhex('0150a005')),
                         {0x10030:80, 0x10031:-96, 0x90001:1, 0x90002:0, 0x90003:1})
        self.assertEqual((ref.report(('input', 1)).payload_bits,
                          ref.report(('input', 1)).wire_bytes), (24, 4))

    def test_keyboard_output_numeric_golden(self):
        ref = self.reference('circuitpython-keyboard.bin')
        self.assertEqual(ref.decode(('output', 1), bytes.fromhex('0115')),
                         {0x80001:1, 0x80002:0, 0x80003:1, 0x80004:0, 0x80005:1})
        self.assertEqual((ref.report(('output', 1)).payload_bits,
                          ref.report(('output', 1)).wire_bytes), (8, 2))

    def test_array_is_not_misrepresented_as_scalar(self):
        from tests_oracle.adapter import UnsupportedOracleReport
        for filename, key in [('circuitpython-keyboard.bin', ('input', 1)),
                              ('circuitpython-consumer-control.bin', ('input', 3))]:
            with self.subTest(filename=filename), self.assertRaises(UnsupportedOracleReport):
                self.reference(filename).report(key)

    def test_unnumbered_offset_and_no_phantom_prefix(self):
        ref = self.ReferenceDescriptor(PLAIN)
        report = ref.report(('input', None))
        self.assertEqual((report.key, report.payload_bits, report.wire_bytes),
                         (('input', None), 8, 1))
        self.assertEqual(report.fields[0].bit_offset, 0)
        self.assertEqual(ref.decode(('input', None), b'\xa5'), {0x10030:165})

    def test_exact_lengths_and_id_are_enforced(self):
        ref = self.reference('circuitpython-mouse.bin')
        for wire in [b'', bytes.fromhex('020550a0'), bytes.fromhex('020550a0ff00'),
                     bytes.fromhex('010550a0ff')]:
            with self.subTest(wire=wire.hex()), self.assertRaises(ValueError):
                ref.decode(('input', 2), wire)
        with self.assertRaises(ValueError):
            self.ReferenceDescriptor(PLAIN).decode(('input', None), b'\x00\xa5')
        with self.assertRaises(KeyError):
            ref.report(('feature', 2))

    def test_constant_only_report_retains_shape(self):
        ref = self.ReferenceDescriptor(bytes.fromhex('750895038103'))
        self.assertEqual(ref.report(('input', None)).payload_bits, 24)
        self.assertEqual(ref.report(('input', None)).wire_bytes, 3)
        self.assertEqual(ref.decode(('input', None), b'abc'), {})

    def test_nonbyte_aligned_report_is_not_rounded_silently(self):
        from tests_oracle.adapter import UnsupportedOracleReport
        ref = self.ReferenceDescriptor(bytes.fromhex('0501150025017501950109308102'))
        with self.assertRaises(UnsupportedOracleReport):
            ref.report(('input', None))

    def test_ordered_values_preserve_duplicate_numeric_usages(self):
        ref = self.ReferenceDescriptor(bytes.fromhex('0501150025ff75089502093009308102'))
        self.assertTrue(hasattr(ref, 'decode_values'), 'ordered decode is required for repeated usages')
        self.assertEqual(ref.decode_values(('input', None), b'\x01\x02'), (1,2))

    def test_missing_oracle_is_a_failure_not_a_skip(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, '-S', '-c', 'import tests_oracle.adapter'],
                                cwd=FIXTURES.parents[1], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Required oracle missing', result.stderr)

    def test_duplicate_numeric_usages_refuse_lossy_dictionary(self):
        from tests_oracle.adapter import UnsupportedOracleReport
        ref = self.ReferenceDescriptor(bytes.fromhex('0501150025ff75089502093009308102'))
        with self.assertRaises(UnsupportedOracleReport):
            ref.decode(('input', None), b'\x01\x02')


if __name__ == '__main__':
    unittest.main()
