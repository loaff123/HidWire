"""Independent reference sweeps, intentionally not an all-32-bit exhaustiveness claim."""
import unittest
from pathlib import Path
from tests_oracle.adapter import ReferenceDescriptor

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'real'


def signed_byte(raw):
    return raw if raw < 128 else raw - 256


class RealReportSweeps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mouse_bytes = (FIXTURES / 'circuitpython-mouse.bin').read_bytes()
        cls.reference = ReferenceDescriptor(cls.mouse_bytes)
        cls.fields = {f.usage: f._oracle for f in cls.reference.report(('input', 2)).fields}

    def test_all_65536_xy_byte_pairs(self):
        x, y = self.fields[0x10030], self.fields[0x10031]
        for raw_x in range(256):
            for raw_y in range(256):
                report = [2, 0, raw_x, raw_y, 0]
                self.assertEqual((x.get_values(report)[0], y.get_values(report)[0]),
                                 (signed_byte(raw_x), signed_byte(raw_y)))

    def test_all_32_button_combinations(self):
        for buttons in range(32):
            values = self.reference.decode(('input', 2), bytes([2, buttons, 0, 0, 0]))
            self.assertEqual([values[0x90001+i] for i in range(5)],
                             [(buttons >> i) & 1 for i in range(5)])

    def test_all_256_wheel_bytes(self):
        for raw in range(256):
            self.assertEqual(self.reference.decode(('input', 2), bytes([2, 0, 0, 0, raw]))[0x10038],
                             signed_byte(raw))

    def test_known_xy_swap_report(self):
        mutated = bytearray(self.mouse_bytes)
        self.assertEqual(mutated[36:40], bytes.fromhex('09300931'))
        mutated[36:40] = bytes.fromhex('09310930')
        old = self.reference.decode(('input', 2), bytes.fromhex('0200010000'))
        new = ReferenceDescriptor(bytes(mutated)).decode(('input', 2), bytes.fromhex('0200010000'))
        self.assertEqual((old[0x10030], old[0x10031]), (1, 0))
        self.assertEqual((new[0x10030], new[0x10031]), (0, 1))


if __name__ == '__main__':
    unittest.main()
