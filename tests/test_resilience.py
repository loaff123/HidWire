"""Deterministic parser robustness checks; these are not equivalence proofs."""
import random
import unittest
from hidwire.model import Limits
from hidwire.parser import parse_descriptor

class ResilienceTests(unittest.TestCase):
    def test_seeded_raw_bytes_never_escape_bounded_diagnostics(self):
        rng=random.Random(20261017)
        for _ in range(10000):
            data=rng.randbytes(rng.randrange(257))
            result=parse_descriptor(data)
            self.assertIn(result.status,('supported','blocked','invalid'))
            self.assertLessEqual(len(result.reports),64)
            self.assertLessEqual(sum(len(r.fields) for r in result.reports),1024)
            self.assertTrue(all(r.payload_bits <=8192 for r in result.reports))

    def test_structural_depth_bombs_are_bounded(self):
        for data in (b'\xa4'*4096, b'\xc0'*4096, bytes.fromhex('05010902a101')*682):
            result=parse_descriptor(data)
            self.assertIn(result.status,('blocked','invalid'))

    def test_limit_records_validate_values(self):
        for invalid in (0,-1,True,1.5,'32'):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                Limits(max_fields=invalid)
