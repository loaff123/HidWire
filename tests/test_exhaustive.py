"""Independent finite-domain proof checks for the supported scalar contract.

Descriptor bytes AND expected layouts below are test-authored. Expectations never
come from product Scalars, coefficient vectors, or product extraction helpers.
The slow decoder reconstructs digits one at a time, then interprets a binary
number, rather than sharing the comparator's coefficient-vector implementation.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from itertools import combinations_with_replacement
import unittest

from hidwire import compare_descriptors, decode_report, parse_descriptor, verify_witness
from hidwire.model import ReportKey


@dataclass(frozen=True)
class ExpectedField:
    usage: int
    start: int
    width: int
    signed: bool
    low: int
    high: int
    flags: int = 2
    page: int = 1

    @property
    def identity(self):
        return self.page, self.usage

    @property
    def metadata(self):
        # Every fixture below leaves physical bounds/unit/exponent absent.
        return self.low, self.high, self.low, self.high, 0, 0, self.flags


@dataclass(frozen=True)
class SmallCase:
    name: str
    hex: str
    bits: int
    fields: tuple[ExpectedField, ...]
    report_id: int | None = None
    kind: str = 'input'

    @property
    def data(self):
        return bytes.fromhex(self.hex)

    @property
    def key(self):
        return ReportKey(self.kind, self.report_id)

    def wire(self, payload):
        return (b'' if self.report_id is None else bytes([self.report_id])) + payload


def slow_values(case, wire):
    """Read only literal test expectations; no parser/model/compare access."""
    prefix = int(case.report_id is not None)
    if len(wire) != case.bits // 8 + prefix:
        raise ValueError('incorrect exact wire size')
    if prefix and wire[0] != case.report_id:
        raise ValueError('incorrect report ID')
    digits = []
    for octet in wire[prefix:]:
        for _ in range(8):
            octet, digit = divmod(octet, 2)
            digits.append(digit)
    result = {}
    for field in case.fields:
        selected = digits[field.start:field.start + field.width]
        value = 0
        for digit in reversed(selected):
            value = value * 2 + digit
        if field.signed and selected[-1]:
            value -= 2 ** len(selected)
        result[field.identity] = value
    return result


def slow_range(case, values):
    return all(field.low <= values[field.identity] <= field.high for field in case.fields)


F = ExpectedField
CASES = (
    SmallCase('u3_at0', '050115002507750395010930810275058101', 8, (F(0x30,0,3,False,0,7),)),
    SmallCase('u3_at1', '05011500250795017501810175030930810275048101', 8, (F(0x30,1,3,False,0,7),)),
    SmallCase('u4_at0', '050115002507750495010930810275048101', 8, (F(0x30,0,4,False,0,7),)),
    SmallCase('u3_wide_items', '0601001600002607007603009601000a3000820200760500820100', 8, (F(0x30,0,3,False,0,7),)),
    SmallCase('u3_relative', '050115002507750395010930810675058101', 8, (F(0x30,0,3,False,0,7,6),)),
    SmallCase('s3_at0', '050115fc2503750395010930810275058101', 8, (F(0x30,0,3,True,-4,3),)),
    SmallCase('s3_at1', '050115fc250395017501810175030930810275048101', 8, (F(0x30,1,3,True,-4,3),)),
    SmallCase('s4_at0', '050115fc2503750495010930810275048101', 8, (F(0x30,0,4,True,-4,3),)),
    SmallCase('u1_at0', '050115002501750195010930810275078101', 8, (F(0x30,0,1,False,0,1),)),
    SmallCase('s1_at0', '050115ff2500750195010930810275078101', 8, (F(0x30,0,1,True,-1,0),)),
    SmallCase('xy3', '05011500250775039502093009318102750295018101', 8,
              (F(0x30,0,3,False,0,7), F(0x31,3,3,False,0,7))),
    SmallCase('yx3', '05011500250775039502093109308102750295018101', 8,
              (F(0x31,0,3,False,0,7), F(0x30,3,3,False,0,7))),
    SmallCase('xyz_positive', '05011500250775039502093009318102150125037502950109328102', 8,
              (F(0x30,0,3,False,0,7), F(0x31,3,3,False,0,7), F(0x32,6,2,False,1,3))),
    SmallCase('yxz_positive', '05011500250775039502093109308102150125037502950109328102', 8,
              (F(0x31,0,3,False,0,7), F(0x30,3,3,False,0,7), F(0x32,6,2,False,1,3))),
    SmallCase('s12_at3', '05011600f826ff07950175038101750c0930810275018101', 16,
              (F(0x30,3,12,True,-2048,2047),)),
    SmallCase('s12_at4', '05011600f826ff07950175048101750c09308102', 16,
              (F(0x30,4,12,True,-2048,2047),)),
    SmallCase('s13_at3', '05011600f826ff07950175038101750d09308102', 16,
              (F(0x30,3,13,True,-2048,2047),)),
    SmallCase('u12_at3', '0501150026ff07950175038101750c0930810275018101', 16,
              (F(0x30,3,12,False,0,2047),)),
    SmallCase('negative8_at0', '0501158025ff75089501093081028101', 16,
              (F(0x30,0,8,True,-128,-1),)),
    SmallCase('negative8_at8', '0501158025ff75089501810109308102', 16,
              (F(0x30,8,8,True,-128,-1),)),
    SmallCase('numbered_xy8', '850205011580257f75089502093009318102', 16,
              (F(0x30,0,8,True,-128,127), F(0x31,8,8,True,-128,127)), 2),
    SmallCase('numbered_yx8', '850205011580257f75089502093109308102', 16,
              (F(0x31,0,8,True,-128,127), F(0x30,8,8,True,-128,127)), 2),
)
BY_NAME = {case.name: case for case in CASES}


def comparable_pairs():
    """All same-framing/same-identity pairs, including equivalent rewrites."""
    for left, right in combinations_with_replacement(CASES, 2):
        if (left.key, left.bits, {f.identity for f in left.fields}) == (
                right.key, right.bits, {f.identity for f in right.fields}):
            yield left, right


@lru_cache(maxsize=None)
def truth_table(case):
    identities = sorted(field.identity for field in case.fields)
    return tuple(tuple(values[identity] for identity in identities)
                 for raw in range(2 ** case.bits)
                 for values in [slow_values(case, case.wire(raw.to_bytes(case.bits // 8, 'little')))])


class ExhaustiveComparisonTests(unittest.TestCase):
    def assert_case(self, case):
        desc = parse_descriptor(case.data)
        self.assertEqual(desc.status, 'supported', (case.name, desc.diagnostics))
        self.assertEqual(len(desc.reports), 1)
        report = desc.reports[0]
        self.assertEqual((report.key, report.payload_bits, report.wire_bytes),
                         (case.key, case.bits, case.bits // 8 + int(case.report_id is not None)))
        self.assertEqual([(s.key.page,s.key.usage,s.bit_offset,s.width,s.signed,s.logical_min,s.logical_max,s.flags)
                          for s in report.fields],
                         [(f.page,f.usage,f.start,f.width,f.signed,f.low,f.high,f.flags) for f in case.fields])
        return desc

    def assert_replayed(self, left, right, result):
        for witness in result.witnesses:
            wire = bytes.fromhex(witness.wire_hex)
            a, b = slow_values(left, wire), slow_values(right, wire)
            identity = witness.differing_key.page, witness.differing_key.usage
            self.assertNotEqual(a[identity], b[identity])
            self.assertEqual((witness.old_value, witness.new_value), (a[identity], b[identity]))
            self.assertEqual((witness.old_range_valid, witness.new_range_valid),
                             (slow_range(left,a), slow_range(right,b)))
            self.assertEqual(witness.old_hash, hashlib.sha256(left.data).hexdigest())
            self.assertEqual(witness.new_hash, hashlib.sha256(right.data).hexdigest())
            self.assertTrue(verify_witness(result.old, result.new, witness))
            # A slow direct replay, not coefficient inspection, determines the
            # first separating one-hot bit and expected deterministic witness.
            for bit in range(left.bits):
                candidate = left.wire((2 ** bit).to_bytes(left.bits // 8, 'little'))
                if slow_values(left,candidate)[identity] != slow_values(right,candidate)[identity]:
                    self.assertEqual(wire, candidate)
                    break
            else:
                self.fail('claimed difference has no separating one-hot payload')

    def test_all_payloads_match_independent_slow_decoder(self):
        for case in CASES:
            with self.subTest(case=case.name):
                desc = self.assert_case(case)
                for raw in range(2 ** case.bits):
                    wire = case.wire(raw.to_bytes(case.bits // 8, 'little'))
                    expected = slow_values(case, wire)
                    decoded = decode_report(desc, case.key, wire)
                    actual = {(v.key.page,v.key.usage): v.value for v in decoded.values}
                    self.assertEqual(actual, expected, (case.name, wire.hex()))
                    outside = {f.identity for f in case.fields if not f.low <= expected[f.identity] <= f.high}
                    self.assertEqual(decoded.all_fields_in_range, not outside)
                    self.assertEqual({(key.page,key.usage) for key in decoded.out_of_range_keys}, outside)
                    self.assertEqual({(v.key.page,v.key.usage) for v in decoded.values if not v.in_range}, outside)

    def test_comparison_iff_every_raw_decode_and_metadata_agree(self):
        for left, right in comparable_pairs():
            with self.subTest(old=left.name, new=right.name):
                a, b = self.assert_case(left), self.assert_case(right)
                result = compare_descriptors(a,b)
                raw_equal = truth_table(left) == truth_table(right)
                metadata_equal = ({f.identity:f.metadata for f in left.fields} ==
                                  {f.identity:f.metadata for f in right.fields})
                self.assertEqual(result.status, 'equal' if raw_equal and metadata_equal else 'different')
                self.assertEqual(not any(d.kind == 'raw_value' for d in result.differences), raw_equal)
                self.assertEqual(not any(d.kind == 'metadata' for d in result.differences), metadata_equal)
                self.assertFalse(any(d.kind == 'schema' for d in result.differences))
                identities = sorted(f.identity for f in left.fields)
                changed = {identity for i,identity in enumerate(identities)
                           if any(x[i] != y[i] for x,y in zip(truth_table(left),truth_table(right)))}
                self.assertEqual({(w.differing_key.page,w.differing_key.usage) for w in result.witnesses}, changed)
                self.assertEqual(len(result.witnesses), len(changed))
                self.assert_replayed(left,right,result)

    def test_signed_one_bit_truth_table_every_bit_position(self):
        for start in range(8):
            # This independent encoding covers the known hid-tools 0.12 gap.
            text = '050115ff25009501'
            if start:
                text += f'75{start:02x}8101'
            text += '750109308102'
            if start < 7:
                text += f'75{7-start:02x}8101'
            case = SmallCase(f's1_at{start}',text,8,(F(0x30,start,1,True,-1,0),))
            desc = self.assert_case(case)
            for byte in range(256):
                expected = -((byte // (2 ** start)) % 2)
                actual = decode_report(desc,case.key,bytes([byte]))
                self.assertEqual(actual.values[0].value, expected)
                self.assertEqual(slow_values(case,bytes([byte])), {(1,0x30):expected})

    def test_metadata_only_difference_has_equal_complete_truth_tables(self):
        left, right = BY_NAME['u3_at0'], BY_NAME['u3_relative']
        self.assertEqual(truth_table(left),truth_table(right))
        result = compare_descriptors(self.assert_case(left),self.assert_case(right))
        self.assertEqual(result.status,'different')
        self.assertEqual([d.kind for d in result.differences],['metadata'])
        self.assertEqual(result.witnesses,())

    def test_unrelated_positive_minimum_invalidates_whole_report_witness(self):
        left, right = BY_NAME['xyz_positive'], BY_NAME['yxz_positive']
        result = compare_descriptors(self.assert_case(left),self.assert_case(right))
        self.assertEqual(len(result.witnesses),2)
        self.assert_replayed(left,right,result)
        for witness in result.witnesses:
            self.assertEqual(witness.wire_hex,'01')
            self.assertFalse(witness.old_range_valid)
            self.assertFalse(witness.new_range_valid)
            # The changed X and Y are individually in range on both sides.
            self.assertTrue(all(0 <= value <= 7 for identity,value in slow_values(left,b'\x01').items()
                                if identity != (1,0x32)))

    def test_signedness_change_requires_a_real_separating_witness(self):
        left, right = BY_NAME['s1_at0'], BY_NAME['u1_at0']
        result = compare_descriptors(self.assert_case(left),self.assert_case(right))
        self.assertEqual(result.status,'different')
        self.assertEqual(len(result.witnesses),1)
        self.assert_replayed(left,right,result)
        witness = result.witnesses[0]
        self.assertEqual((witness.wire_hex,witness.old_value,witness.new_value),('01',-1,1))

    def test_numbered_payload_never_treats_id_as_a_free_bit(self):
        left, right = BY_NAME['numbered_xy8'], BY_NAME['numbered_yx8']
        result = compare_descriptors(self.assert_case(left),self.assert_case(right))
        self.assertEqual(len(result.witnesses),2)
        self.assert_replayed(left,right,result)
        self.assertEqual({w.wire_hex for w in result.witnesses},{'020100'})
        decoded = decode_report(result.old,left.key,bytes.fromhex('0280ff'))
        self.assertEqual([v.value for v in decoded.values],[-128,-1])


if __name__ == '__main__':
    unittest.main()
