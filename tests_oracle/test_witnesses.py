"""Replay generated separating reports in pinned, independent hid-tools 0.12.

The raw external discrepancies are asserted, never normalized away: signed
one-bit extraction and negative-maximum range metadata use the independent
literal-fixture oracle instead. See docs/oracle-notes.md for reviewed authority.
"""
from dataclasses import replace
from pathlib import Path
import unittest

from hidwire import compare_descriptors, decode_report, parse_descriptor, verify_witness
from hidwire.model import ReportKey
from tests.test_exhaustive import BY_NAME, comparable_pairs, slow_range, slow_values
from tests_oracle.adapter import ReferenceDescriptor

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'real'


def numeric(identity):
    return identity[0] * 65536 + identity[1]


class ExternalWitnessTests(unittest.TestCase):
    def test_every_small_model_emitted_witness_replayed_externally(self):
        replayed = exceptional_value_cells = exceptional_range_cells = 0
        for left,right in comparable_pairs():
            result = compare_descriptors(parse_descriptor(left.data),parse_descriptor(right.data))
            refs = [ReferenceDescriptor(case.data) for case in (left,right)]
            for witness in result.witnesses:
                replayed += 1
                wire = bytes.fromhex(witness.wire_hex)
                identity = witness.differing_key.page,witness.differing_key.usage
                external_values = []
                for side,(case,ref) in enumerate(zip((left,right),refs)):
                    with self.subTest(old=left.name,new=right.name,side=side,wire=wire.hex()):
                        expected = slow_values(case,wire)
                        raw_external = ref.decode(case.key,wire)
                        recorded = (witness.old_value,witness.new_value)[side]
                        recorded_range = (witness.old_range_valid,witness.new_range_valid)[side]
                        self.assertEqual(recorded,expected[identity])
                        self.assertEqual(recorded_range,slow_range(case,expected))
                        for field in case.fields:
                            observed = raw_external[numeric(field.identity)]
                            if field.signed and field.width == 1 and expected[field.identity] == -1:
                                # Exact pre-existing external capability gap.
                                self.assertEqual(observed,1)
                                exceptional_value_cells += 1
                            else:
                                self.assertEqual(observed,expected[field.identity])
                        raw_fields = ref.report(case.key).fields
                        if any(field.high < 0 for field in case.fields):
                            # Raw extraction still checked above; external
                            # maximum metadata cannot decide range validity.
                            self.assertEqual([f.logical_max for f in raw_fields],[255])
                            exceptional_range_cells += 1
                        elif not any(field.signed and field.width == 1 for field in case.fields):
                            external_range = all(f.logical_min <= raw_external[f.usage] <= f.logical_max
                                                 for f in raw_fields)
                            self.assertEqual(recorded_range,external_range)
                        external_values.append(raw_external[numeric(identity)])
                if not any(f.signed and f.width == 1 and f.identity == identity
                           for case in (left,right) for f in case.fields):
                    self.assertNotEqual(*external_values)
                self.assertTrue(verify_witness(result.old,result.new,witness))
        self.assertGreater(replayed,50)
        self.assertGreater(exceptional_value_cells,0)
        self.assertGreater(exceptional_range_cells,0)

    def test_real_mouse_xy_swap_generated_witnesses(self):
        raw = (FIXTURES/'circuitpython-mouse.bin').read_bytes()
        self.assertEqual(raw[36:40],bytes.fromhex('09300931'))
        swapped = raw[:36] + bytes.fromhex('09310930') + raw[40:]
        old,new = parse_descriptor(raw),parse_descriptor(swapped)
        result = compare_descriptors(old,new)
        self.assertEqual(result.status,'different')
        self.assertEqual(len(result.witnesses),2)
        refs = ReferenceDescriptor(raw),ReferenceDescriptor(swapped)
        self.assertEqual({w.differing_key.usage for w in result.witnesses},{0x30,0x31})
        for witness in result.witnesses:
            self.assertEqual(witness.wire_hex,'0200010000')
            wire = bytes.fromhex(witness.wire_hex)
            left,right = [ref.decode(ReportKey('input',2),wire) for ref in refs]
            key = numeric((witness.differing_key.page,witness.differing_key.usage))
            self.assertEqual((witness.old_value,witness.new_value),(left[key],right[key]))
            self.assertNotEqual(left[key],right[key])
            self.assertTrue(witness.old_range_valid)
            self.assertTrue(witness.new_range_valid)
            self.assertTrue(verify_witness(old,new,witness))
            self.assertEqual((left[0x10030],left[0x10031]),(1,0))
            self.assertEqual((right[0x10030],right[0x10031]),(0,1))

    def test_witnesses_for_each_direction_and_framing(self):
        for kind,main in (('input','81'),('output','91'),('feature','b1')):
            for report_id in (None,1,255):
                prefix = '' if report_id is None else f'85{report_id:02x}'
                pair = [replace(BY_NAME[name],kind=kind,report_id=report_id,
                                hex=prefix+BY_NAME[name].hex.replace('81',main))
                        for name in ('xy3','yx3')]
                result = compare_descriptors(*(parse_descriptor(case.data) for case in pair))
                self.assertEqual(len(result.witnesses),2)
                for witness in result.witnesses:
                    with self.subTest(kind=kind,report_id=report_id,usage=witness.differing_key.usage):
                        self.assertEqual(witness.report_key,ReportKey(kind,report_id))
                        wire = bytes.fromhex(witness.wire_hex)
                        self.assertEqual(len(wire),1+int(report_id is not None))
                        expected = []
                        key = numeric((witness.differing_key.page,witness.differing_key.usage))
                        for case in pair:
                            external = ReferenceDescriptor(case.data).decode(case.key,wire)
                            self.assertEqual(external,{numeric(k):v for k,v in slow_values(case,wire).items()})
                            expected.append(external[key])
                        self.assertEqual((witness.old_value,witness.new_value),tuple(expected))
                        self.assertNotEqual(*expected)

    def test_signed_one_bit_oracle_nonseparation_is_explicit(self):
        signed,unsigned = BY_NAME['s1_at0'],BY_NAME['u1_at0']
        result = compare_descriptors(parse_descriptor(signed.data),parse_descriptor(unsigned.data))
        self.assertEqual(len(result.witnesses),1)
        witness = result.witnesses[0]
        self.assertEqual((witness.wire_hex,witness.old_value,witness.new_value),('01',-1,1))
        # hid-tools returns 1 on both descriptors. Do not claim external
        # separating-witness verification for this precise known exception.
        self.assertEqual(ReferenceDescriptor(signed.data).decode(signed.key,b'\x01'),{0x10030:1})
        self.assertEqual(ReferenceDescriptor(unsigned.data).decode(unsigned.key,b'\x01'),{0x10030:1})
        self.assertEqual(slow_values(signed,b'\x01'),{(1,0x30):-1})
        self.assertEqual(slow_values(unsigned,b'\x01'),{(1,0x30):1})
        self.assertTrue(verify_witness(result.old,result.new,witness))

    def test_negative_maximum_external_range_disagreement_is_explicit(self):
        left,right = BY_NAME['negative8_at0'],BY_NAME['negative8_at8']
        result = compare_descriptors(parse_descriptor(left.data),parse_descriptor(right.data))
        self.assertEqual(len(result.witnesses),1)
        witness = result.witnesses[0]
        self.assertEqual((witness.wire_hex,witness.old_value,witness.new_value),('0100',1,0))
        self.assertEqual((witness.old_range_valid,witness.new_range_valid),(False,False))
        for case in (left,right):
            ref = ReferenceDescriptor(case.data)
            field = ref.report(case.key).fields[0]
            self.assertEqual((field.logical_min,field.logical_max),(-128,255))
            values = ref.decode(case.key,bytes.fromhex(witness.wire_hex))
            self.assertTrue(field.logical_min <= values[field.usage] <= field.logical_max)
            self.assertFalse(slow_range(case,slow_values(case,bytes.fromhex(witness.wire_hex))))
            # Negative-value raw extraction is trustworthy in this same case.
            self.assertEqual(ref.decode(case.key,b'\xff\xff'),{0x10030:-1})
            self.assertEqual(decode_report(parse_descriptor(case.data),case.key,b'\xff\xff').values[0].value,-1)

    def test_metadata_only_change_externally_agrees_for_every_payload(self):
        left,right = BY_NAME['u3_at0'],BY_NAME['u3_relative']
        result = compare_descriptors(parse_descriptor(left.data),parse_descriptor(right.data))
        self.assertEqual(result.status,'different')
        self.assertEqual(result.witnesses,())
        refs = ReferenceDescriptor(left.data),ReferenceDescriptor(right.data)
        for raw in range(256):
            wire = bytes([raw])
            self.assertEqual(refs[0].decode(left.key,wire),refs[1].decode(right.key,wire))
            self.assertEqual(refs[0].decode(left.key,wire),{0x10030:raw % 8})


if __name__ == '__main__':
    unittest.main()
