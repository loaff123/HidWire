"""Hand-authored metadata, collection and source-span goldens.

hid-tools cannot supply the full source/collection model. Expected values below
are read directly from explicit test bytes and the HID state rules, never from
product output. Known reference disagreements remain visible in separate tests.
"""
import unittest
from pathlib import Path
from hidwire.parser import parse_descriptor
from tests_oracle.adapter import ReferenceDescriptor
from tests_oracle.cases import scalar_descriptor, slow_bit_value

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'real'
SIGNED_ONE_BIT = '05010902a10115ff25007501950109308102750795018101c0'
ID_PUSH_POP = '05010902a10185011500257f7508950109308102a4850209318102b409388102c0'


class IndependentMetadata(unittest.TestCase):
    def test_mouse_collection_tree_and_precise_spans(self):
        descriptor = parse_descriptor((FIXTURES / 'circuitpython-mouse.bin').read_bytes())
        root, = descriptor.collection_tree
        child, = root.children
        self.assertEqual((root.identity.kind, root.identity.page, root.identity.usage,
                          root.source.offset, root.source.length), (1, 1, 2, 4, 2))
        self.assertEqual((child.identity.kind, child.identity.page, child.identity.usage,
                          child.source.offset, child.source.length), (0, 1, 1, 8, 2))
        self.assertEqual(child.children, ())
        fields = descriptor.reports[0].fields
        for f in fields:
            self.assertEqual([(c.kind, c.page, c.usage) for c in f.key.path], [(1,1,2),(0,1,1)])
        for f in fields[:5]:
            self.assertEqual((f.sources.main.offset, f.sources.main.length), (26,2))
            self.assertEqual([(s.offset, s.length) for s in f.sources.usages], [(14,2),(16,2)])
            expected = {'usage_page':12, 'logical_min':18, 'logical_max':20,
                        'report_count':22, 'report_size':24, 'report_id':10}
            for name, offset in expected.items():
                self.assertEqual((f.sources.global_origin(name).offset,
                                  f.sources.global_origin(name).length), (offset,2))
        for f, usage_offset in zip(fields[5:7], [36,38]):
            self.assertEqual((f.sources.main.offset, f.sources.main.length), (48,2))
            self.assertEqual([(s.offset,s.length) for s in f.sources.usages], [(usage_offset,2)])
            expected = {'usage_page':34, 'logical_min':40, 'logical_max':42,
                        'report_count':46, 'report_size':44, 'report_id':10}
            for name, offset in expected.items():
                self.assertEqual(f.sources.global_origin(name).offset, offset)
        wheel = fields[-1]
        self.assertEqual(wheel.sources.main.offset, 60)
        self.assertEqual(wheel.sources.usages[0].offset, 50)
        self.assertEqual(wheel.sources.global_origin('report_size').offset, 56)
        self.assertIsNone(wheel.sources.global_origin('unit'))
        self.assertIsNone(wheel.sources.global_origin('physical_min'))

    def test_late_page_has_usage_and_effective_page_origins(self):
        data = bytes.fromhex('05010902a1011500257f75089501093005098102c0')
        f = parse_descriptor(data).reports[0].fields[0]
        self.assertEqual((f.key.page, f.key.usage), (9,0x30))
        self.assertEqual(f.sources.usages[0].offset, 14)
        self.assertEqual(f.sources.global_origin('usage_page').offset, 16)
        self.assertEqual(f.sources.main.offset, 18)

    def test_pop_restores_declaration_origins(self):
        data = bytes.fromhex('05010902a1011500257f7508950109308102a40509150125017501950109018102750795018101b409318102c0')
        f = parse_descriptor(data).reports[0].fields[-1]
        self.assertEqual((f.key.page,f.key.usage,f.bit_offset,f.width), (1,0x31,16,8))
        for name, offset in [('usage_page',0),('logical_min',6),('logical_max',8),
                             ('report_size',10),('report_count',12)]:
            self.assertEqual(f.sources.global_origin(name).offset, offset)

    def test_physical_default_normalization_is_explicit(self):
        for physical in ('', '35004500', '352a'):
            h = '05010902a1011581257f' + physical + '7508950109308102c0'
            with self.subTest(physical=physical):
                f = parse_descriptor(bytes.fromhex(h)).reports[0].fields[0]
                self.assertEqual((f.physical_min,f.physical_max),(-127,127))
                self.assertEqual((f.unit,f.unit_exponent),(0,0))
        f = parse_descriptor(bytes.fromhex('05010902a1011581257f350045647508950109308102c0')).reports[0].fields[0]
        self.assertEqual((f.physical_min,f.physical_max), (0,100))

    def test_metadata_only_relative_absolute_keeps_integer_extraction(self):
        data = (FIXTURES / 'circuitpython-mouse.bin').read_bytes()
        changed = data.replace(b'\x81\x06', b'\x81\x02')
        old, new = parse_descriptor(data), parse_descriptor(changed)
        payload = bytes.fromhex('0550a0ff')
        for left, right in zip(old.reports[0].fields, new.reports[0].fields):
            self.assertEqual((left.bit_offset,left.width,left.signed),(right.bit_offset,right.width,right.signed))
            self.assertEqual(slow_bit_value(payload,left.bit_offset,left.width,left.signed),
                             slow_bit_value(payload,right.bit_offset,right.width,right.signed))
        self.assertEqual([f.flags for f in old.reports[0].fields], [2]*5+[6]*3)
        self.assertEqual([f.flags for f in new.reports[0].fields], [2]*8)
        self.assertEqual(ReferenceDescriptor(data).decode(('input',2),b'\x02'+payload),
                         ReferenceDescriptor(changed).decode(('input',2),b'\x02'+payload))

    def test_real_array_reports_do_not_contaminate_keyboard_output(self):
        keyboard = parse_descriptor((FIXTURES / 'circuitpython-keyboard.bin').read_bytes())
        reports = {r.key.kind:r for r in keyboard.reports}
        self.assertEqual(keyboard.status,'blocked')
        self.assertEqual(keyboard.status_for((reports['output'].key,)),'supported')
        self.assertEqual(keyboard.status_for((reports['input'].key,)),'blocked')
        self.assertEqual([(f.key.page,f.key.usage,f.bit_offset) for f in reports['output'].fields],
                         [(8,i,i-1) for i in range(1,6)])
        self.assertEqual((reports['output'].payload_bits,reports['output'].wire_bytes),(8,2))
        consumer = parse_descriptor((FIXTURES / 'circuitpython-consumer-control.bin').read_bytes())
        self.assertEqual(consumer.status,'blocked')
        self.assertIn('data_array',{d.code for r in consumer.reports for d in r.diagnostics})

    def test_signed_one_bit_independent_exhaustive_truth_table(self):
        # HID 1.11 §5.8 / §6.2.2.7: a negative minimum selects two's complement.
        # This is independent semantic coverage, NOT external-oracle agreement.
        for start in range(8):
            descriptor = parse_descriptor(scalar_descriptor(1,True,start))
            self.assertEqual(descriptor.status,'supported')
            f = descriptor.reports[0].fields[0]
            self.assertEqual((f.width,f.signed,f.logical_min,f.logical_max),(1,True,-1,0))
            for byte in range(256):
                expected = -1 if byte & (1 << start) else 0
                self.assertEqual(slow_bit_value(bytes([byte]),f.bit_offset,f.width,f.signed),expected)

    def test_known_signed_one_bit_reference_gap_stays_visible(self):
        reference = ReferenceDescriptor(bytes.fromhex(SIGNED_ONE_BIT))
        actual = reference.decode(('input',None),b'\x01')[0x10030]
        self.assertEqual(actual,1, 'Investigate changed oracle capability before altering the exception')
        self.assertNotEqual(actual,-1, 'hid-tools is not an agreeing oracle for signed width 1')
        self.assertEqual(reference.decode(('input',None),b'\x00')[0x10030],0)

    def test_known_report_id_push_pop_gap_blocks_product(self):
        data = bytes.fromhex(ID_PUSH_POP)
        reference = ReferenceDescriptor(data)
        self.assertEqual([f.usage for f in reference.report(('input',1)).fields],[0x10030])
        self.assertEqual([f.usage for f in reference.report(('input',2)).fields],[0x10031,0x10038])
        # Correct global-state restoration would place Wheel in ID1, not ID2.
        product = parse_descriptor(data)
        self.assertEqual(product.status,'blocked')
        self.assertIn('report_id_in_push',{d.code for d in product.diagnostics})

    def test_negative_maxima_independent_metadata_goldens_and_reference_gap(self):
        # Keep the raw reference disagreement visible at every item width.
        for kind in ('logical','physical'):
            for width in (1,2,4):
                with self.subTest(kind=kind,width=width):
                    low_tag = ({1:0x15,2:0x16,4:0x17} if kind=='logical' else {1:0x35,2:0x36,4:0x37})[width]
                    high_tag = low_tag + 0x10
                    data = bytes.fromhex('05010902a101')
                    if kind=='physical':
                        data += bytes.fromhex('1580257f')
                    data += bytes([low_tag]) + (-128).to_bytes(width,'little',signed=True)
                    data += bytes([high_tag]) + (-1).to_bytes(width,'little',signed=True)
                    data += bytes.fromhex('7508950109308102c0')
                    product = parse_descriptor(data)
                    self.assertEqual(product.status,'supported')
                    p = product.reports[0].fields[0]
                    r = ReferenceDescriptor(data).report(('input',None)).fields[0]
                    actual = (p.logical_min,p.logical_max) if kind=='logical' else (p.physical_min,p.physical_max)
                    self.assertEqual(actual,(-128,-1))
                    reference_max = r.logical_max if kind=='logical' else r.physical_max_raw
                    self.assertEqual(reference_max,(1 << (8*width))-1)
                    self.assertNotEqual(reference_max,-1)
                    # This gap is metadata-only: raw sign extraction still agrees.
                    self.assertEqual(ReferenceDescriptor(data).decode(('input',None),b'\xff')[0x10030],-1)

    def test_zero_data_global_value_is_explicitly_outside_verified_subset(self):
        data = bytes.fromhex('05010902a10114257f7508950109308102c0')
        self.assertEqual(ReferenceDescriptor(data).report(('input',None)).fields[0].logical_min,0)
        product = parse_descriptor(data)
        self.assertEqual(product.status,'blocked')
        self.assertFalse(any(d.category=='invalid' for d in product.diagnostics))


if __name__ == '__main__':
    unittest.main()
