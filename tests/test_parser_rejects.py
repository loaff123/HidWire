import unittest
from tests.helpers import parse, simple, codes


class RejectTests(unittest.TestCase):
    def test_all_excluded_flags(self):
        for flags in (0,4,8,0x0a,0x12,0x22,0x42,0x82,0x102,0x202,5,7):
            encoded=('81'+f'{flags:02x}') if flags<256 else '82'+flags.to_bytes(2,'little').hex()
            d=parse(self,simple().replace('8102c0',encoded+'c0'))
            self.assertEqual(d.status,'blocked',hex(flags))

    def test_all_unmodeled_item_categories(self):
        for extra in ('3901','4901','5901','7901','8901','9901','a901','d501','d901','d101','fc','fe0199aa'):
            with self.subTest(extra=extra): self.assertEqual(parse(self,simple(prefix=extra)).status,'blocked')

    def test_usage_ambiguities(self):
        for usages,count in [('0930','02'),('09300930','02'),('093019312932','03'),('1930','01'),('2930','01'),('19322b33000100','02')]:
            with self.subTest(usages=usages): self.assertEqual(parse(self,simple(usages=usages,count=count)).status,'blocked')

    def test_invalid_usage_ranges(self):
        for usages in ('19322931','1b300001002b31000200'):
            self.assertEqual(parse(self,simple(usages=usages)).status,'invalid')

    def test_duplicate_sibling_collections_blocked(self):
        d=parse(self,'05010902a1010930a100c00930a100c0c0')
        self.assertIn('duplicate_collection',codes(d))

    def test_collection_identity_missing_or_multiple_blocked(self):
        for h in ('a101c0','050109020930a101c0','050119012902a101c0','05010902a104c0'):
            self.assertEqual(parse(self,h).status,'blocked')

    def test_structural_errors_invalid(self):
        for h in ('c0','b4','05010902a101','8500','860001','750095018101','750895008101','a501','b501','c001'):
            with self.subTest(h=h): self.assertEqual(parse(self,h).status,'invalid')

    def test_unbalanced_push_blocked(self):
        self.assertIn('unbalanced_push',codes(parse(self,'a4')))

    def test_mixed_numbered_unnumbered_invalid(self):
        self.assertEqual(parse(self,'75089501810185018101').status,'invalid')

    def test_nonbyte_alignment_and_missing_explicit_bounds_block(self):
        self.assertIn('report_alignment',codes(parse(self,simple(size='01',bounds='15002501'))))
        self.assertIn('logical_bounds_missing',codes(parse(self,simple(bounds=''))))

    def test_bound_and_order_rejections(self):
        for bounds in ('15022501','150025ff','15fe2501'):
            self.assertEqual(parse(self,simple(bounds=bounds,size='01',suffix='750795018101')).status,'invalid')
        self.assertIn('logical_max_before_min',codes(parse(self,simple(bounds='257f1500'))))
        self.assertIn('physical_max_before_min',codes(parse(self,simple(prefix='45003500'))))
        for extra in ('55ff','6505','6700000010'):
            self.assertEqual(parse(self,simple(prefix=extra)).status,'blocked')

    def test_application_caps(self):
        cases=[(simple(),{'max_descriptor_bytes':1},'descriptor_limit'),
               (simple(),{'max_payload_bits':4},'payload_limit'),
               (simple(usages='09300931',count='02'),{'max_fields':1},'field_limit'),
               (simple(prefix='a4a4',suffix='b4b4'),{'max_global_depth':1},'global_depth'),
               ('05010902a1010901a100c0c0',{'max_collection_depth':1},'collection_depth'),
               (simple(suffix='09309102'),{'max_reports':1},'report_limit'),
               (simple(size='21'),{},'scalar_width')]
        for h,limits,code in cases:
            with self.subTest(code=code): self.assertIn(code,codes(parse(self,h,**limits)))

    def test_expansion_bombs_bounded(self):
        for h in ('05011500257f750897ffffffff193029ff8102','05011500257f750895011b000001002bffff01008102'):
            self.assertEqual(parse(self,h).status,'blocked')

    def test_invalid_tail_after_unsupported_still_invalid(self):
        for prefix in ('fe0199aa','fc','3901'):
            self.assertEqual(parse(self,prefix+'27').status,'invalid')
