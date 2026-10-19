import unittest
from tests.helpers import parse, simple, codes

class ResourceCoverageTests(unittest.TestCase):
    def test_resource_stop_never_fabricates_unclosed_collection(self):
        d=parse(self,simple(),max_payload_bits=4)
        self.assertEqual(d.status,'blocked')
        self.assertNotIn('unbalanced_collection',codes(d))

    def test_resource_stop_poison_other_selected_report(self):
        d=parse(self,'750895019101750897ffffffff8101fc')
        output=d.reports[0].key
        self.assertEqual(d.status_for((output,)),'blocked')
        self.assertTrue(any(x.report_key is None and x.code == 'payload_limit' for x in d.diagnostics))

    def test_default_caps_enforced_before_expansion(self):
        self.assertEqual(parse(self,'750197ffffffff8101').status,'blocked')
        self.assertEqual(parse(self,'050115002501750197ffffffff193029ff8102').status,'blocked')

    def test_parent_directory_symlink_rejected(self):
        import tempfile
        from pathlib import Path
        from hidwire.bytesource import SourceError, read_descriptor
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'dir').mkdir(); (p/'dir'/'file').write_bytes(b'00'); (p/'link').symlink_to(p/'dir',target_is_directory=True)
            with self.assertRaises(SourceError): read_descriptor(p/'link'/'file','hex')

    def test_collection_syntax_after_resource_stop_is_still_checked(self):
        d=parse(self,'750895019101750897ffffffff8101c0')
        self.assertEqual(d.status,'invalid')
        self.assertIn('collection_underflow',codes(d))

    def test_long_item_does_not_hide_malformed_collection_tail(self):
        d=parse(self,'fe0199aac0')
        self.assertEqual(d.status,'invalid')
        self.assertIn('long_item',codes(d))
        self.assertIn('collection_underflow',codes(d))

    def test_fixed_item_syntax_after_resource_stop_still_invalid(self):
        for tail in ('a501b4','a4b501','05010902a101c100','8500','860001','0700000100'):
            with self.subTest(tail=tail):
                d=parse(self,'750895019101751095018101'+tail,max_payload_bits=8)
                self.assertEqual(d.status,'invalid')
