import unittest
from tests.helpers import parse
from hidwire.model import SourceSpan

class DiagnosticSourceTests(unittest.TestCase):
    def test_invalid_field_keeps_inherited_global_origins(self):
        d=parse(self,'0501150025ff750195010930810275078101')
        issue=next(x for r in d.reports for x in r.diagnostics if x.code=='logical_range')
        self.assertTrue(hasattr(issue,'sources'),'diagnostic inherited source provenance missing')
        self.assertEqual(issue.sources.main,SourceSpan(12,2))
        self.assertEqual(issue.sources.global_origin('logical_min'),SourceSpan(2,2))
        self.assertEqual(issue.sources.global_origin('logical_max'),SourceSpan(4,2))
        self.assertEqual(issue.sources.global_origin('report_size'),SourceSpan(6,2))
        self.assertEqual(issue.sources.usages,(SourceSpan(10,2),))

    def test_collection_identity_keeps_main_usage_and_page_origins(self):
        d=parse(self,'05010902a1010901a100c0c0')
        outer,=d.collection_tree
        inner,=outer.children
        self.assertTrue(hasattr(inner,'sources'),'collection usage source provenance missing')
        self.assertEqual(inner.sources.main,SourceSpan(8,2))
        self.assertEqual(inner.sources.usages,(SourceSpan(6,2),))
        self.assertEqual(inner.sources.global_origin('usage_page'),SourceSpan(0,2))

    def test_resource_diagnostic_keeps_report_shape_sources(self):
        d=parse(self,'750895028101',max_payload_bits=8)
        issue=next(x for x in d.diagnostics if x.code=='payload_limit')
        self.assertTrue(hasattr(issue,'sources'),'diagnostic inherited source provenance missing')
        self.assertEqual(issue.sources.main,SourceSpan(4,2))
        self.assertEqual(issue.sources.global_origin('report_count'),SourceSpan(2,2))
