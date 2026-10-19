import unittest
from hidwire import compare_descriptors, parse_descriptor
from hidwire.render import comparison_data

class ComparisonProvenanceTests(unittest.TestCase):
    def test_constant_only_shape_has_main_and_inherited_size_sources(self):
        a=parse_descriptor(bytes.fromhex('750895018101'))
        b=parse_descriptor(bytes.fromhex('751095018101'))
        diff=compare_descriptors(a,b).differences[0]
        self.assertTrue(hasattr(diff,'old_report_sources'), 'report-shape sources missing')
        self.assertEqual(diff.old_report_sources[0].main.offset,4)
        self.assertEqual(diff.new_report_sources[0].global_origin('report_size').offset,0)
        data=comparison_data(compare_descriptors(a,b))
        self.assertEqual(data['coverage']['old'][0]['sources'][0]['main']['offset'],4)

    def test_empty_collection_identity_change_has_usage_and_main_sources(self):
        a=parse_descriptor(bytes.fromhex('05010902a101750895018101c0'))
        b=parse_descriptor(bytes.fromhex('05010903a101750895018101c0'))
        changes=[d for d in compare_descriptors(a,b).differences if d.component=='collection_presence']
        self.assertEqual(len(changes),2)
        self.assertEqual(changes[0].old_sources.main.offset,4)
        self.assertEqual(changes[0].old_sources.usages[0].offset,2)
        self.assertEqual(changes[1].new_sources.main.offset,4)
