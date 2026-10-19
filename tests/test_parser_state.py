import unittest
from tests.helpers import parse, simple, codes


class StateTests(unittest.TestCase):
    def test_push_pop_restores_globals_and_source_origins(self):
        d=parse(self,'05010902a1011500257f7508950109308102a40509150125017501950109018102750795018101b409318102c0')
        self.assertEqual(d.status,'supported')
        f=d.reports[0].fields[-1]
        self.assertEqual((f.key.page,f.key.usage,f.bit_offset,f.width,f.logical_min,f.logical_max),(1,49,16,8,0,127))
        self.assertEqual(f.sources.global_origin('report_size').offset,10)

    def test_pop_changes_pending_ordinary_usage_page(self):
        d=parse(self,'05010902a1011500257f75089501a405090930b48102c0')
        self.assertEqual(d.status,'supported')
        self.assertEqual(d.reports[0].fields[0].key.page,1)

    def test_independent_ids_directions_and_collection_offsets(self):
        d=parse(self,'05010902a10185011500257f7508950109308102093191020938b102850209308102850109318102c00904a10109388102c0')
        self.assertEqual(d.status,'supported')
        reports={(r.key.kind,r.key.report_id):r for r in d.reports}
        self.assertEqual([(f.bit_offset,f.key.usage) for f in reports['input',1].fields],[(0,48),(8,49),(16,56)])
        self.assertEqual(reports['input',2].payload_bits,8)
        self.assertEqual(reports['output',1].payload_bits,8)
        self.assertEqual(reports['feature',1].payload_bits,8)

    def test_local_reset_after_each_main_item(self):
        cases = [
            '05010902a1011500257f750895018102c0',
            simple(suffix='8102'), simple(suffix='9102'), simple(suffix='b102'),
            '05010902a1010930c01500257f750895018102',
        ]
        for h in cases:
            with self.subTest(h=h): self.assertIn('usage_count',codes(parse(self,h)))

    def test_push_does_not_save_local_usage(self):
        d=parse(self,simple(usages='a40930b4'))
        self.assertEqual(d.status,'supported')
        self.assertEqual(d.reports[0].fields[0].key.usage,48)

    def test_maximum_not_reinterpreted_after_new_minimum(self):
        d=parse(self,simple(bounds='150025ff15ff'))
        self.assertIn('logical_range',codes(d))

    def test_report_id_inside_push_blocked(self):
        d=parse(self,'05010902a10185011500257f7508950109308102a4850209318102b409388102c0')
        self.assertIn('report_id_in_push',codes(d))
        self.assertEqual(d.status,'blocked')

    def test_same_id_inside_push_permitted(self):
        d=parse(self,simple(prefix='8501a48501',suffix='b4'))
        self.assertEqual(d.status,'supported')

    def test_known_unsupported_array_is_report_local(self):
        d=parse(self,'05010906a1018501050719e029e71500250175019508810295017508810195057501050819012905910295017503910195067508150026ff00050719002aff008100c0')
        self.assertEqual(d.status,'blocked')
        reports={r.key.kind:r for r in d.reports}
        self.assertEqual((reports['output'].payload_bits,reports['output'].wire_bytes,len(reports['output'].fields)),(8,2,5))
        self.assertEqual(d.status_for((reports['output'].key,)),'supported')
        self.assertEqual(d.status_for((reports['input'].key,)),'blocked')
        self.assertIn('data_array',codes(d))

    def test_unknown_state_blocks_even_other_report_selection(self):
        d=parse(self,simple(prefix='fc'))
        self.assertEqual(d.status,'blocked')
        self.assertEqual(d.status_for((d.reports[0].key,)),'blocked')
