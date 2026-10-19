"""HID1.11 §6.2.2.4 explicitly defaults missing Main-item data to zero."""
import unittest
from tests.helpers import parse, codes

class ZeroDataTests(unittest.TestCase):
    def test_zero_data_report_main_is_array_not_malformed(self):
        for main in ('80','90','b0'):
            d=parse(self,'05011500257f750895010930'+main)
            self.assertEqual(d.status,'blocked')
            self.assertIn('data_array',codes(d))
            self.assertNotIn('item_size',codes(d))

    def test_zero_data_collection_is_physical(self):
        d=parse(self,'05010902a01500257f7508950109308102c0')
        self.assertEqual(d.status,'supported')
        self.assertEqual(d.collection_tree[0].identity.kind,0)

    def test_unproven_zero_data_globals_and_locals_block_not_invalid(self):
        for h in ('05010902a10114257f7508950109308102c0',
                  '05010902a1011500257f75089501088102c0'):
            self.assertEqual(parse(self,h).status,'blocked')
