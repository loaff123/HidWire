"""Adversarial pending-local diagnostics must not expand quadratically."""
import unittest
from hidwire import parse_descriptor,compare_descriptors
from hidwire.render import json_text,comparison_data

class DiagnosticResourceTests(unittest.TestCase):
    def test_nonconsuming_diagnostics_do_not_copy_pending_usage_state(self):
        raw=bytes.fromhex('0930')*1365+bytes([0x38])*1366
        self.assertEqual(len(raw),4096)
        d=parse_descriptor(raw)
        self.assertEqual(d.status,'blocked')
        self.assertEqual(len(d.diagnostics),1366)
        self.assertEqual(sum(len(item.sources.usages) for item in d.diagnostics),0,
                         'non-consuming local errors must not copy pending Usage lists')
        self.assertEqual(d.diagnostics[-1].sources.main.offset,4095)

    def test_small_attack_has_linear_json_and_invalid_tail_precedence(self):
        raw=bytes.fromhex('05010930')+bytes.fromhex('0930')*299+bytes([0x38])*300
        d=parse_descriptor(raw)
        text=json_text(comparison_data(compare_descriptors(d,d)))
        self.assertLess(len(text),700000)
        self.assertEqual(d.diagnostics[-1].sources.global_origin('usage_page').offset,0)
        bad=parse_descriptor(raw+b'\xc0')
        self.assertEqual(compare_descriptors(d,bad).status,'invalid')

    def test_consuming_main_keeps_usage_provenance(self):
        raw=bytes.fromhex('0501150025ff75089501')+bytes.fromhex('0930')*300+bytes.fromhex('8102')
        d=parse_descriptor(raw)
        diagnostic=next(x for r in d.reports for x in r.diagnostics if x.code=='usage_count')
        self.assertEqual(len(diagnostic.sources.usages),300)
        self.assertEqual(diagnostic.sources.usages[0].offset,10)
        self.assertEqual(diagnostic.sources.main.offset,610)

    def test_synthetic_eof_diagnostics_do_not_consume_pending_usages(self):
        raw=bytes.fromhex('75019501')+b''.join(bytes([0x85,i,0x81,1]) for i in range(1,65))+bytes.fromhex('0930')*1000
        d=parse_descriptor(raw)
        self.assertEqual(len(d.reports),64)
        errors=[x for r in d.reports for x in r.diagnostics if x.code=='report_alignment']
        self.assertEqual(len(errors),64)
        self.assertEqual(sum(len(x.sources.usages) for x in errors),0)
        self.assertEqual(d.status,'blocked')
