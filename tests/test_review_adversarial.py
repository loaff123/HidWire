"""Independent parser boundary probes; no comparator or reference-parser calls."""
from pathlib import Path
import tempfile
import unittest

from hidwire.bytesource import SourceError, read_descriptor
from hidwire.model import Limits, ReportKey, SourceSpan
from hidwire.parser import parse_descriptor, tokenize


def parse(hex_text, **limits):
    return parse_descriptor(bytes.fromhex(hex_text), Limits(**limits))


def diagnostics(descriptor):
    return descriptor.diagnostics + tuple(d for r in descriptor.reports for d in r.diagnostics)


class IndependentParserReviewTests(unittest.TestCase):
    def test_resource_stop_cannot_green_earlier_report_with_unknown_tail(self):
        cases = (
            ('750895019101751095018101d501', {'max_payload_bits': 8}),
            ('05011500257f750895010930910209318102d501', {'max_fields': 1}),
        )
        for raw, caps in cases:
            with self.subTest(caps=caps):
                d = parse(raw, **caps)
                self.assertEqual(d.status_for((ReportKey('output', None),)), 'blocked')
                self.assertTrue(any(x.category == 'blocked' and x.report_key is None for x in d.diagnostics))

    def test_resource_stop_cannot_hide_invalid_pop_tail(self):
        for raw, caps in (
            ('750895019101751095018101b4', {'max_payload_bits': 8}),
            ('05011500257f750895010930910209318102b4', {'max_fields': 1}),
        ):
            with self.subTest(caps=caps):
                d = parse(raw, **caps)
                self.assertEqual(d.status_for((ReportKey('output', None),)), 'invalid')
                self.assertTrue(any(x.code == 'global_underflow' for x in diagnostics(d)))

    def test_resource_stop_does_not_fabricate_invalid_unclosed_collection(self):
        for raw, caps in (
            ('05010902a101750895018101c0', {'max_payload_bits': 4}),
            ('05010902a1010901a100c0c0', {'max_collection_depth': 1}),
            ('05010902a1017508950181019101c0', {'max_reports': 1}),
            ('05010902a1011500257f75089502093009318102c0', {'max_fields': 1}),
        ):
            with self.subTest(caps=caps):
                d = parse(raw, **caps)
                self.assertEqual(d.status, 'blocked')
                self.assertFalse(any(x.category == 'invalid' for x in diagnostics(d)))

    def test_resource_stop_cannot_hide_malformed_item_sizes(self):
        head = '750895019101751095018101'
        for tail in ('a501b4', 'a4b501', '05010902a101c100'):
            with self.subTest(tail=tail):
                d = parse(head + tail, max_payload_bits=8)
                self.assertEqual(d.status, 'invalid')
                self.assertTrue(any(x.code == 'item_size' for x in diagnostics(d)))

    def test_every_unknown_item_category_globally_poisons_selected_scope(self):
        # Start with a fully supported, unnumbered constant-only Output report.
        head = '750895019101'
        unknowns = [(0, tag) for tag in range(16) if tag not in (8, 9, 10, 11, 12)]
        unknowns += [(1, tag) for tag in range(12, 16)]
        unknowns += [(2, tag) for tag in range(3, 16)]
        unknowns += [(3, tag) for tag in range(16)]
        for item_type, tag in unknowns:
            prefix = (tag << 4) | (item_type << 2) | 1
            with self.subTest(item_type=item_type, tag=tag):
                d = parse(head + bytes([prefix, 0]).hex())
                self.assertEqual(d.status_for((ReportKey('output', None),)), 'blocked')

    def test_report_id_change_in_push_blocks_other_selected_direction(self):
        d = parse('8501750895019101a485028101b4')
        self.assertEqual(d.status_for((ReportKey('output', 1),)), 'blocked')
        self.assertTrue(any(x.code == 'report_id_in_push' and x.report_key is None for x in d.diagnostics))

    def test_numbered_and_unnumbered_constant_shapes_have_no_phantom_id(self):
        for prefix, report_id, wire_bytes in (('', None, 2), ('8507', 7, 3)):
            with self.subTest(report_id=report_id):
                d = parse(prefix + '750895028101')
                self.assertEqual(d.status, 'supported')
                report, = d.reports
                self.assertEqual((report.key, report.payload_bits, report.wire_bytes),
                                 (ReportKey('input', report_id), 16, wire_bytes))
                self.assertEqual(report.fields, ())

    def test_collections_and_padding_never_reset_payload_offsets(self):
        d = parse('05010902a1017508950181011500257f09308102c0'
                  '0904a1017504950281037508950109318102c0')
        self.assertEqual(d.status, 'supported')
        report, = d.reports
        self.assertEqual((report.payload_bits, report.wire_bytes), (32, 4))
        self.assertEqual([(f.bit_offset, f.key.usage) for f in report.fields], [(8, 48), (24, 49)])
        self.assertEqual([f.key.path[0].usage for f in report.fields], [2, 4])

    def test_pending_usage_range_binds_after_pop_and_keeps_range_origins(self):
        d = parse('05011500257f75089502a4050919302931b48102')
        self.assertEqual(d.status, 'supported')
        self.assertEqual([(f.key.page, f.key.usage) for f in d.reports[0].fields], [(1, 48), (1, 49)])
        for scalar in d.reports[0].fields:
            self.assertEqual(scalar.sources.usages, (SourceSpan(13, 2), SourceSpan(15, 2)))
            self.assertEqual(scalar.sources.global_origin('usage_page'), SourceSpan(0, 2))

    def test_pending_extended_usage_survives_pop_without_page_rebinding(self):
        d = parse('05011500257f75089501a405090b3000ff00b48102')
        self.assertEqual(d.status, 'supported')
        scalar, = d.reports[0].fields
        self.assertEqual((scalar.key.page, scalar.key.usage), (255, 48))
        self.assertEqual(scalar.sources.usages, (SourceSpan(13, 5),))

    def test_pop_restores_undefined_physical_unit_state_and_origins(self):
        d = parse('05011500257f75089501a4350145646511550f09308102b409318102')
        self.assertEqual(d.status, 'supported')
        first, last = d.reports[0].fields
        self.assertEqual((first.physical_min, first.physical_max, first.unit, first.unit_exponent), (1, 100, 17, -1))
        self.assertEqual((last.physical_min, last.physical_max, last.unit, last.unit_exponent), (0, 127, 0, 0))
        for name in ('physical_min', 'physical_max', 'unit', 'unit_exponent'):
            self.assertIsNone(last.sources.global_origin(name))
        self.assertEqual(last.sources.global_origin('report_size'), SourceSpan(6, 2))
        self.assertEqual(last.sources.main, SourceSpan(26, 2))

    def test_invalid_field_diagnostic_preserves_effective_source_spans(self):
        d = parse('0501150025ff750195010930810275078101')
        error = next(x for x in diagnostics(d) if x.code == 'logical_range')
        self.assertEqual(error.offset, 12)
        self.assertIsNotNone(error.sources)
        self.assertEqual(error.sources.main, SourceSpan(12, 2))
        self.assertEqual(error.sources.usages, (SourceSpan(10, 2),))
        self.assertEqual(error.sources.global_origin('logical_min'), SourceSpan(2, 2))
        self.assertEqual(error.sources.global_origin('logical_max'), SourceSpan(4, 2))
        self.assertEqual(error.sources.global_origin('report_size'), SourceSpan(6, 2))

    def test_collection_identity_preserves_usage_and_page_provenance(self):
        d = parse('050109020509a101750895018101c0')
        self.assertEqual(d.status, 'supported')
        collection, = d.collection_tree
        self.assertEqual((collection.identity.page, collection.identity.usage), (9, 2))
        self.assertEqual(collection.sources.main, SourceSpan(6, 2))
        self.assertEqual(collection.sources.usages, (SourceSpan(2, 2),))
        self.assertEqual(collection.sources.global_origin('usage_page'), SourceSpan(4, 2))

    def test_signed_one_bit_spec_truth_table_is_complete(self):
        # HID 1.11 §§5.8,6.2.2.7: negative minimum selects two's-complement.
        # This asserts the parser model, and independently enumerates its entire
        # scalar domain. It is not a claim that a product decoder exists yet.
        d = parse('050115ff2500750195010930810275078101')
        self.assertEqual(d.status, 'supported')
        scalar, = d.reports[0].fields
        self.assertEqual((scalar.bit_offset, scalar.width, scalar.signed,
                          scalar.logical_min, scalar.logical_max), (0, 1, True, -1, 0))
        truth = {}
        for raw_bit in (0, 1):
            # Independent mathematical two's-complement definition for width 1.
            truth[raw_bit] = -raw_bit
        self.assertEqual(truth, {0: 0, 1: -1})

    def test_unit_canonical_exponents_cover_all_sixteen_values(self):
        for raw in range(16):
            d = parse('05011500257f75089501093055' + f'{raw:02x}' + '8102')
            self.assertEqual(d.status, 'supported')
            self.assertEqual(d.reports[0].fields[0].unit_exponent,
                             raw if raw <= 7 else raw - 16)

    def test_zero_data_report_main_items_are_arrays_not_malformed(self):
        # HID 1.11 §6.2.2.4 explicitly defaults Main-item bits to zero.
        for main in ('80', '90', 'b0'):
            with self.subTest(main=main):
                d = parse('05011500257f750895010930' + main)
                self.assertEqual(d.status, 'blocked')
                self.assertTrue(any(x.code == 'data_array' for x in diagnostics(d)))
                self.assertFalse(any(x.category == 'invalid' for x in diagnostics(d)))

    def test_zero_data_collection_means_physical(self):
        d = parse('05010902a0750895018101c0')
        self.assertEqual(d.status, 'supported')
        self.assertEqual(d.collection_tree[0].identity.kind, 0)

    def test_zero_data_value_tags_are_not_mislabeled_structurally_invalid(self):
        # Conservative explicit exclusion is acceptable pending coverage.
        # Optional zero-byte data is allowed by the generic short-item format.
        cases = ('050114257f7508950109308102',
                 '05011500257f75089501088102')
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertNotEqual(parse(raw).status, 'invalid')

    def test_signed_maxima_follow_their_corresponding_minimum(self):
        # Primary-source corroboration: Linux v6.12 hid_parser_global/item_sdata.
        for byte_width, size_code in ((1, 1), (2, 2), (4, 3)):
            for maximum in (-2, -1):
                encoded_max = maximum.to_bytes(byte_width, 'little', signed=True).hex()
                logical_max = f'{0x24 | size_code:02x}' + encoded_max
                physical_max = f'{0x44 | size_code:02x}' + encoded_max
                with self.subTest(byte_width=byte_width, maximum=maximum):
                    d = parse('05011580' + logical_max + '3580' + physical_max + '7508950109308102')
                    self.assertEqual(d.status, 'supported')
                    scalar, = d.reports[0].fields
                    self.assertEqual((scalar.logical_min, scalar.logical_max,
                                      scalar.physical_min, scalar.physical_max),
                                     (-128, maximum, -128, maximum))
        # Adjacent unsigned control: identical maximum bytes under nonnegative minima.
        d = parse('0501150025ff350045ff7508950109308102')
        self.assertEqual(d.status, 'supported')
        scalar, = d.reports[0].fields
        self.assertEqual((scalar.logical_max, scalar.physical_max), (255, 255))

    def test_complete_long_item_does_not_hide_structural_errors(self):
        for raw, expected_code in (('fe0199aac0', 'collection_underflow'),
                                   ('fe0199aab4', 'global_underflow'),
                                   ('fe0199aa05010902a101', 'unbalanced_collection')):
            with self.subTest(raw=raw):
                d = parse(raw)
                self.assertEqual(d.status, 'invalid')
                self.assertTrue(any(x.code == expected_code for x in diagnostics(d)))
                self.assertTrue(any(x.code == 'long_item' for x in diagnostics(d)))

    def test_input_file_never_mutated(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'descriptor.hex'
            original = b'05 01\n15 00\n25 ff\n'
            source.write_bytes(original)
            self.assertEqual(read_descriptor(source, 'hex'), bytes.fromhex('0501150025ff'))
            self.assertEqual(source.read_bytes(), original)

    def test_invalid_path_nul_is_reported_as_source_error(self):
        with self.assertRaises(SourceError):
            read_descriptor(Path('bad\x00name'), 'binary')

    def test_descriptor_hash_and_item_sources_are_exact_bytes(self):
        from hashlib import sha256
        raw = bytes.fromhex('05011500257f7508950109308102')
        d = parse_descriptor(raw)
        self.assertEqual(d.sha256, sha256(raw).hexdigest())
        self.assertEqual(d.byte_length, len(raw))
        self.assertEqual([(x.offset, 1 + len(x.data)) for x in tokenize(raw)],
                         [(0, 2), (2, 2), (4, 2), (6, 2), (8, 2), (10, 2), (12, 2)])


if __name__ == '__main__':
    unittest.main()
