"""Target exact comparison, independent decoding, framing, and witness ranges.

Reuse the fixture-complete temporary-copy harness; an unmodified full core
baseline must pass, and no mutant is credited for errors rather than assertions.
No production source is changed by this script.
"""
import json
from verify_mutations import run_mutations

MUTATIONS = (
    ('ignore_bit_offsets','src/hidwire/compare.py',
     'scalar.bit_offset + bit','bit',
     'tests.test_compare.CompareTests.test_real_swap_and_deterministic_lowest_bit'),
    ('ignore_signed_coefficient','src/hidwire/compare.py',
     '-(1 << bit) if scalar.signed and bit == scalar.width - 1 else 1 << bit',
     '1 << bit',
     'tests.test_exhaustive.ExhaustiveComparisonTests.test_signedness_change_requires_a_real_separating_witness'),
    ('omit_decoder_sign_extension','src/hidwire/decode.py',
     'value -= 1 << scalar.width','value = value',
     'tests.test_exhaustive.ExhaustiveComparisonTests.test_signed_one_bit_truth_table_every_bit_position'),
    ('decode_wrong_byte_order','src/hidwire/decode.py',
     "int.from_bytes(payload, 'little')","int.from_bytes(payload, 'big')",
     'tests.test_witness.WitnessTests.test_real_report_values'),
    ('decode_id_as_payload','src/hidwire/decode.py',
     'payload = wire[1:]','payload = wire[:-1]',
     'tests.test_witness.WitnessTests.test_real_report_values'),
    ('accept_wrong_id_prefix','src/hidwire/decode.py',
     'if not wire or wire[0] != key.report_id:','if not wire:',
     'tests.test_witness.WitnessTests.test_exact_length_prefix_and_blocked_refusal'),
    ('ignore_whole_report_range','src/hidwire/decode.py',
     'DecodedReport(key, tuple(values), not outside, outside)',
     'DecodedReport(key, tuple(values), True, outside)',
     'tests.test_exhaustive.ExhaustiveComparisonTests.test_unrelated_positive_minimum_invalidates_whole_report_witness'),
    ('ignore_witness_old_range_label','src/hidwire/decode.py',
     'left.all_fields_in_range == witness.old_range_valid','True',
     'tests.test_witness.WitnessTests.test_whole_report_range_labels_and_tamper_detection'),
)


def main():
    report = run_mutations(MUTATIONS)
    print(json.dumps(report,indent=2))
    return 0 if report['all_caught'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
