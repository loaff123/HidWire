"""Direct little-endian report decoding, independent of comparison algebra (MIT)."""
from .model import DecodedReport, DecodedValue, Descriptor, ReportKey, Witness


def decode_report(descriptor: Descriptor, key: ReportKey, wire: bytes) -> DecodedReport:
    """Decode exactly one supported report. Raw integers are never clamped."""
    if not isinstance(wire, bytes):
        raise ValueError('wire report must be bytes')
    if descriptor.status_for((key,)) != 'supported':
        raise ValueError('requested report is missing, invalid, or unsupported')
    report = next(r for r in descriptor.reports if r.key == key)
    if len(wire) != report.wire_bytes:
        raise ValueError(f'expected exactly {report.wire_bytes} wire bytes; got {len(wire)}')
    if key.report_id is not None:
        if not wire or wire[0] != key.report_id:
            raise ValueError('report ID prefix does not match requested report')
        payload = wire[1:]
    else:
        payload = wire
    packed = int.from_bytes(payload, 'little')
    values = []
    for scalar in report.fields:
        value = (packed >> scalar.bit_offset) & ((1 << scalar.width) - 1)
        if scalar.signed and value & (1 << (scalar.width - 1)):
            value -= 1 << scalar.width
        values.append(DecodedValue(scalar.key, value,
                                   scalar.logical_min <= value <= scalar.logical_max))
    outside = tuple(v.key for v in values if not v.in_range)
    return DecodedReport(key, tuple(values), not outside, outside)


def verify_witness(old: Descriptor, new: Descriptor, witness: Witness) -> bool:
    """Check source binding, framing, separation, integers and all-field ranges.

    This does not establish that a comparison artifact is complete or that a
    raw counterexample is a physically valid device report.
    """
    if witness.old_hash != old.sha256 or witness.new_hash != new.sha256:
        return False
    if witness.differing_key.report_key != witness.report_key:
        return False
    if type(witness.old_value) is not int or type(witness.new_value) is not int:
        return False
    if type(witness.old_range_valid) is not bool or type(witness.new_range_valid) is not bool:
        return False
    if not isinstance(witness.wire_hex, str) or len(witness.wire_hex) > 2050:
        return False
    try:
        wire = bytes.fromhex(witness.wire_hex)
        # Saved witnesses use canonical compact lowercase hexadecimal.
        if wire.hex() != witness.wire_hex:
            return False
        left = decode_report(old, witness.report_key, wire)
        right = decode_report(new, witness.report_key, wire)
        a = next(v.value for v in left.values if v.key == witness.differing_key)
        b = next(v.value for v in right.values if v.key == witness.differing_key)
    except (ValueError, StopIteration):
        return False
    return (a != b and a == witness.old_value and b == witness.new_value
            and left.all_fields_in_range == witness.old_range_valid
            and right.all_fields_in_range == witness.new_range_valid)
