"""Exact equality of scalar bit functions for the bounded HID contract (MIT)."""
from .decode import decode_report, verify_witness
from .model import Comparison, Descriptor, Difference, FieldKey, ReportKey, Scalar, Witness


class ComparisonError(ValueError):
    """A requested scope cannot be interpreted."""


def report_sort_key(key: ReportKey):
    return (('input', 'output', 'feature').index(key.kind),
            -1 if key.report_id is None else key.report_id)


def field_sort_key(key: FieldKey):
    return (report_sort_key(key.report_key),
            tuple((c.kind, c.page, c.usage) for c in key.path), key.page, key.usage)


def coefficients(scalar: Scalar) -> tuple[tuple[int, int], ...]:
    """Sparse integer coefficients over payload bits; the ID is not a variable."""
    return tuple((scalar.bit_offset + bit,
                  -(1 << bit) if scalar.signed and bit == scalar.width - 1 else 1 << bit)
                 for bit in range(scalar.width))


def _metadata(scalar):
    return {name: getattr(scalar, name) for name in
            ('logical_min', 'logical_max', 'physical_min', 'physical_max',
             'unit', 'unit_exponent', 'flags')}


def _shape(report):
    return {'payload_bits': report.payload_bits, 'wire_bytes': report.wire_bytes}


def _collection_paths(descriptor):
    paths = {}
    def visit(nodes, parent=()):
        for node in nodes:
            path = parent + ((node.identity.kind, node.identity.page, node.identity.usage),)
            paths[path] = node
            visit(node.children, path)
    visit(descriptor.collection_tree)
    return paths


def compare_descriptors(old: Descriptor, new: Descriptor,
                        scope: tuple[ReportKey, ...] | None = None) -> Comparison:
    """Decide the selected wire contract, preserving unsupported/invalid status.

    Coefficient equality is necessary and sufficient over all raw payload bits.
    Metadata and schema are distinct additional parts of the supported contract.
    """
    old_reports = {r.key: r for r in old.reports}
    new_reports = {r.key: r for r in new.reports}
    available = old_reports.keys() | new_reports.keys()
    if scope is not None:
        if not scope:
            raise ComparisonError('scope must contain at least one report')
        for key in scope:
            if not isinstance(key, ReportKey) or key.kind not in ('input', 'output', 'feature'):
                raise ComparisonError('invalid report selector')
            if key.report_id is not None and (type(key.report_id) is not int or not 1 <= key.report_id <= 255):
                raise ComparisonError('report ID must be none or 1..255')
            if key not in available:
                raise ComparisonError('selected report is absent on both sides')
        scope = tuple(sorted(set(scope), key=report_sort_key))
    selected = tuple(sorted(available, key=report_sort_key)) if scope is None else scope
    statuses = [d.status_for(tuple(k for k in selected if k in reports))
                for d, reports in ((old, old_reports), (new, new_reports))]
    differences, witnesses = [], []
    # Unknown global state can invalidate any inferred schema/value contract.
    global_blocked = any(d.category == 'blocked' for d in old.diagnostics + new.diagnostics)
    if not global_blocked and 'invalid' not in statuses:
        if scope is None and old.status == new.status == 'supported':
            a, b = _collection_paths(old), _collection_paths(new)
            for path in sorted(a.keys() ^ b.keys()):
                differences.append(Difference('schema', 'collection_presence', None, None,
                                              path if path in a else None, path if path in b else None,
                                              a[path].sources if path in a else None,
                                              b[path].sources if path in b else None))
        for key in selected:
            left, right = old_reports.get(key), new_reports.get(key)
            if left is None or right is None:
                differences.append(Difference('schema', 'report_presence', key, None,
                                              _shape(left) if left else None,
                                              _shape(right) if right else None,
                                              old_report_sources=left.sources if left else (),
                                              new_report_sources=right.sources if right else ()))
                continue
            if old.status_for((key,)) != 'supported' or new.status_for((key,)) != 'supported':
                continue
            same_shape = _shape(left) == _shape(right)
            if not same_shape:
                differences.append(Difference('schema', 'report_shape', key, None,
                                              _shape(left), _shape(right),
                                              old_report_sources=left.sources,
                                              new_report_sources=right.sources))
            a_fields = {s.key: s for s in left.fields}
            b_fields = {s.key: s for s in right.fields}
            for field_key in sorted(a_fields.keys() | b_fields.keys(), key=field_sort_key):
                a, b = a_fields.get(field_key), b_fields.get(field_key)
                if a is None or b is None:
                    differences.append(Difference('schema', 'field_presence', key, field_key,
                                                  a is not None, b is not None,
                                                  a.sources if a else None, b.sources if b else None))
                    continue
                if _metadata(a) != _metadata(b):
                    differences.append(Difference('metadata', 'effective_metadata', key, field_key,
                                                  _metadata(a), _metadata(b), a.sources, b.sources))
                ca, cb = coefficients(a), coefficients(b)
                if ca == cb:
                    continue
                differences.append(Difference('raw_value', 'coefficients', key, field_key,
                                              ca, cb, a.sources, b.sources))
                if not same_shape:
                    continue  # No common exact-length framing for a report witness.
                va, vb = dict(ca), dict(cb)
                bit = min(i for i in va.keys() | vb.keys() if va.get(i, 0) != vb.get(i, 0))
                payload = (1 << bit).to_bytes(left.payload_bits // 8, 'little')
                wire = (bytes([key.report_id]) if key.report_id is not None else b'') + payload
                decoded_a = decode_report(old, key, wire)
                decoded_b = decode_report(new, key, wire)
                witness = Witness(key, wire.hex(), old.sha256, new.sha256, field_key,
                                  va.get(bit, 0), vb.get(bit, 0),
                                  decoded_a.all_fields_in_range, decoded_b.all_fields_in_range)
                if not verify_witness(old, new, witness):
                    raise RuntimeError('internal witness verification failed')
                witnesses.append(witness)
    status = ('invalid' if 'invalid' in statuses else 'blocked' if 'blocked' in statuses
              else 'different' if differences else 'equal')
    return Comparison(status, scope, selected, old, new, tuple(differences), tuple(witnesses))
