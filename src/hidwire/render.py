"""Stable, source-linked JSON and concise text reports (MIT)."""
from dataclasses import asdict
import json
from . import CONTRACT_VERSION, __version__
from .compare import report_sort_key


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n'


def source_summary(descriptor):
    return {'sha256': descriptor.sha256, 'byte_length': descriptor.byte_length}


def diagnostics(descriptor):
    values = list(descriptor.diagnostics)
    values.extend(d for r in descriptor.reports for d in r.diagnostics)
    return [asdict(d) for d in sorted(values, key=lambda d: (d.offset, d.category, d.code,
            ('', -1) if d.report_key is None else (d.report_key.kind, d.report_key.report_id or -1)))]


def comparison_data(comparison):
    coverage = {}
    for side, descriptor in (('old', comparison.old), ('new', comparison.new)):
        coverage[side] = [
            {'report': asdict(r.key), 'selected': r.key in comparison.selected_reports,
             'status': descriptor.status_for((r.key,)), 'payload_bits': r.payload_bits,
             'wire_bytes': r.wire_bytes, 'field_count': len(r.fields),
             'sources': [asdict(source) for source in r.sources]}
            for r in sorted(descriptor.reports, key=lambda r: report_sort_key(r.key))]
    return {
        'schema_version': 1, 'contract_version': CONTRACT_VERSION,
        'tool': {'name': 'hidwire', 'version': __version__},
        'status': comparison.status,
        'scope': {'mode': 'all' if comparison.scope is None else 'selected',
                  'reports': [asdict(key) for key in comparison.selected_reports]},
        'sources': {'old': source_summary(comparison.old), 'new': source_summary(comparison.new)},
        'coverage': coverage,
        'diagnostics': {'old': diagnostics(comparison.old), 'new': diagnostics(comparison.new)},
        'differences': [asdict(d) for d in comparison.differences],
        'witnesses': [asdict(w) for w in comparison.witnesses],
        'witness_semantics': 'raw-extraction counterexamples; range labels check every scalar '
                             'in the selected report, not physical device validity',
    }


def _report_label(key):
    return f'{key.kind}:{"none" if key.report_id is None else key.report_id}'


def comparison_text(comparison):
    lines = [f'HidWire: {comparison.status}',
             'Scope: ' + ('all reports' if comparison.scope is None else
                           ', '.join(_report_label(k) for k in comparison.scope))]
    if comparison.status == 'equal':
        lines.append('Same supported wire contract within this scope.')
    elif comparison.status in ('blocked', 'invalid'):
        lines.append('No complete equality decision. Any differences below are partial findings.')
    for diff in comparison.differences:
        location = _report_label(diff.report_key) if diff.report_key else 'descriptor'
        if diff.field_key:
            location += f' usage {diff.field_key.page:#06x}:{diff.field_key.usage:#06x}'
            if diff.field_key.path:
                location += ' path ' + '/'.join(f'{c.kind}:{c.page:x}:{c.usage:x}' for c in diff.field_key.path)
        lines.append(f'{diff.kind}: {location}: {diff.component}')
        report_sources = tuple(('old', source) for source in diff.old_report_sources) + tuple(('new', source) for source in diff.new_report_sources)
        for side, source in (('old', diff.old_sources), ('new', diff.new_sources)) + report_sources:
            if source:
                globals_ = ', '.join(f'{name}@{span.offset}' for name, span in source.globals)
                lines.append(f'  {side} Main@{source.main.offset}; globals {globals_}')
    for w in comparison.witnesses:
        a = 'range-valid' if w.old_range_valid else 'out-of-range'
        b = 'range-valid' if w.new_range_valid else 'out-of-range'
        lines.append(f'raw-extraction witness {_report_label(w.report_key)} '
                     f'usage {w.differing_key.page:#06x}:{w.differing_key.usage:#06x}: '
                     f'{" ".join(w.wire_hex[i:i+2] for i in range(0,len(w.wire_hex),2))}; '
                     f'old={w.old_value} ({a}), new={w.new_value} ({b})')
    for side, d in (('old', comparison.old), ('new', comparison.new)):
        for diag in diagnostics(d):
            lines.append(f'{side} {diag["category"]} @{diag["offset"]} {diag["code"]}: {diag["detail"]}')
    return '\n'.join(lines) + '\n'
