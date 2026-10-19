"""Offline, explicitly scoped command line interface (MIT)."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from . import CONTRACT_VERSION, __version__
from .bytesource import SourceError, read_descriptor
from .compare import compare_descriptors
from .decode import decode_report, verify_witness
from .model import CollectionIdentity, FieldKey, Limits, ReportKey, Witness
from .parser import parse_descriptor
from .render import comparison_data, comparison_text, diagnostics, json_text, source_summary

EXIT_CODES = {'equal': 0, 'different': 1, 'blocked': 2, 'invalid': 3}


class InvocationError(ValueError):
    pass


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise InvocationError(message)


def _selector(text):
    try:
        kind, value = text.split(':')
        if kind not in ('input', 'output', 'feature'):
            raise ValueError
        if value == 'none':
            report_id = None
        elif value.isascii() and value.isdecimal() and 1 <= int(value) <= 255:
            report_id = int(value)
        else:
            raise ValueError
        return ReportKey(kind, report_id)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('report must be input|output|feature:none|1..255') from exc


def _arguments():
    parser = ArgumentParser(prog='hidwire', description='Compare bounded scalar HID wire contracts offline (Linux file input).')
    parser.add_argument('--version', action='version', version=f'hidwire {__version__}')
    commands = parser.add_subparsers(dest='command', required=True, parser_class=ArgumentParser)
    compare = commands.add_parser('compare', help='compare complete supported contracts or selected reports')
    check = commands.add_parser('witness-check', help='independently replay saved raw-extraction witnesses')
    for command in (compare, check):
        command.add_argument('old', type=Path)
        command.add_argument('new', type=Path)
        command.add_argument('--old-format', choices=('binary', 'hex'), required=True)
        command.add_argument('--new-format', choices=('binary', 'hex'), required=True)
        command.add_argument('--json', action='store_true')
    compare.add_argument('--report', action='append', type=_selector, help='repeatable exact report scope, e.g. output:1 or input:none')
    check.add_argument('--artifact', required=True, type=Path, help='saved comparison JSON containing witnesses')
    decode = commands.add_parser('decode', help='decode exactly one supported report')
    decode.add_argument('descriptor', type=Path)
    decode.add_argument('--format', choices=('binary', 'hex'), required=True)
    decode.add_argument('--report', type=_selector, required=True)
    decode.add_argument('--wire', required=True, help='strict hexadecimal wire bytes, including ID when numbered')
    decode.add_argument('--json', action='store_true')
    return parser


def _load(path, format):
    return parse_descriptor(read_descriptor(path, format))


def _wire_hex(text):
    if len(text) > 65536 or any(ch not in '0123456789abcdefABCDEF \t\r\n\v\f' for ch in text):
        raise InvocationError('wire bytes must be bounded strict ASCII hexadecimal')
    data = bytes.fromhex(''.join(text.split()))
    if len(data) > 1025:
        raise InvocationError('wire report exceeds 1025 bytes')
    return data


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvocationError('duplicate JSON object key')
        result[key] = value
    return result


def _record(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise InvocationError('malformed witness record')
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise InvocationError('malformed witness integer')
    return value


def _report_key(value):
    value = _record(value, ('kind', 'report_id'))
    if value['kind'] not in ('input', 'output', 'feature'):
        raise InvocationError('malformed witness report kind')
    rid = value['report_id']
    if rid is not None:
        _integer(rid, 1, 255)
    return ReportKey(value['kind'], rid)


def _witness(value):
    value = _record(value, ('report_key', 'wire_hex', 'old_hash', 'new_hash', 'differing_key',
                            'old_value', 'new_value', 'old_range_valid', 'new_range_valid'))
    key = _record(value['differing_key'], ('report_key', 'path', 'page', 'usage'))
    if not isinstance(key['path'], list) or len(key['path']) > 32:
        raise InvocationError('malformed witness collection path')
    path = []
    for node in key['path']:
        node = _record(node, ('kind', 'page', 'usage'))
        path.append(CollectionIdentity(_integer(node['kind'], 0, 3),
                                       _integer(node['page'], 0, 65535),
                                       _integer(node['usage'], 0, 65535)))
    field_key = FieldKey(_report_key(key['report_key']), tuple(path),
                         _integer(key['page'], 0, 65535), _integer(key['usage'], 0, 65535))
    for name in ('old_hash', 'new_hash'):
        text = value[name]
        if not isinstance(text, str) or len(text) != 64 or any(ch not in '0123456789abcdef' for ch in text):
            raise InvocationError('malformed source hash')
    if not isinstance(value['wire_hex'], str) or len(value['wire_hex']) > 2050:
        raise InvocationError('malformed witness bytes')
    for name in ('old_range_valid', 'new_range_valid'):
        if type(value[name]) is not bool:
            raise InvocationError('malformed witness range label')
    return Witness(_report_key(value['report_key']), value['wire_hex'], value['old_hash'], value['new_hash'],
                   field_key, _integer(value['old_value'], -(2**31), 2**32-1),
                   _integer(value['new_value'], -(2**31), 2**32-1),
                   value['old_range_valid'], value['new_range_valid'])


def _load_witnesses(path):
    raw = read_descriptor(path, 'binary', Limits(max_descriptor_bytes=32 * 1024 * 1024))
    def invalid_constant(value):
        raise InvocationError('non-finite JSON number')
    artifact = json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=invalid_constant)
    if not isinstance(artifact, dict) or type(artifact.get('schema_version')) is not int or artifact['schema_version'] != 1:
        raise InvocationError('expected schema_version 1 witness artifact')
    if artifact.get('contract_version') != CONTRACT_VERSION:
        raise InvocationError('unsupported witness contract version')
    values = artifact.get('witnesses')
    if not isinstance(values, list) or not 1 <= len(values) <= 2048:
        raise InvocationError('artifact must contain 1..2048 witnesses; no equality proof is inferred')
    return tuple(_witness(value) for value in values)


def main(argv=None):
    try:
        args = _arguments().parse_args(argv)
        if args.command == 'decode':
            descriptor = _load(args.descriptor, args.format)
            if args.report not in {r.key for r in descriptor.reports}:
                if descriptor.status == 'invalid':
                    status = 'invalid'
                else:
                    raise InvocationError('requested report is absent')
            else:
                status = descriptor.status_for((args.report,))
            data = {'schema_version': 1, 'contract_version': CONTRACT_VERSION,
                    'status': status, 'source': source_summary(descriptor),
                    'scope': {'mode': 'selected', 'reports': [asdict(args.report)]},
                    'diagnostics': diagnostics(descriptor)}
            if status != 'supported':
                print(json_text(data) if args.json else f'HidWire decode: {status}\nScope: {args.report.kind}:{args.report.report_id}', end='' if args.json else '\n')
                return EXIT_CODES[status]
            decoded = decode_report(descriptor, args.report, _wire_hex(args.wire))
            data['decoded'] = asdict(decoded)
            if args.json:
                print(json_text(data), end='')
            else:
                print(f'Scope: {args.report.kind}:{"none" if args.report.report_id is None else args.report.report_id}')
                for v in decoded.values:
                    print(f'{v.key.page:#06x}:{v.key.usage:#06x} = {v.value} ({"in range" if v.in_range else "out of range"})')
                print('Whole-report logical ranges: ' + ('range-valid' if decoded.all_fields_in_range else 'out-of-range'))
            return 0
        old, new = _load(args.old, args.old_format), _load(args.new, args.new_format)
        if args.command == 'compare':
            comparison = compare_descriptors(old, new, tuple(args.report) if args.report else None)
            print(json_text(comparison_data(comparison)) if args.json else comparison_text(comparison), end='')
            return EXIT_CODES[comparison.status]
        witnesses = _load_witnesses(args.artifact)
        checks = [verify_witness(old, new, w) for w in witnesses]
        data = {'schema_version': 1, 'status': 'verified' if all(checks) else 'failed',
                'checked_witnesses': len(checks), 'results': checks,
                'meaning': 'Checks saved witnesses only; does not certify artifact completeness or equality.'}
        print(json_text(data) if args.json else f'{data["status"]}: {len(checks)} raw-extraction witnesses\n{data["meaning"]}\n', end='')
        return 0 if all(checks) else 1
    except (SourceError, ValueError, UnicodeError, RecursionError) as exc:
        print(f'hidwire: {exc}', file=sys.stderr)
        return 64


if __name__ == '__main__':
    raise SystemExit(main())
