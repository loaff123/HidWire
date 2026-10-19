"""Bounded short-item decoding and fail-closed scalar HID parsing (MIT)."""
from .model import DEFAULT_LIMITS, Diagnostic, Item, Limits


class ParseError(ValueError):
    def __init__(self, diagnostic: Diagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic.detail)


def _scan_items(data: bytes, limits: Limits) -> tuple[tuple[Item, ...], tuple[Diagnostic, ...]]:
    if len(data) > limits.max_descriptor_bytes:
        raise ParseError(Diagnostic('blocked', 'descriptor_limit', 0, None, 'descriptor byte limit exceeded'))
    items = []
    blocked = None
    pos = 0
    while pos < len(data):
        start = pos
        prefix = data[pos]
        pos += 1
        if prefix == 0xfe:
            if pos + 2 > len(data):
                raise ParseError(Diagnostic('invalid', 'truncated_item', start, None, 'truncated long item header'))
            length = data[pos]
            pos += 2
            if pos + length > len(data):
                raise ParseError(Diagnostic('invalid', 'truncated_item', start, None, 'truncated long item payload'))
            pos += length
            blocked = blocked or Diagnostic('blocked', 'long_item', start, None, 'long items are outside the supported subset')
            continue
        length = (0, 1, 2, 4)[prefix & 3]
        if pos + length > len(data):
            raise ParseError(Diagnostic('invalid', 'truncated_item', start, None, 'truncated short item payload'))
        items.append(Item(start, prefix, (prefix >> 2) & 3, prefix >> 4, data[pos:pos + length]))
        pos += length
    return tuple(items), (blocked,) if blocked else ()


def tokenize(data: bytes, limits: Limits = DEFAULT_LIMITS) -> tuple[Item, ...]:
    items, diagnostics = _scan_items(data, limits)
    if diagnostics:
        raise ParseError(diagnostics[0])
    return items


# No reference-library implementation is imported or embedded here.
from dataclasses import dataclass, field
from hashlib import sha256
from .model import (Collection, CollectionIdentity, Descriptor, FieldKey, Report,
                    ReportKey, Scalar, Sources, SourceSpan)


@dataclass
class _CollectionBuilder:
    identity: CollectionIdentity
    source: SourceSpan
    sources: Sources
    children: list = field(default_factory=list)

    def freeze(self):
        return Collection(self.identity, self.source, tuple(c.freeze() for c in self.children), self.sources)


@dataclass
class _ReportBuilder:
    key: ReportKey
    bits: int = 0
    fields: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    sources: list = field(default_factory=list)


@dataclass(frozen=True)
class _Usage:
    value: int
    extended: bool
    source: SourceSpan

    def resolve(self, page):
        return (self.value >> 16, self.value & 65535) if self.extended else (page, self.value)


_GLOBAL_NAMES = {0: 'usage_page', 1: 'logical_min', 2: 'logical_max',
                 3: 'physical_min', 4: 'physical_max', 5: 'unit_exponent',
                 6: 'unit', 7: 'report_size', 8: 'report_id', 9: 'report_count'}
_MAIN_KINDS = {8: 'input', 9: 'output', 11: 'feature'}


def parse_descriptor(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Descriptor:
    """Parse bytes into supported scalar reports, retaining fail-closed diagnostics.

    Status means parser coverage only; it is never an equivalence decision.
    """
    if not isinstance(data, bytes):
        raise TypeError('descriptor must be immutable bytes')
    digest = sha256(data).hexdigest()
    try:
        items, token_diagnostics = _scan_items(data, limits)
    except ParseError as exc:
        return Descriptor(digest, len(data), False, (), (), (exc.diagnostic,))
    structure = _structure_diagnostics(items, len(data))
    globals_ = {}
    origins = {}
    stack = []
    collections = []
    roots = []
    sibling_keys = {}
    reports = {}
    diagnostics = list(token_diagnostics + structure)
    usages = []
    minimum = maximum = None
    numbered = False
    seen_report = False
    field_count = 0
    field_keys = set()

    def sources_for(item, include_usages=True):
        # Only Main items consume local usages. Copying pending locals into
        # every unrelated unknown Global/Local diagnostic amplifies a bounded
        # descriptor quadratically without providing causal provenance.
        usage_spans = (tuple(u.source for u in usages) + tuple(u.source for u in (minimum, maximum) if u is not None)) if include_usages else ()
        return Sources(SourceSpan(item.offset, len(item.data) + 1), usage_spans, tuple(sorted(origins.items())))

    def diag(category, code, item, detail, report=None):
        diagnostic = Diagnostic(category, code, item.offset, report.key if report else None, detail, sources_for(item, include_usages=item.item_type == 0 and item.offset < len(data)))
        for index, existing in enumerate(diagnostics):
            if (existing.category, existing.code, existing.offset) == (category, code, item.offset):
                diagnostics[index] = diagnostic
                return
        (report.diagnostics if report else diagnostics).append(diagnostic)

    def resolve_usages(item, count, report=None):
        page = globals_.get('usage_page')
        if usages and (minimum is not None or maximum is not None):
            diag('blocked', 'mixed_usages', item, 'mixed usage lists and ranges are outside the subset', report)
            return None
        if minimum is not None or maximum is not None:
            if minimum is None or maximum is None:
                diag('blocked', 'usage_range_incomplete', item, 'both usage range endpoints are required', report)
                return None
            if minimum.extended != maximum.extended:
                diag('blocked', 'usage_range_form', item, 'range endpoints must use the same ordinary/extended form', report)
                return None
            lo_page, lo = minimum.resolve(page)
            hi_page, hi = maximum.resolve(page)
            if lo_page is None or hi_page is None:
                diag('blocked', 'usage_page_missing', item, 'ordinary usages require an effective Usage Page', report)
                return None
            if lo_page != hi_page or lo > hi:
                diag('invalid', 'usage_range', item, 'range must be ordered and on a single page', report)
                return None
            if hi - lo + 1 != count:
                diag('blocked', 'usage_count', item, 'expanded usage count must equal Report Count', report)
                return None
            return [(lo_page, value, (minimum.source, maximum.source)) for value in range(lo, hi + 1)]
        if len(usages) != count:
            diag('blocked', 'usage_count', item, 'explicit usage count must equal the consuming item count', report)
            return None
        result = []
        for usage in usages:
            p, u = usage.resolve(page)
            if p is None:
                diag('blocked', 'usage_page_missing', item, 'ordinary usages require an effective Usage Page', report)
                return None
            result.append((p, u, (usage.source,)))
        return result

    for item in items:
        value = int.from_bytes(item.data, 'little')
        span = SourceSpan(item.offset, len(item.data) + 1)
        if item.item_type == 1:
            if item.tag in (10, 11):
                if item.data:
                    diag('invalid', 'item_size', item, 'Push and Pop have zero data bytes')
                    continue
                if item.tag == 10:
                    if len(stack) >= limits.max_global_depth:
                        diag('blocked', 'global_depth', item, 'global stack depth limit exceeded')
                        break
                    stack.append((globals_.copy(), origins.copy()))
                elif not stack:
                    pass  # Reported by the complete structure pass.
                else:
                    globals_, origins = stack.pop()
                continue
            name = _GLOBAL_NAMES.get(item.tag)
            if name is None:
                diag('blocked', 'unknown_global', item, 'unmodeled global item poisons descriptor coverage')
                continue
            if not item.data:
                diag('blocked', 'zero_data_global', item, 'zero-data global value items are outside independently verified grammar')
                continue
            if item.tag in (1, 3):
                value = int.from_bytes(item.data, 'little', signed=True)
            if item.tag in (2, 4):
                min_name = 'logical_min' if item.tag == 2 else 'physical_min'
                if min_name not in globals_:
                    diag('blocked', name + '_before_min', item, 'maximum before an explicit minimum is outside the subset')
                elif globals_[min_name] < 0:
                    value = int.from_bytes(item.data, 'little', signed=True)
            if item.tag == 0 and value > 65535:
                diag('invalid', 'usage_page', item, 'Usage Page exceeds 16 bits')
            elif item.tag == 5:
                if value > 15:
                    diag('blocked', 'unit_exponent_encoding', item, 'only canonical four-bit unit exponents are supported')
                else:
                    value = value if value < 8 else value - 16
            elif item.tag == 6:
                if 5 <= (value & 15) <= 14 or value >> 28:
                    diag('blocked', 'unit_encoding', item, 'reserved unit system or reserved high nibble')
            elif item.tag == 8:
                if not 1 <= value <= 255:
                    diag('invalid', 'report_id', item, 'Report ID must be 1 through 255')
                if stack and value != globals_.get('report_id'):
                    diag('blocked', 'report_id_in_push', item, 'Report ID changes within Push lack a trustworthy external oracle')
                if seen_report and not numbered:
                    diag('invalid', 'mixed_report_ids', item, 'first Report ID must precede every report Main item')
                numbered = True
            globals_[name] = value
            origins[name] = span
            continue
        if item.item_type == 2:
            if item.tag not in (0, 1, 2):
                diag('blocked', 'unsupported_local', item, 'unmodeled local item poisons descriptor coverage')
                continue
            if not item.data:
                diag('blocked', 'zero_data_local', item, 'zero-data local value items are outside independently verified grammar')
                continue
            usage = _Usage(value, len(item.data) == 4, span)
            if item.tag == 0:
                usages.append(usage)
            elif item.tag == 1:
                if minimum is not None:
                    diag('blocked', 'multiple_usage_ranges', item, 'multiple usage ranges are not supported')
                minimum = usage
            else:
                if maximum is not None:
                    diag('blocked', 'multiple_usage_ranges', item, 'multiple usage ranges are not supported')
                maximum = usage
            continue
        if item.item_type != 0:
            diag('blocked', 'reserved_item', item, 'reserved item type poisons descriptor coverage')
            continue

        # Every Main item resets local state, even unsupported Main tags.
        if item.tag == 10:
            if value > 3:
                diag('blocked', 'collection_type', item, 'only Collection types 0 through 3 are supported')
            values = resolve_usages(item, 1)
            page, usage = (values[0][0], values[0][1]) if values else (-1, -1)
            identity = CollectionIdentity(value, page, usage)
            parent_path = tuple(c.identity for c in collections)
            seen = sibling_keys.setdefault(parent_path, set())
            if identity in seen:
                diag('blocked', 'duplicate_collection', item, 'duplicate sibling collection identity')
            seen.add(identity)
            if len(collections) >= limits.max_collection_depth:
                diag('blocked', 'collection_depth', item, 'collection depth limit exceeded')
                break
            node = _CollectionBuilder(identity, span, sources_for(item))
            (collections[-1].children if collections else roots).append(node)
            collections.append(node)
        elif item.tag == 12:
            if item.data:
                diag('invalid', 'item_size', item, 'End Collection must have zero data bytes')
            if not collections:
                pass  # Reported by the complete structure pass.
            else:
                collections.pop()
        elif item.tag in _MAIN_KINDS:
            seen_report = True
            key = ReportKey(_MAIN_KINDS[item.tag], globals_.get('report_id'))
            if key not in reports:
                if len(reports) >= limits.max_reports:
                    diag('blocked', 'report_limit', item, 'report-kind/ID pair limit exceeded')
                    break
                reports[key] = _ReportBuilder(key)
            report = reports[key]
            report.sources.append(sources_for(item))
            width, count = globals_.get('report_size'), globals_.get('report_count')
            if width is None or count is None:
                diag('blocked', 'report_shape_missing', item, 'explicit Report Size and Report Count are required', report)
            elif width <= 0 or count <= 0:
                diag('invalid', 'report_shape', item, 'Report Size and Count must be positive', report)
            elif width * count + report.bits > limits.max_payload_bits:
                diag('blocked', 'payload_limit', item, 'payload bit limit exceeded; parsing stopped descriptor-wide')
                break
            else:
                offset = report.bits
                report.bits += width * count
                if value & 1:
                    if value not in (1, 3):
                        diag('blocked', 'unsupported_flags', item, 'Constant flags must be 0x01 or 0x03', report)
                elif value not in (2, 6):
                    code = 'data_array' if not value & 2 else 'unsupported_flags'
                    diag('blocked', code, item, 'Data flags must be 0x02 or 0x06', report)
                elif width > 32:
                    diag('blocked', 'scalar_width', item, 'Data scalar widths are limited to 1 through 32', report)
                elif field_count + count > limits.max_fields:
                    diag('blocked', 'field_limit', item, 'expanded Data scalar limit exceeded; parsing stopped descriptor-wide')
                    break
                elif 'logical_min' not in globals_ or 'logical_max' not in globals_:
                    diag('blocked', 'logical_bounds_missing', item, 'explicit logical minimum and maximum are required', report)
                else:
                    lo, hi = globals_['logical_min'], globals_['logical_max']
                    signed = lo < 0
                    lower = -(1 << (width - 1)) if signed else 0
                    upper = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
                    if not lower <= lo <= hi <= upper:
                        diag('invalid', 'logical_range', item, 'logical bounds are unordered or not representable', report)
                    else:
                        values = resolve_usages(item, count, report)
                        if values is not None:
                            physical_lo, physical_hi = globals_.get('physical_min'), globals_.get('physical_max')
                            if physical_lo is None or physical_hi is None or physical_lo == physical_hi == 0:
                                physical_lo, physical_hi = lo, hi
                            elif physical_lo > physical_hi:
                                diag('invalid', 'physical_range', item, 'physical bounds are unordered', report)
                            path = tuple(c.identity for c in collections)
                            for index, (page, usage, usage_sources) in enumerate(values):
                                field_key = FieldKey(key, path, page, usage)
                                if field_key in field_keys:
                                    diag('blocked', 'duplicate_field', item, 'scalar field identity is ambiguous', report)
                                field_keys.add(field_key)
                                report.fields.append(Scalar(field_key, offset + index * width, width, signed,
                                    lo, hi, physical_lo, physical_hi, globals_.get('unit', 0),
                                    globals_.get('unit_exponent', 0), value,
                                    Sources(span, usage_sources, tuple(sorted(origins.items())))))
                            field_count += count
        else:
            diag('blocked', 'unknown_main', item, 'unmodeled Main item poisons descriptor coverage')
        usages = []
        minimum = maximum = None

    eof = Item(len(data), 0, 0, 0, b'')
    for report in reports.values():
        if report.bits % 8:
            diag('blocked', 'report_alignment', eof, 'declared payload length must be byte-aligned', report)
    frozen_reports = tuple(Report(r.key, r.bits, (r.bits + 7) // 8 + (r.key.report_id is not None),
                                  tuple(r.fields), tuple(r.diagnostics), tuple(r.sources)) for r in reports.values())
    return Descriptor(digest, len(data), numbered, frozen_reports,
                      tuple(c.freeze() for c in roots), tuple(diagnostics))


def _structure_diagnostics(items: tuple[Item, ...], length: int) -> tuple[Diagnostic, ...]:
    """Check all structural nesting, including beyond a later resource stop."""
    collections = pushes = 0
    result = []
    for item in items:
        value = int.from_bytes(item.data, 'little')
        if ((item.item_type == 1 and item.tag in (10, 11)) or (item.item_type == 0 and item.tag == 12)) and item.data:
            result.append(Diagnostic('invalid', 'item_size', item.offset, None, 'Push, Pop and End Collection require zero data bytes'))
        if item.item_type == 1 and item.tag == 8 and item.data and not 1 <= value <= 255:
            result.append(Diagnostic('invalid', 'report_id', item.offset, None, 'Report ID must be 1 through 255'))
        if item.item_type == 1 and item.tag == 0 and value > 65535:
            result.append(Diagnostic('invalid', 'usage_page', item.offset, None, 'Usage Page exceeds 16 bits'))
        if item.item_type == 0 and item.tag == 10:
            collections += 1
        elif item.item_type == 0 and item.tag == 12:
            if collections:
                collections -= 1
            else:
                result.append(Diagnostic('invalid', 'collection_underflow', item.offset, None, 'End Collection without Collection'))
        elif item.item_type == 1 and item.tag == 10:
            pushes += 1
        elif item.item_type == 1 and item.tag == 11:
            if pushes:
                pushes -= 1
            else:
                result.append(Diagnostic('invalid', 'global_underflow', item.offset, None, 'Pop without Push'))
    if collections:
        result.append(Diagnostic('invalid', 'unbalanced_collection', length, None, 'unclosed Collection at end of descriptor'))
    if pushes:
        result.append(Diagnostic('blocked', 'unbalanced_push', length, None, 'unclosed global Push is outside the supported subset'))
    return tuple(result)
