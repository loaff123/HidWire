"""Immutable data records for the bounded scalar HID contract (MIT)."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_descriptor_bytes: int = 4096
    max_text_bytes: int = 65536
    max_reports: int = 64
    max_fields: int = 1024
    max_payload_bits: int = 8192
    max_collection_depth: int = 32
    max_global_depth: int = 32

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in vars(self).values()):
            raise ValueError('limits must be positive integers')


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class Diagnostic:
    category: str
    code: str
    offset: int
    report_key: object | None
    detail: str
    sources: "Sources | None" = None


@dataclass(frozen=True)
class Item:
    offset: int
    prefix: int
    item_type: int
    tag: int
    data: bytes


@dataclass(frozen=True)
class ReportKey:
    kind: str
    report_id: int | None


@dataclass(frozen=True)
class CollectionIdentity:
    kind: int
    page: int
    usage: int


@dataclass(frozen=True)
class FieldKey:
    report_key: ReportKey
    path: tuple[CollectionIdentity, ...]
    page: int
    usage: int


@dataclass(frozen=True)
class SourceSpan:
    offset: int
    length: int


@dataclass(frozen=True)
class Sources:
    main: SourceSpan
    usages: tuple[SourceSpan, ...]
    globals: tuple[tuple[str, SourceSpan], ...]

    def global_origin(self, name: str) -> SourceSpan | None:
        return next((span for key, span in self.globals if key == name), None)


@dataclass(frozen=True)
class Scalar:
    key: FieldKey
    bit_offset: int
    width: int
    signed: bool
    logical_min: int
    logical_max: int
    physical_min: int
    physical_max: int
    unit: int
    unit_exponent: int
    flags: int
    sources: Sources


@dataclass(frozen=True)
class Collection:
    identity: CollectionIdentity
    source: SourceSpan
    children: tuple['Collection', ...]
    sources: Sources | None = None


@dataclass(frozen=True)
class Report:
    key: ReportKey
    payload_bits: int
    wire_bytes: int
    fields: tuple[Scalar, ...]
    diagnostics: tuple[Diagnostic, ...]
    sources: tuple[Sources, ...] = ()


@dataclass(frozen=True)
class Descriptor:
    sha256: str
    byte_length: int
    numbered: bool
    reports: tuple[Report, ...]
    collection_tree: tuple[Collection, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def status(self) -> str:
        return self.status_for(tuple(report.key for report in self.reports))

    def status_for(self, keys: tuple[ReportKey, ...]) -> str:
        # Malformed syntax is descriptor-wide even when exposed at a report item.
        all_diagnostics = self.diagnostics + tuple(d for r in self.reports for d in r.diagnostics)
        if any(d.category == 'invalid' for d in all_diagnostics):
            return 'invalid'
        selected = self.diagnostics + tuple(d for r in self.reports if r.key in keys for d in r.diagnostics)
        if any(d.category == 'blocked' for d in selected):
            return 'blocked'
        if any(key not in {r.key for r in self.reports} for key in keys):
            return 'invalid'
        return 'supported'


@dataclass(frozen=True)
class DecodedValue:
    key: FieldKey
    value: int
    in_range: bool


@dataclass(frozen=True)
class DecodedReport:
    report_key: ReportKey
    values: tuple[DecodedValue, ...]
    all_fields_in_range: bool
    out_of_range_keys: tuple[FieldKey, ...]


@dataclass(frozen=True)
class Difference:
    kind: str
    component: str
    report_key: ReportKey | None
    field_key: FieldKey | None
    old: object
    new: object
    old_sources: Sources | None = None
    new_sources: Sources | None = None
    old_report_sources: tuple[Sources, ...] = ()
    new_report_sources: tuple[Sources, ...] = ()


@dataclass(frozen=True)
class Witness:
    report_key: ReportKey
    wire_hex: str
    old_hash: str
    new_hash: str
    differing_key: FieldKey
    old_value: int
    new_value: int
    old_range_valid: bool
    new_range_valid: bool


@dataclass(frozen=True)
class Comparison:
    status: str
    scope: tuple[ReportKey, ...] | None
    selected_reports: tuple[ReportKey, ...]
    old: Descriptor
    new: Descriptor
    differences: tuple[Difference, ...]
    witnesses: tuple[Witness, ...]
