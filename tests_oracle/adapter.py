"""Independent development-only adapter around hid-tools 0.12.

This module imports no HidWire code. It uses the installed GPL oracle as a
separate dependency; no GPL implementation is copied into the product. Raw
oracle metadata remains raw: default normalization belongs in hand-authored
expectations, so this adapter cannot hide a metadata disagreement.
"""
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Any

EXPECTED_VERSIONS = {'hid-tools': '0.12', 'parse': '1.22.3'}


def oracle_versions() -> dict[str, str]:
    try:
        actual = {name: version(name) for name in EXPECTED_VERSIONS}
    except PackageNotFoundError as exc:
        raise RuntimeError('Required oracle missing. Install tests_oracle/requirements.txt '
                           'offline from the pinned, hash-verified wheels; never skip required reference checks.') from exc
    if actual != EXPECTED_VERSIONS:
        raise RuntimeError(f'Oracle version mismatch: expected {EXPECTED_VERSIONS}, got {actual}')
    return actual


oracle_versions()
from hidtools.hid import ReportDescriptor  # noqa: E402; mandatory version check precedes import


class UnsupportedOracleReport(ValueError):
    """The adapter cannot honestly represent this oracle report as scalar values."""


@dataclass(frozen=True)
class ReferenceField:
    kind: str
    report_id: int | None
    usage: int
    bit_offset: int
    width: int
    signed: bool
    logical_min: int
    logical_max: int
    physical_min_raw: int
    physical_max_raw: int
    unit: int
    unit_exponent: int
    flags: int
    _oracle: Any = field(repr=False, compare=False)


@dataclass(frozen=True)
class ReferenceReport:
    key: tuple[str, int | None]
    payload_bits: int
    wire_bytes: int
    fields: tuple[ReferenceField, ...]


def _key(key: Any) -> tuple[str, int | None]:
    # Accept a product ReportKey structurally without importing any product code.
    if hasattr(key, 'kind') and hasattr(key, 'report_id'):
        kind, report_id = key.kind, key.report_id
    else:
        kind, report_id = key
    return str(getattr(kind, 'value', kind)), report_id


class ReferenceDescriptor:
    def __init__(self, data: bytes):
        self._descriptor = ReportDescriptor.from_bytes(list(data))
        self._reports = {}
        for kind in ('input', 'output', 'feature'):
            for raw_id, report in getattr(self._descriptor, kind + '_reports').items():
                normalized = None if raw_id == -1 else raw_id
                if normalized is not None and not 1 <= normalized <= 255:
                    raise UnsupportedOracleReport('Invalid report ID returned by oracle')
                self._reports[(kind, normalized)] = report

    @property
    def keys(self) -> tuple[tuple[str, int | None], ...]:
        return tuple(self._reports)

    def report(self, key: Any) -> ReferenceReport:
        kind, report_id = normalized = _key(key)
        raw = self._reports[normalized]
        prefix_bits = 0 if report_id is None else 8
        payload_bits = raw.bitsize - prefix_bits
        if payload_bits % 8:
            raise UnsupportedOracleReport('Non-byte-aligned declared report; no implicit rounding')
        fields = []
        for item in raw.fields:
            if item.type & 1:  # Constants are padding, including Constant Array.
                continue
            if not item.type & 2 or item.count != 1:
                raise UnsupportedOracleReport('Data Array/grouped field cannot be a scalar oracle')
            fields.append(ReferenceField(
                kind, report_id, item.usage, item.start - prefix_bits, item.size,
                item.logical_min < 0, item.logical_min, item.logical_max,
                item.physical_min, item.physical_max, item.unit, item.unit_exp,
                item.type, item,
            ))
        return ReferenceReport(normalized, payload_bits, (payload_bits + prefix_bits) // 8,
                               tuple(fields))

    def decode_values(self, key: Any, wire: bytes) -> tuple[int, ...]:
        """Return values in descriptor field order without collapsing usages."""
        report = self.report(key)
        if len(wire) != report.wire_bytes:
            raise ValueError(f'Expected exactly {report.wire_bytes} wire bytes; got {len(wire)}')
        if report.key[1] is not None and wire[0] != report.key[1]:
            raise ValueError('Report ID prefix does not match requested report')
        values = []
        # Pass exactly the caller's wire bytes: never add/remove a synthetic ID.
        raw_wire = list(wire)
        for scalar in report.fields:
            extracted = scalar._oracle.get_values(raw_wire)
            if len(extracted) != 1 or extracted[0] is None:
                raise UnsupportedOracleReport('Oracle did not decode exactly one complete scalar')
            values.append(extracted[0])
        return tuple(values)

    def decode(self, key: Any, wire: bytes) -> dict[int, int]:
        report = self.report(key)
        decoded = self.decode_values(key, wire)
        values = {}
        for scalar, value in zip(report.fields, decoded):
            if scalar.usage in values:
                raise UnsupportedOracleReport('Repeated numeric usage would make this dictionary lossy')
            values[scalar.usage] = value
        return values


def reference_fields(data: bytes) -> tuple[ReferenceField, ...]:
    reference = ReferenceDescriptor(data)
    return tuple(field for key in reference.keys for field in reference.report(key).fields)


def reference_decode(data: bytes, key: Any, wire: bytes) -> dict[int, int]:
    return ReferenceDescriptor(data).decode(key, wire)
