# CLI and library reference

## Commands

- `hidwire compare OLD NEW --old-format binary|hex --new-format binary|hex`
- `hidwire decode DESCRIPTOR --format binary|hex --report KIND:ID --wire HEX`
- `hidwire witness-check OLD NEW --old-format binary|hex --new-format binary|hex --artifact FILE`

All commands accept `--json`. Compare also accepts repeatable `--report KIND:ID`.
KIND is `input`, `output` or `feature`. ID is `none` or an integer 1–255.
Compare without selectors covers the whole descriptor. File input is Linux-only,
requires procfs, and rejects symlink components as well as nonregular final files.
Input and source files are never modified. `--wire` is hexadecimal data, not a
filename; URLs are never fetched. There is no standard-input or device capture
mode.

The CLI rejects source-size and hexadecimal-format violations with exit 64;
semantic parser limits yield blocked/exit 2.

Descriptor caps: 4096 binary bytes or 65536 strict hexadecimal source bytes,
64 kind/ID reports, 1024 Data scalars, 8192 payload bits/report, 32 collection or
global-stack depth, and 1–32 bits/scalar. A witness artifact is capped at 32 MiB,
2048 witnesses and 32 collection-path entries per identity. Its schema rejects
duplicate keys, non-finite numbers and malformed records.

## JSON version 1

A comparison contains:

- `schema_version`: 1; `contract_version`: "1"; `tool`: name/version
- `status`: equal, different, blocked or invalid
- `scope`: mode (all/selected) and normalized selected report keys
- `sources`: old/new SHA-256 hashes of decoded descriptor bytes and byte lengths
- `coverage`: every observed report on each side, its selected flag, parser
  status, exact payload/wire shape, field count and Main-item source records
- `diagnostics`: both sides' categorized, zero-based descriptor offsets and
  source records where a semantic state is available, including unselected reports
- `differences`: ordered schema, metadata or raw_value records with report/field
  identities, old/new values and effective declaration sources
- `witnesses`: report key, compact hex wire bytes, old/new hashes, differing
  field identity, old/new integers, old/new whole-report logical-range booleans
- `witness_semantics`: the scope of these raw-extraction counterexamples

A field identity contains report kind/ID, collection type/page/usage path, and
numeric usage page/ID. Source spans give decoded-byte offset and length. Globals
include the effective origin even when inherited or restored by Pop. Report
sources retain Constant Main items too. A resource-limited coverage list is
partial and the result is blocked. It is never a complete inventory in that case.

Ordering is stable: input/output/feature, absent ID before numeric IDs, then
numeric collection and scalar identities. JSON keys are sorted and no timestamp
or machine path is emitted. Reordered descriptor declarations may alter source
spans even when the compared contract is equal.

Saved artifact verification checks each listed witness independently. It does
not trust the artifact's `status`, `differences`, metadata or claimed coverage;
those fields are not certified by `witness-check`. Re-run `compare` to establish
a complete result. Source binding lives in each witness. SHA-256 binds bytes,
not authorship or authenticity. An empty witness artifact is an invocation error.

## Library

```python
from hidwire import parse_descriptor, compare_descriptors, decode_report, verify_witness
from hidwire.model import ReportKey

old = parse_descriptor(old_descriptor_bytes)
new = parse_descriptor(new_descriptor_bytes)
result = compare_descriptors(old, new)  # immutable Comparison
selected = compare_descriptors(old, new, (ReportKey('output', 1),))
values = decode_report(old, ReportKey('input', 2), bytes.fromhex('02 05 50 a0 ff'))
assert all(verify_witness(old, new, w) for w in result.witnesses)
```

`parse_descriptor` accepts immutable bytes. `compare_descriptors` and
`decode_report` expect models returned by that parser; arbitrary manually forged
model objects are outside the API contract. `Descriptor.status` is a parser
coverage classification (`supported`, `blocked`, `invalid`), while
`Comparison.status` is the comparison decision. The decoder refuses missing,
invalid or unsupported reports. It returns raw integers without clamping.
The byte-model functions have no OS-specific implementation, but only Linux
execution is verified in this release. File safety and CLI support are explicitly
Linux-specific.
