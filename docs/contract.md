# Supported scalar wire contract

## Scope

A complete `equal` result means all selected constructs fit the subset below,
and their report shapes, scalar identities, integer extraction functions and
normalized metadata match. `supported` is the parser coverage status,
not a hardware or host compatibility claim. Full-descriptor comparisons also
compare all collection identity paths, including empty collections. Selected
report comparisons cover only selected shapes and scalar collection paths.

`different` means a complete comparison found a contract difference. `blocked`
means unsupported semantics or resource bounds prevent completeness; `invalid`
means malformed input. Incomplete results never mean equality.

The file reader treats source-size/hex-format violations as invocation errors
(exit 64). Limits reached during parsing are blocked results (exit 2).

Input bounds: 4,096 decoded descriptor bytes; 65,536 strict-hex source bytes; 64 report-kind/ID pairs; 1,024 expanded Data scalars; 8,192 declared payload bits per report; 32 collection and global-stack depth; scalar widths 1–32. Custom positive integer limits may be supplied. Constants are bounded before any expansion and are not emitted as observable fields.

## Accepted state and identity

- Short items with 1/2/4-byte value encodings; explicit numeric Usage, inclusive Usage Minimum/Maximum, Usage Page, Logical/Physical bounds, Unit/Exponent, Report Size/Count/ID, Global Push/Pop, Input/Output/Feature and Collection/End Collection.
- Collection types0/1/2/3. Zero-data Collection means Physical(0); zero-data report Main flags are zero and therefore blocked Data Arrays. Zero-data global/local value items are conservatively blocked pending independent coverage. Push, Pop and End Collection require zero data bytes.
- Ordinary one/two-byte Usage IDs resolve against the page effective at their consuming Main item, including page changes or Pop after the Usage declaration. Four-byte extended usages retain their explicit page.
- Exact usage count, no repeated-last assignment. Ranges must be ordered, same-page and same ordinary/extended form at both endpoints. Mixed lists/ranges, multiple ranges, missing usage and duplicate field/sibling collection identities block.
- Field identity includes report kind/ID, the collection type/page/usage path and numeric field page/usage. Vendor numeric usages are opaque identifiers.
- Push/Pop copies/restores every modeled global, undefined markers and source declarations. Local state is unaffected by Push/Pop and resets at every Main item. Maximum is decoded at its declaration using the effective minimum, not reinterpreted later.

## Framing and metadata

Each direction/ID has independent cumulative payload offsets. Collection boundaries never reset offsets. Payload bit0 is the least significant bit of payload byte0. No Report-ID declaration means no ID prefix. Numbered reports have IDs1–255 and one prefix byte; the first ID must precede every report Main item. Mixed numbered/unnumbered framing is invalid. Report-ID changes while global state is pushed block descriptor-wide because the chosen reference mishandles restoration.

Declared report payloads must be byte-aligned. Constant-only reports remain in the model. `wire_bytes` includes the ID byte only for numbered reports.

Data flags only0x02/0x06; Constant flags only0x01/0x03. Logical bounds must be explicitly defined, ordered and representable at the field width. Negative logical minimum selects two's-complement signedness, including width1. Maximum before its corresponding explicit minimum is conservatively blocked. Physical defaults resolve to logical bounds if either physical bound is absent or both are zero. Unit/exponent defaults are zero; exponent accepts canonical nibble0..15 mapped to0..7,-8..-1. Reserved unit systems5..14 and a nonzero reserved high nibble block. No physical-unit conversion is inferred.

## Fail-closed coverage

Data Arrays and unsupported known report flags block their report while keeping bounded shape. Unmodeled or unknown state-changing items, invalid collection identity and unsupported global/local encodings block descriptor-wide. Long items are blocked, but later short-item structural errors remain visible. Syntax invalidity takes precedence even under selected-report coverage.

Any application resource limit that stops semantic traversal blocks the entire descriptor. Full byte framing and fixed structural checks still run, including truncated items, Collection/Push nesting, fixed zero-data item sizes, numeric Report-ID validity and Usage-Page width. After a resource stop the model is partial; it does not promise every possible semantic error in the unmodeled remainder is diagnosed. It never reports that remainder as supported.

Diagnostics for interpreted items include the current item and effective inherited globals. Only consuming Main-item diagnostics include pending Usage sources; unrelated Global/Local/reserved items do not depend on or duplicate that pending list. This keeps malformed-input provenance linear in the bounded source size. Collection identities also retain their usage/global sources. Token-level/structure-only errors may have only a byte offset because no effective semantic state was established.

## Exclusions

Data Arrays, keyboard rollover, boot protocol, Null State, wrapping/nonlinear/nonpreferred/volatile/buffered data, delimiter/designator/string locals, long/reserved/unknown items, ambiguous identities, physical descriptors, packet sizing, enumeration, host quirks, transport/API buffer padding, HID-over-GATT and proprietary vendor semantics.

File access rejects every symlink component and nonregular object. A Linux `O_PATH` handle identifies an inode without device/FIFO I/O; only a verified regular inode is reopened through procfs. Reads are capped even if the file grows. Input files are never modified. The core never retrieves URLs, executes firmware, imports descriptor-provided code, or uses credentials.

## Exact comparison and range labels

The scalar function is its little-endian extraction, interpreted as signed when
Logical Minimum is negative. The comparator compares sparse integer coefficient
vectors over payload bits. Equal coefficients prove equality for every raw
payload. A lowest differing coefficient yields a deterministic one-hot payload
when both sides have identical report framing. Report IDs are fixed prefix
bytes, not variables. A separate direct-shift/mask decoder verifies each emitted
witness and its source hashes. See [proof and limitations](proof.md).

Logical/physical bounds, unit/exponent and flags compare separately. Raw values
are never clamped. Metadata-only changes have no integer counterexample. Range
labels test every Data scalar of that whole report against its logical bounds.
No search for a jointly range-valid witness is promised. Shape/key differences
may have no raw-value witness. Reordered or split padding may remain equal when
report shape and all observable functions are unchanged.

Reports include consuming Main and inherited-global provenance, including
Constant-only shapes. Source offsets are zero-based bytes in the decoded
descriptor, not character offsets in a hexadecimal source file.
