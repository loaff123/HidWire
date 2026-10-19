# Independent reference and known counterexamples

The tests compare bounded parsing and generated raw-extraction witnesses with
hid-tools. A separate hand-authored bit-loop oracle enumerates small report
models. These checks do not establish general HID, device or host compatibility.

## Reproduce offline

Python 3.12.14 was used. The product has no oracle runtime dependency. Create a
separate environment and install only the two parser dependencies from the
previously downloaded official PyPI wheels:

```sh
python -m venv .oracle-venv
WHEELS=/path/to/verified/wheels
.oracle-venv/bin/python -m pip install \
  --no-cache-dir --no-index --no-deps --require-hashes \
  --find-links "$WHEELS" -r tests_oracle/requirements.txt
PYTHONPATH=src .oracle-venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=src .oracle-venv/bin/python -m unittest discover -s tests_oracle -v
PYTHONPATH=src .oracle-venv/bin/python -m unittest discover -v
```

The wheel directory is external research evidence, not a directory bundled with
this product. No package download, network, hardware, HID kernel interfaces or device access is
needed. `--no-deps` intentionally avoids unrelated capture/device dependencies;
only the pure parser and `parse` are invoked. The requirements pin:

- hid-tools 0.12: SHA-256 `37e56369ac88d0b151f7529a77b53bac2f0dbdc2d0845a5d261b22ff0a524680`
- parse 1.22.3: SHA-256 `2cd33a301b5a4b400ee79952f42364fe486e5f10701fbf819fbbab1eab478139`

The actual wheels were independently hashed, then force-reinstalled offline with
`--require-hashes`. The adapter checks installed versions. Missing dependencies
raise an error; the suite never skips required reference checks. A subprocess test
with `python -S` verifies that the missing-oracle path really fails.

See [verification coverage](verification.md) for measured release checks.

## Fixture provenance and rights

Four binary fixtures are independently checked against their exact pinned source
initializers, not merely against another output of the product parser:

- CircuitPython mouse: 64 bytes, SHA-256 `8641a1658bc9b779a7d69166f5d4c9d2992101fc6085711868e72b8743015f8b`
- CircuitPython keyboard: 67 bytes, SHA-256 `17e28792f7b3c412bd2b49fdb80caa8c410457cfe0dd5be150e893c26e17c550`
- CircuitPython consumer control: 25 bytes, SHA-256 `644862deff2b1fd2af03e6f137b1fa43d7dd0ce8df15084b30bde22607f4a657`
- Waratah README mouse: 50 bytes, SHA-256 `630b3cebc8cc2db05afc886a7ea39cad9af2fd6a0c5c94ebc237233f44ee5a82`

`fixtures/manifest.json` retains source URLs, commits, Git blob hashes, file
SHA-256 hashes, initializer symbols, binary hashes and MIT license paths. The
original sources and complete license notices are bundled. Each research text
retrieval had exactly one extra final LF; removing only that byte reproduced all
four recorded original Git blob hashes. This transport normalization is recorded
per source and the tests verify the recovered originals, including the original
Microsoft license's two terminal LFs. No descriptor bytes were normalized.

The keyboard and consumer input reports are intentional negative-scope Data
Array fixtures. Only the keyboard's selected scalar Output report is supported.
No hardware capture or USB-IF standards PDF is bundled. hid-tools is an external
GPL-licensed test dependency; neither its implementation nor its wheel is copied
into the permissively licensed product. Its wheel metadata says GPL-2.0-only;
source/classifier wording elsewhere differs, so redistributing that dependency
would need a separate license review.

## Adapter invariants and coverage

`tests_oracle/adapter.py` has no product imports. It calls
`hidtools.hid.ReportDescriptor.from_bytes` and the oracle fields' `get_values`,
without copying any implementation. It preserves raw reference metadata and
never "fixes" a known disagreement to agree with the product.

- Oracle report ID -1 becomes `None`. Only numbered field offsets lose 8 bits.
  Exact caller-provided wire bytes are passed to the oracle; no zero ID is added.
- Length must equal the declared byte-aligned wire length; wrong ID, short,
  oversized and non-byte-aligned reports fail. Permissive oracle report lookup
  and its rounded byte-size property are not used.
- Constant Array and Constant Variable are padding; Data Arrays are refused as
  scalar oracle reports. Constant-only report shape remains visible.
- Ordered scalar values preserve repeated numeric usages in distinct collection
  paths. The convenience numeric dictionary refuses duplicates rather than
  overwriting. Full collection identity/source spans are separately hand-authored
  goldens because the external parser cannot provide an equivalent source model.
- Supported Input, Output and Feature, multiple IDs, independent offsets,
  collection types 0–3, zero-data Collection, both Data flags, both Constant
  flags, ordinary/extended usages and ranges, late page binding, vendor usage
  pages, 1/2/4-byte item encodings, redundant globals, nested Push/Pop, local
  state persistence across Push/Pop, all unit exponents and supported unit-system
  values have differential cases. Report ID changes inside Push remain blocked.
- All unsigned widths 1–32 and signed widths 2–32 are checked at starts 0, 1, 3,
  and 7 with explicit sample bytes. Signed width 1 has separate independent
  coverage, as explained below. Global/source restoration and physical defaults
  have explicit expected metadata rather than product-generated expectations.
- Real mouse goldens reproduce `02 05 50 a0 ff`: buttons 1/3, X=80, Y=-96,
  Wheel=-1. Waratah `01 50 a0 05` and keyboard Output `01 15` are also goldens.
- All 65,536 X/Y byte pairs, 32 button combinations and 256 wheel values are
  checked against explicit two's-complement expectations and the parsed product
  layout. These are independent field sweeps, not every 32-bit report.
- A signed 12-bit field starting at bit 3 is checked for every one of 65,536
  possible 16-bit payloads. Each expected value is independently computed.
- The known X/Y-swap raw report `02 00 01 00 00` is decoded by the oracle on both
  fixture variants. The comparator also generates this witness;
  external tests replay each generated witness on both descriptors.

## Explicit oracle capability exceptions

These are positive tests that preserve disagreements, not skips or xfails. The
independent expected values remain separate from the raw hid-tools results.
An independent reviewer approved the signed semantics using the primary sources
below. No unexplained mismatch is converted into a claimed differential pass.

### Signed one-bit values: external value cell excluded

Descriptor:

`05010902a10115ff25007501950109308102750795018101c0`

The field has width 1, logical minimum -1, maximum 0. hid-tools 0.12 returns 1 for
raw bit 1; two's-complement semantics require -1. Raw bit 0 returns 0 in both.
The product retains signed-one-bit support. The exact truth table `0 → 0,
1 → -1` is tested independently at every bit offset 0–7 over all 256 byte values.
Only the signed-width-1 external value comparison is excluded. The test also
asserts the uncorrected oracle result 1 so a changed oracle capability cannot be
silently assumed.

Authority: [HID 1.11](https://www.usb.org/sites/default/files/hid1_11.pdf), §5.8
(printed p.19) and §6.2.2.7 remarks (printed p.38), independently reviewed.

### Negative maxima: external metadata cells excluded

Logical example: `05010902a101158025ff7508950109308102c0`.
Physical example: `05010902a1011580257f358045ff7508950109308102c0`.

An effective negative minimum makes the corresponding maximum signed. An
encoded all-ones maximum is -1 for 1-, 2-, and 4-byte items. hid-tools instead
exposes 255, 65,535 and 4,294,967,295. Only these negative Logical Maximum and
negative Physical Maximum **metadata** comparisons are excluded; the independently
expected signed maxima are tested directly and the raw oracle discrepancies are
asserted. The same cases still compare raw signed extraction (`ff → -1`) with
hid-tools. Positive maxima and unsigned-max controls remain differential.

In addition to HID 1.11's signed semantics, the independent review checked
[Linux v6.12 hid-core.c](https://github.com/torvalds/linux/blob/v6.12/drivers/hid/hid-core.c):
`hid_parser_global` selects `item_sdata` for Logical Maximum when the effective
logical minimum is negative and likewise for Physical Maximum and physical
minimum; otherwise it selects `item_udata`. `item_sdata` sign-extends 1/2/4-byte
items. This corroborates the descriptor interpretation; it is not a claim of
compatibility with every host.

### Report ID inside Push: product subset excludes it

Descriptor:

`05010902a10185011500257f7508950109308102a4850209318102b409388102c0`

A full global restore would put X/Wheel in ID1 and Y in ID2. hid-tools keeps X
in ID1 and Y/Wheel in ID2. The product blocks a changed ID while a global state
is pushed; the exact raw oracle grouping and product diagnostic are regression
assertions. Unchanged Report ID inside Push and all other modeled global
restoration remain differentially covered.

### Zero-data global/local values: conservative product boundary

hid-tools accepts zero-data Logical Minimum `14` as zero. The product explicitly
blocks unproven zero-data global/local value encodings rather than declaring
malformed HID or claiming unsupported agreement. Zero-data Input/Output/Feature
are valid defaults to Array flags and therefore blocked as Data Arrays; zero-data
Collection defaults to Physical and is supported. These are explicit boundary
choices, not adapter corrections.

### hid-parser 0.1.0 is excluded entirely as a value oracle

The pinned research probe on mouse report `02 05 50 a0 ff` returned false for all
buttons and unsigned Y=160/Wheel=255, while explicit expectations and hid-tools
agree on buttons1/3, Y=-96/Wheel=-1. Its late-page binding also differs and Push
is unsupported. This documents only the tested version, not later releases or
its development branch. Its wheel hash was verified as
`65111ea2eefb44e526f30e126db626ad6c6a8b83366573670cc07cffb3931665`; it is not
installed in the acceptance environment, imported by these tests, or substituted
when the required oracle is missing.
