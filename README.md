# HidWire

Compare two exported HID report descriptors before a firmware rewrite. HidWire
checks whether they describe the **same supported scalar wire contract**, and
produces replayable raw-report counterexamples when integer extraction changes.
It also reports changes to report shapes, identities and metadata separately.

This is an alpha, offline review tool with a deliberately narrow contract.
Data Arrays, including common keyboard Input reports, are unsupported. It does
not establish USB/HID conformance, firmware correctness, or host/hardware
compatibility. See [the supported contract](docs/contract.md).

## Install

Python 3.11 or newer. The command-line file reader requires **Linux with procfs**;
it refuses unsupported file-access capabilities rather than falling back to an
unsafe reader. The first [hosted verification run](https://github.com/loaff123/HidWire/actions/runs/39195924690)
passed on Linux x86_64 (`ubuntu-24.04`) with Python 3.11–3.15 on 19 October 2026.
Each version passed 183 source tests and 183 installed-wheel tests outside the
checkout; Python 3.12 also detected all 14 targeted mutations. This is evidence
for the tested scalar contract, not general device or operating-system
compatibility. No Windows or macOS support is claimed. The package uses only
the Python standard library at runtime.

Install from this source repository in a virtual environment:

```sh
git clone https://github.com/loaff123/HidWire.git
cd HidWire
python -m venv .venv
.venv/bin/python -m pip install --no-deps .
.venv/bin/hidwire --help
```

This repository is a source-only publication; it does not publish packages to
PyPI or attach prebuilt release binaries. The installation command obtains its
build backend from PyPI. For a fully offline review, run directly from the
checkout with `PYTHONPATH=src python -m hidwire` in place of `hidwire`.
Examples, fixtures, tests and documentation are included in the checkout.

## Compare two descriptors

Specify each file's format explicitly. Hex files may contain only ASCII hex
digits and whitespace, with no `0x` prefixes or comments. Binary files contain
only the exported descriptor bytes. Files must be regular files; symlinks,
devices, pipes, sockets and URL fetching are not supported.

```sh
hidwire compare fixtures/real/circuitpython-mouse.bin fixtures/real/circuitpython-mouse.bin \
  --old-format binary --new-format binary
```

Expected status: `equal`, with scope `all reports`.

A deliberate X/Y swap demonstrates a different raw extraction function:

```sh
hidwire compare fixtures/real/circuitpython-mouse.bin examples/mouse-swapped.hex \
  --old-format binary --new-format hex --json > comparison.json
```

Expected exit code: **1** (`different`). The saved JSON contains two checked
counterexamples using report `02 00 01 00 00`: X changes from 1 to 0 and Y from
0 to 1. Exit 1 is a comparison result, not an invocation failure.

```sh
hidwire witness-check fixtures/real/circuitpython-mouse.bin examples/mouse-swapped.hex \
  --old-format binary --new-format hex --artifact comparison.json
```

Expected: `verified: 2 raw-extraction witnesses`. This command checks source
hashes, exact framing, both integers and whole-report range labels. It checks
saved witnesses only; it does not certify that a modified artifact contains all
differences or proves equality. An empty witness list is rejected.

A witness may be out of logical range. Every range label checks **all scalar
fields in that report**, including unchanged fields with positive minima.
HidWire never calls a witness a valid device report.

## Select a narrower report

```sh
hidwire compare fixtures/real/circuitpython-keyboard.bin fixtures/real/circuitpython-keyboard.bin \
  --old-format binary --new-format binary --report output:1
```

Expected: `equal` for `output:1`. The whole keyboard comparison is `blocked`
because its Input includes Data Arrays. A selected result never verifies the
unselected Input. Repeat `--report` for multiple exact selections; use
`input:none` for an unnumbered report. Missing on one side means different;
missing on both sides is an invocation error. Unknown global state and malformed
syntax still prevent a selected report from obtaining an unsafe green result.

## Decode one wire report

```sh
hidwire decode fixtures/real/circuitpython-mouse.bin --format binary \
  --report input:2 --wire '02 05 50 a0 ff' --json
```

The decoded values are buttons 1/3 pressed, X=80, Y=-96, wheel=-1.
The ID byte belongs in numbered reports; unnumbered reports have no synthetic
zero prefix. Short, oversized or wrong-ID buffers are rejected.

## Results and automation

- Exit **0**: equal, or a successful decode/witness check
- Exit **1**: different, or a witness check that fails
- Exit **2**: blocked by unsupported semantics or a semantic parser resource limit
- Exit **3**: structurally invalid descriptor
- Exit **64**: invocation, I/O, strict-input (including file-size caps) or malformed-artifact error

Comparison precedence is invalid, blocked, different, equal. Supported reports
can retain proven partial differences when another report blocks completeness.
No identical-bytes shortcut can turn unsupported descriptors into `equal`.

`--json` emits deterministic schema-version-1 JSON without timestamps or input
paths. It includes hashes, selected scope, coverage for both descriptors,
normalized report framing, categorized differences, inherited source-byte spans,
raw-extraction witnesses and range labels. Metadata-only changes, such as
Relative/Absolute or units, do not invent an integer witness.
See [CLI and API details](docs/usage.md) and [the exact decision](docs/proof.md).

## Verification and development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_mutations.py
python scripts/verify_comparison_mutations.py
```

The independent reference is optional for use, but mandatory for the external
acceptance suite. Install the hash-pinned official PyPI dependencies in a
separate development environment:

```sh
python -m venv .oracle-venv
.oracle-venv/bin/python -m pip install --no-deps --require-hashes -r tests_oracle/requirements.txt
PYTHONPATH=src .oracle-venv/bin/python -m unittest discover -v
```

For offline installation, add `--no-index --find-links /path/to/verified/wheels`.
Missing or wrong reference versions fail the suite; they are never skips.
No GPL reference implementation or wheel is bundled with HidWire.

The read-only [GitHub Actions workflow](.github/workflows/tests.yml) runs source
tests and the complete installed-wheel suite outside the checkout, with no source
package present in that test directory. It also checks targeted mutations on
Python 3.12. It has no upload or publication job. See the CI details in
[verification coverage](docs/verification.md).

Read [verification coverage](docs/verification.md), [known reference
counterexamples](docs/oracle-notes.md), and [fixture provenance](fixtures/manifest.json).
The fixture sources and complete MIT notices are included. There is no device
access, firmware execution, credential handling or input-driven network activity.

## License

Original implementation: [MIT](LICENSE). Third-party fixture attributions and
MIT notices: [fixtures/NOTICE.md](fixtures/NOTICE.md). No USB-IF standards PDF or
unlicensed capture is redistributed.
