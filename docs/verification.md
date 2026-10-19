# Verification summary

Release candidate: 0.1.0a1, 17 October 2026. Tested on Linux x86_64 with
Python 3.12.14. The public contract is bounded scalar wire equivalence, not
USB/HID certification or host/hardware compatibility.

## Automated coverage

The final source suite contains **183 tests: 136 core and 47 external-oracle
tests**, with zero failures or skips. Counts are test methods; many contain
exhaustive loops or multiple adversarial cases.

- Four licensed real-source/example descriptors are checked against original
  source initializers, pinned Git blobs, hashes, commits and retained MIT notices.
- A separate, test-authored slow bit decoder evaluates 22 literal small models:
  **527,872 complete payload evaluations**, **85 model comparisons** and all
  **63 generated witnesses**. Each raw equality decision is checked against
  every payload in its finite model, separately from metadata equality.
- Another **2,048 signed-one-bit cells** cover every bit position in a byte.
  Cross-byte signed fields, widths 1–32, numbered and unnumbered reports and all
  three report directions have explicit checks.
- External hid-tools 0.12 replays generated witnesses, including the real mouse
  X/Y swap. Existing sweeps cover all 65,536 X/Y pairs, 32 button states, 256
  wheel values and 65,536 payloads of a cross-byte signed12 field. These are
  bounded field sweeps, not every possible real-device report.
- 10,000 seeded arbitrary-byte descriptors complete with bounded diagnostics.
  Structural errors, unsupported state, caps, empty/constant-only reports,
  source provenance and Report-ID/Push exclusions are tested.
- CLI tests cover status precedence, selected keyboard Output, blocked whole
  keyboard/consumer descriptors, exact framing, deterministic JSON across hash
  seeds, unchanged inputs, malformed artifacts and source/witness tampering.
- The regular-file boundary has symlink/nonregular-file checks, inode replacement
  and growth-race checks, and missing-O_PATH/procfs refusal simulations. These
  simulations do not constitute testing on other operating systems.

## Mutation checks

The mutation scripts use fixture-complete temporary source copies. A complete
unmodified core baseline must pass first. A mutant counts only when its named
regression test reports assertion failures, with no errors or skips. Missing
fixtures/imports and broken baselines cannot count as detection.

- Six parser mutations: ID prefix sizing, signedness, Main-time Usage Page
  binding, local resets, Null State acceptance and bit offsets.
- Eight comparison/decoder mutations: coefficient offsets/sign, decoder sign,
  byte order, ID-as-payload, wrong-ID acceptance, whole-report range validity
  and tampered range labels.

All **14/14** targeted mutations were detected. This shows that those selected
regressions are observable; it is not proof that every defect is detectable.

## Independent adversarial review

A fresh reviewer inspected the accepted grammar, parser state, exact coefficient
comparison, separate decoder, source-bound witness checks and scoped CLI. Eighteen
independent whole-tool tests cover all five high-risk conditions: ID framing,
late/Pop-restored Usage Page, accumulated padding/collection offsets, global
unknown-state poisoning and unrelated positive-minimum fields.

Two late resource findings were reproduced and repaired with failing-then-passing
regressions:

1. A valid deep, many-field comparison could emit more than the original 16 MiB
   witness-artifact limit. The reader now has a bounded **32 MiB** limit. A
   maximum-8192-bit/depth32/1023-field test round-trips its own output; a separate
   1024-field/four-report adversarial construction emitted 24,447,127 bytes.
2. Non-consuming item diagnostics duplicated all pending Usage sources. A
   4096-byte malformed input had retained 1,864,590 source-span references.
   Those diagnostics now retain their current item and effective globals,
   without unrelated pending locals. Consuming Main-item provenance remains
   complete. Synthetic EOF diagnostics likewise do not duplicate pending Usage
   state. No diagnostic severity or selected-scope status is discarded.

## Reference exceptions remain visible

hid-tools 0.12 is a development-only comparison point. Its known signed-one-bit
extraction and negative-maximum metadata/range errors are explicitly asserted,
never normalized away or silently skipped. Independent, reviewed expectations
cover those cells. Report-ID changes while pushed remain outside the product
subset. See [exact counterexamples and primary references](oracle-notes.md).

The product has no third-party runtime dependencies. No GPL parser source or
wheel, device capture or USB-IF specification PDF is bundled. The fixture
sources are redistributed with their MIT notices. The tool performs no hardware,
credential, firmware or input-driven network operations.

## Reproduce

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_mutations.py
python scripts/verify_comparison_mutations.py
```

Install the exact hash-pinned test dependencies as described in the README,
then run `PYTHONPATH=src python -m unittest discover -v`. Missing or wrong oracle
versions fail rather than skip. The source manifest records SHA-256 for each
shipped source file except the manifest itself. The release manifest binds the
wheel, source distribution and source ZIP of the separately reviewed candidate.
This GitHub publication contains source files only. Documentation updates after
publication refresh `SOURCE_MANIFEST.json`; they do not rewrite the original
candidate archives or their release manifest. Generated package metadata in a
source distribution is additional to the source manifest.

## Continuous integration configuration

The included `.github/workflows/tests.yml` targets Linux x86_64 on
`ubuntu-24.04` with Python 3.11, 3.12, 3.13, 3.14 and 3.15. The first
[hosted run](https://github.com/loaff123/HidWire/actions/runs/39195924690) completed
successfully on 19 October 2026 for source commit
[`f53be3e42249c28dbcb235ed6b6a71b6f9a63b27`](https://github.com/loaff123/HidWire/commit/f53be3e42249c28dbcb235ed6b6a71b6f9a63b27).
All five jobs passed 183 source tests and 183 installed-wheel tests each, with no
test failures or skips. The Python 3.12 job additionally passed both clean-core
baselines and detected all six parser and eight comparison/decoder mutations.
The mutation step is intentionally not run in the other four matrix jobs.

The original local candidate evidence remains Linux/Python 3.12.14; the hosted
run adds the five tested Python versions on the stated Linux runner. Neither
result establishes general hardware, firmware, host or USB/HID compatibility.
Future hosted failures must be investigated rather than treated as
supported-version passes. No Windows or macOS support is claimed.

Each matrix job runs the source suite, builds a wheel and sdist, installs the
wheel without runtime dependencies, and copies only tests/fixtures/examples
outside the checkout. It asserts there is no `src` tree there, unsets PYTHONPATH,
checks that isolated-mode imports resolve to the installed package outside the
checkout, runs isolated CLI smoke checks, and runs the complete suite again.
The 3.12 job additionally runs both clean-baseline mutation checks.

Permissions are `contents: read`; checkout does not persist credentials. Only
push, pull-request and manual triggers are configured. There are no write,
publication, upload, privileged pull-request or secret-handling steps. Build
tools come from official PyPI; oracle versions and hashes remain pinned.
The official actions are pinned to release commits:
[checkout v7.0.1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1)
and [setup-python v7.0.0](https://github.com/actions/setup-python/commit/5fda3b95a4ea91299a34e894583c3862153e4b97).
The Python matrix follows the currently maintained versions listed by the
[Python Developer's Guide](https://devguide.python.org/versions/).
