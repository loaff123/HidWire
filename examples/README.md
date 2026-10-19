# Reproducible counterexample

`mouse-swapped.hex` is a deliberate mutation of the 64-byte CircuitPython mouse
fixture. It replaces the adjacent X/Y Usage declarations at descriptor offsets
36–39 (`09 30 09 31`) with `09 31 09 30`; every other decoded byte is unchanged.
This is a synthetic review example, not a historical firmware migration.

Copyright (c) 2018 hathach for Adafruit Industries. SPDX-License-Identifier: MIT.
The complete original MIT license is retained at
`../fixtures/licenses/LICENSE-CircuitPython`. Source URL, commit, original Git
blob and descriptor hashes are in `../fixtures/manifest.json`.

The deterministic separating wire report is `02 00 01 00 00`. Originally it
extracts X=1/Y=0; the mutated descriptor extracts X=0/Y=1. Both sides' complete
scalar report falls within its declared logical ranges. This does not establish
that hardware emits those bytes or that a host accepts the descriptor.
