# Exact decision, bounded claim

## Scalar extraction theorem

For a fixed report kind/ID and payload of n bits, write each input bit as
b[i] in {0, 1}. A width-w unsigned scalar at offset o decodes to

    f(b) = sum(2**j * b[o+j], j=0..w-1).

A two's-complement signed scalar changes only the final coefficient to
`-2**(w-1)`. All positions outside the field have coefficient zero. Thus each
supported scalar is an integer linear function of independent payload bits.

For two such functions f and g:

1. If every coefficient matches, their sums match for every raw payload.
2. If a coefficient differs at bit k, set b[k]=1 and every other bit to 0.
   The outputs are the unequal coefficients at k, so this payload separates them.

This is a necessary-and-sufficient equality test for raw scalar extraction.
It is not randomized testing and needs no solver. The coefficient comparison is
mathematically equivalent to comparing correctly resolved offsets, widths and
signedness; no novel verification algorithm is claimed.

## Framing, identity and metadata

The theorem applies to matched scalar identities in a common payload space.
HidWire separately compares report kind/ID, exact declared payload and wire
lengths, collection/usage identities, and normalized metadata. If framing differs,
it reports the shape change without pretending that a single exact-length wire
report is accepted by both sides. Constant-only reports remain part of shape.

The report ID, when present, is a fixed prefix and is not a payload variable.
The deterministic witness selects the lowest differing payload bit, then adds
the fixed ID prefix. One witness is emitted per changed matched scalar function.
Different scalar witnesses can contain identical bytes.

A separate decoder uses little-endian integer loading, shifts, masks and signed
subtraction. It imports neither the comparator nor its coefficient helper. Each
witness is checked against source hashes, exact wire length, ID, field identity,
both recorded values, actual inequality and whole-report logical-range labels.
This decoder shares the parsed model; independent descriptor/oracle tests and
review are still needed to establish the parser boundary.

## What the proof does not claim

- Metadata equality is part of the contract but not implied by equal integers.
  A Relative/Absolute, logical-range or unit change may yield no integer witness.
- One-hot reports may be out of range. Every scalar's logical range is checked,
  including unchanged fields whose declared minimum is positive. No search for
  a jointly range-valid witness is performed.
- Logical-range validity does not mean physical device validity. Constant bits,
  usage-specific constraints, firmware behavior and host interpretation are not
  inferred.
- An unsupported or malformed descriptor never obtains equality merely because
  its bytes match another file. Unknown global state blocks every scope;
  report-local known exclusions can permit explicit supported-report selection.
- Comparison of an explicit report selection does not verify unselected reports
  or empty collection structure unrelated to selected scalar paths.
- The mathematical argument assumes the documented parsed scalar model. It is
  not a formal proof of the complete Python implementation, USB conformance or
  compatibility with every HID implementation.
