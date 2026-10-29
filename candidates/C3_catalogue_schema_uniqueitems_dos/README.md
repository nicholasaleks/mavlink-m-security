# C3 — Schema-valid catalogue drives the validator into O(n²) work

| | |
|---|---|
| **Area** | payload catalogue / schema validation |
| **Severity** | 🟡 MEDIUM (DoS) |
| **CWE** | 1333 / 407 (inefficient algorithmic complexity) / 400 |
| **Affected** | `component_metadata/payloads.schema.json` (`uniqueItems` sites); the prose limits in `payload_metadata.md:106-131` |
| **Reviewed at** | `mavlink-military` @ `6375c34` |
| **State** | measured with `jsonschema` 4.26.0 (agent) |

## Summary

The catalogue JSON schema encodes almost no size bounds; all limits live in prose.
The schema has 21 `uniqueItems` sites, and a common validator (python-`jsonschema`)
falls back to an O(n²) comparison when the items are mixed types or objects. A
catalogue or profile that respects every prose limit can therefore cost minutes of
CPU per validation pass, and the pass repeats on every catalogue revision. This is
the PYULOG-01 / MAVSDK-03 amplification class inside the metadata validator.

## Root cause

- The schema itself leaves ~70 strings, ~15 arrays, and 9 map objects unbounded
  (all caps are prose, `payload_metadata.md:109-131`), so a schema-only validator
  gets no protection.
- 21 `uniqueItems` checks; `jsonschema`'s `uniq` degrades to an O(n²) `equal()`
  loop when `sorted()` raises (mixed types or dicts).

## What was measured (agent, within every prose limit)

- A profile `allowedValues` with 16,300 mixed int/str values (111,614 B, 16,326
  values) validated in **17.1 s** (0.26 s @ 2k, 1.04 s @ 4k, 4.17 s @ 8k — clearly
  quadratic). A pass may fetch 64 profiles inside the 8 MiB budget ≈ **18 min CPU**.
- A catalogue inhibition `prevents` array with 21,000 distinct object members
  (857,747 B, 63,255 values; `prevents` has no per-entry cap) validated in
  **175.3 s** for the schema pass alone.
- Both re-trigger on every revision: a status naming a new file resets the retry
  count (`payload_metadata.md:153`) and there is no client cap on revisions
  processed.

## Impact

A malicious payload (or, via [MAVLINKM-03](../../MAVLINKM-03_payload_catalogue_crc_forgery/),
a network attacker) publishes a conforming catalogue that stalls the client's
metadata validation for minutes per revision, repeatable, starving the GCS of CPU
during catalogue processing.

Not claimed: a specific GCS uses python-`jsonschema`; the O(n²) `uniqueItems`
behavior is validator-dependent, though common. The schema-level absence of bounds
is universal.

## Reproduction

```sh
cd poc
python3 -I -m venv venv && ./venv/bin/pip -q install jsonschema
./venv/bin/python -I uniq_dos.py      # allowedValues quadratic growth
./venv/bin/python -I prevents_dos.py  # prevents[] quadratic growth
```

## Fix

Put `maxItems` / `maxLength` / `maxProperties` into the schema itself; cap
`allowedValues`, `enum`, and `prevents` entry counts; require uniqueness checks via
hashing rather than pairwise comparison; and cap revisions processed per period.
