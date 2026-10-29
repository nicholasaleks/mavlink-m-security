# MAVLINKM-04 — Reference ESAD handler arms on any nonzero value; regeneration inverts safety

| | |
|---|---|
| **Product** | `nucleo-mavlink-m-demo` (MAVLink-M "worked example on real hardware") |
| **Severity** | 🟠 HIGH (reference implementation; safety-critical enum mishandling) |
| **CWE** | 1284 (improper validation of quantity) / 20 / 697 (incorrect comparison) / 440 |
| **Affected** | `nucleo_mavlink_m/nucleo_mavlink_m.ino:135-138`; the handler as a pattern |
| **Reviewed at** | demo @ `4860564`; spec `mavlink-military` @ `6375c34` |
| **Interaction** | zero-click: one ESAD_ARMING frame |
| **Delivery class** | push |
| **Verified** | by running the handler (Docker `gcc:14`, ASan+UBSan) on 2026-10-28 |
| **Status** | reference/example code; the pattern is what integrators copy |

## Summary

The demo is the project's on-hardware reference: a PX4 flight controller relaying
MAVLink-M to an STM32 Nucleo ESAD peripheral. Its ESAD_ARMING handler maps the
`arming_request` field to the armed state with a C truthiness test rather than an
exact enum comparison. Against the headers it currently vendors (an old encoding
where DISARM=0, ARM=1), that happens to arm on *any* value 1-255 and on every
1-3-bit corruption of DISARM. When the headers are regenerated from the current
`military.xml`, as the demo's own SETUP.md tells integrators to do, the Hamming
codewords make DISARM=51 (nonzero), so the truthiness test **inverts**: DISARM
arms, and the only value that disarms is NONE=0, which the spec requires a receiver
to refuse. The reference for integrators teaches the exact anti-pattern the spec's
enum-encoding guide warns against.

The same review found the demo implements no MAVLink 2 signing anywhere (firmware,
host, or docs), so every ESAD command is accepted unsigned from any sysid; that is
written up as [MAVLINKM-05](../MAVLINKM-05_signing_coverage_gap/) alongside the
spec-level signing-coverage gap.

## Root cause

### Truthiness in place of an exact enum match

`nucleo_mavlink_m/nucleo_mavlink_m.ino:135-138`:

```c
// arming_request: 0 = disarm (MAVLINK_M_ESAD_REQUEST_DISARM),
// 1 = arm (MAVLINK_M_ESAD_REQUEST_ARM). Map straight to the state enum.
g_arming_status = in.arming_request ? MAVLINK_M_ESAD_ARMING_ARMED
                                    : MAVLINK_M_ESAD_ARMING_DISARMED;
```

The code never names `MAVLINK_M_ESAD_REQUEST_ARM` or `_DISARM`; it treats the
field as a boolean. This is exactly what
`docs/en/guide/status_field_encoding.md` forbids for in-scope enums: a receiver
"must match the received byte exactly against the enum's listed values," "must
refuse an unrecognised commanded value," and must never use a range or truthiness
test.

### The vendored headers hide it; regeneration exposes it

The vendored firmware headers predate the Hamming-codeword change (spec commit
`1b8851c`, Sep 21). In them DISARM=0 and ARM=1, so truthiness matches 0/1 and the
bug reads as "arms on out-of-range values only." The current spec encodes the same
enum as codewords (DISARM=51, ARM a different nonzero codeword, NONE=0). SETUP.md
(lines ~103-114) tells integrators to regenerate headers "if military.xml
changes." After regeneration the identical source compiles with no warning (it
never references the enum) and now arms on DISARM and disarms only on NONE, which
must be refused.

### CRC_EXTRA caveat (honest limit)

ESAD_ARMING's `CRC_EXTRA` changed between the vendored and current definitions
(153 vs 3), so a current-spec ESAD_ARMING sent over the wire to the *as-flashed
vendored binary* is dropped on CRC_EXTRA mismatch. The inversion is reached through
the documented regeneration step, not by injecting a new-spec frame at today's
binary. The arms-on-nonzero behavior itself is live against the vendored binary.

## Taint trace

```
ESAD_ARMING.arming_request  (uint8, attacker-chosen 0-255)
  → ino:137  g_arming_status = arming_request ? ARMED : DISARMED
      vendored headers (DISARM=0, ARM=1):
        values 1-255  → ARMED        (254 non-ARM values arm)
        1-3-bit flips of DISARM(0)   → ARMED
      regenerated headers (DISARM=51, ARM=codeword, NONE=0):
        DISARM(51)    → ARMED        (safety inverted)
        only NONE(0)  → DISARMED     (and NONE must be refused)
  → digitalWrite(LED, ARMED)         (physical arm indication)
  → ESAD_STATE echoes arming_status
```

## Impact

A single ESAD_ARMING with a non-ARM `arming_request`, or a few bit flips of a
DISARM, leaves the reference ESAD armed. Integrators who follow the worked example
inherit a handler that arms on corruption and, after the regeneration the docs
prescribe, treats the disarm codeword as arm. The spec's whole enum-encoding
defense, detect-don't-correct on safety enums, is defeated by the reference code
that is supposed to demonstrate it.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Arms on values 2-255 (vendored headers) | ✅ | 255/256 values arm; reproduced |
| Every 1-3-bit flip of DISARM arms | ✅ | 92/92 reproduced |
| Regeneration inverts DISARM→arm | ✅ | reproduced against current-spec headers |
| Reached over the wire at today's vendored binary with a new-spec frame | ❌ | CRC_EXTRA mismatch drops it; reached via regeneration |
| Receive-path memory safety | ➖ clean | fuzzing (6×1.5M iters, ASan+UBSan) found no OOB on either header set |

Not claimed: a memory-safety break. The handler reads two uint8 fields and is
memory-safe; the defect is semantic.

## Version scope

Present in the demo at `4860564` with the vendored (July 17) headers, and worse
after regeneration against `military.xml` @ `6375c34`. The branch
`origin/mrpollo/px4-custom-build-guide` is already merged (no additional diff).

## Reproduction

Harness and outputs are in [poc/](poc/). The handler is driven in-process with an
Arduino shim; the `regen/` build uses headers mavgen produces from the current
`military.xml` (the SETUP.md step).

```sh
# macOS Apple clang ASan hangs at startup; build/run the sanitized harness in Linux/Docker:
#   docker run --rm -v "$PWD":/w -w /w gcc:14 bash -c '<build cmd in poc/NOTES.md>'
# then:
./lx_regen all      # exact-match sweep, bit-flip sweep, named DISARM test
./lx_vendored all
```

Expected (regenerated headers):

```
[named] start=ARMED send MAVLINK_M_ESAD_REQUEST_DISARM (51) -> g_arming_status=51 (ARMED)
[sweep] arming_request values that ARM a disarmed ESAD: 255/256
[sweep] arming_request values that DISARM an armed ESAD: 0 (1/256)
[bitflip] DISARM codeword 51 with 1-3 bits changed: 92/92 leave/turn the ESAD ARMED
```

`poc/out_vendored.txt` and `poc/out_regen.txt` are the captured runs;
`poc/NOTES.md` has the full harness method and the exact Docker command.

## Fix

Replace the truthiness map with an exact-match switch:

```c
switch (in.arming_request) {
case MAVLINK_M_ESAD_REQUEST_ARM:    g_arming_status = MAVLINK_M_ESAD_ARMING_ARMED;    break;
case MAVLINK_M_ESAD_REQUEST_DISARM: g_arming_status = MAVLINK_M_ESAD_ARMING_DISARMED; break;
default: /* incl. NONE and any unlisted value */
    send_ack(MAVLINK_M_ACK_FAILED /*, reason: arming_request */);
    return;  /* no state change */
}
```

and send `MAVLINK_M_ACK` on every request, as the spec's commanded-value rules
require. Pin the headers/generator to a spec revision so the demo and docs stay
consistent (also [MAVLINKM-05](../MAVLINKM-05_signing_coverage_gap/) for the
host-tool 0/1 breakage).
