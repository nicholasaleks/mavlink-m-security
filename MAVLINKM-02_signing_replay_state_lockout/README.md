# MAVLINKM-02 — Signing replay-state poisoning suppresses stops

| | |
|---|---|
| **Product** | MAVLink-M signing stack: pinned pymavlink generator + generated C library |
| **Severity** | 🟠 HIGH (safety availability) |
| **CWE** | 294 (authentication bypass by capture-replay primitive) / 400 / 1286 |
| **Affected** | pymavlink @ pin `19880422` (`generator/mavgen_python.py` `check_signature`); `mavlink-military-c_library_v2` `mavlink_helpers.h` `mavlink_signature_check` |
| **Reviewed at** | pymavlink pin `19880422`, C library @ `a957b86` |
| **Interaction** | zero-click: one frame per victim stream |
| **Delivery class** | push |
| **Verified** | both reproduced in-process on 2026-10-28, bench key, no network |
| **Status** | pymavlink half fixed upstream (ArduPilot/pymavlink #1300, `bd0a1b29`, 15 commits ahead of the pin); C-library / key-holder half unfixed |

## Summary

MAVLink-M's SAFETY BOUNDARIES (`military.xml:364-374`) rests two guarantees on
MAVLink 2 signing: "A frame that fails the signature check changes no replay
state, so a forgery cannot lock a sender out," and "A receiver ... never rejects
a stop for its time." Both the pinned pymavlink generator and the generated C
library violate these. A single frame advances a victim stream's replay timestamp
to its maximum, after which every later genuine signed frame from that stream,
ENGAGEMENT_DIRECTIVE ABORT and ESAD_ARMING DISARM included, is dropped as a
replay. The dialect's own stop messages are the payload that gets suppressed.

Two reachers:

- **pymavlink** poisons the replay state *before* the signature is verified, so a
  **keyless** attacker (no network key) triggers it with any malformed frame.
- **the C library** has no upper bound on the timestamp, so a **key holder** — in
  the shared-key model, any aircraft or munition that can be lost — triggers it
  with one validly-signed frame claiming the authority's stream.

## Root cause

### pymavlink commits replay state before authentication

`generator/mavgen_python.py` at the pin, `check_signature`:

```
1033  stream_key = (link_id, srcSystem, srcComponent)
1034  if stream_key in self.signing.stream_timestamps:
1035      if timestamp <= self.signing.stream_timestamps[stream_key]:
1036          return False          # reject old timestamp
1037-1045  ... (new-stream acceptance window)
1048  self.signing.stream_timestamps[stream_key] = timestamp   # <-- committed here
1050-1057  h = sha256(...); if sig1 != sig2: return False       # <-- verified AFTER
```

The per-stream timestamp is written at line 1048, then the signature is checked at
1055. A frame with a bad signature and `timestamp = 2^48-1` is rejected, but only
after it has set the stream's stored timestamp to the maximum. Every genuine frame
afterward has a smaller timestamp and is dropped at line 1035.

### The C library has no timestamp upper bound

`mavlink_helpers.h` `mavlink_signature_check` verifies the signature first (good),
but on a validly-signed frame it accepts any timestamp and stores it:

```
// remember last timestamp
memcpy(signing_streams->stream[i].timestamp_bytes, psig+1, 6);
if (tstamp.t64 > signing->timestamp) {
    signing->timestamp = tstamp.t64;     // global clock dragged forward too
}
```

There is no "reject a timestamp absurdly far in the future" check. Under the
shared key, a key holder signs one frame as the authority's `(sysid, compid,
link_id)` with timestamp `2^48-1`. That stream's stored timestamp is maxed, so the
authority's later frames drop as `REPLAY`; and because the global `signing->timestamp`
is dragged to the maximum, a backup station the receiver has not heard yet is
rejected as `OLD_TIMESTAMP` (its genuine current timestamp is now "more than a
minute behind").

This is the shared-key property the spec acknowledges (`military.xml:351-363`,
"any holder can sign as any system ID ... an aircraft or munition that can be lost
included") turned into a stop-suppression primitive.

## Taint trace

```
pymavlink (keyless):
  attacker frame, bad signature, timestamp=2^48-1
    → check_signature commits stream_timestamps[stream]=2^48-1  (line 1048)
    → then signature fails (line 1055), frame dropped
  genuine signed frame from that stream, timestamp < 2^48-1
    → rejected at line 1035 "old timestamp"  → STOP never delivered

C library (key holder):
  one valid-signature frame as authority's stream, timestamp=2^48-1
    → stream[i].timestamp_bytes = 2^48-1 ; signing->timestamp = 2^48-1
  authority ENGAGEMENT_DIRECTIVE ABORT, real timestamp
    → tstamp <= last_tstamp  → MAVLINK_SIGNING_STATUS_REPLAY → dropped
  backup station ABORT, new stream
    → tstamp + 60s < signing->timestamp → OLD_TIMESTAMP → dropped
```

## Impact

An attacker can make a specified sender's signed traffic undeliverable to a given
receiver for the life of that receiver's replay state. Because the suppressed
traffic includes the dialect's stops, the concrete effect is that an ABORT,
CHECK_FIRE, or DISARM from the human authority stops being accepted, defeating the
"a receiver never rejects a stop for its time" guarantee. The keyless pymavlink
variant needs no key; the C variant needs only a shared key the threat model
already treats as reachable.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Keyless lockout (pymavlink) | ✅ | reproduced; one bad-signature frame suffices |
| Key-holder lockout of the authority (C lib) | ✅ | reproduced; one valid frame, timestamp 2^48-1 |
| Suppresses the authority's later stops | ✅ | reproduced: ABORT drops as REPLAY |
| Suppresses an unheard backup station | ✅ | reproduced: ABORT drops as OLD_TIMESTAMP |
| pymavlink half already fixed upstream | ✅ | #1300 / `bd0a1b29`, 15 commits ahead of the pin |
| C-library / key-holder half fixed | ❌ | no upper timestamp bound upstream |
| Defeats signing's authenticity (forge a command) | ❌ | this is availability only; signatures still authenticate |

Not claimed: a confidentiality or command-forgery break. This is a denial-of-stop.

## Version scope

- pymavlink: present at the MAVLink-M pin `19880422`; fixed on master at
  `bd0a1b29` (2026-10-16). MAVLink-M's pin predates the fix.
- C library: present at `a957b86` and in upstream mavlink `mavlink_helpers.h`; no
  upper-bound check exists.

## Reproduction

Both PoCs are in [poc/](poc/). They are in-process, use a bench key, and open no
sockets.

```sh
# keyless lockout, needs a pymavlink install (any recent 2.4.x reproduces it)
python3 -I poc/pymavlink_keyless_lockout.py

# key-holder lockout, builds against the generated MAVLink-M C headers
cc -std=c11 -O1 -I <path-to>/mavlink-military-c_library_v2 \
   poc/c_keyholder_lockout.c -o /tmp/c_keyholder_lockout
/tmp/c_keyholder_lockout
```

Gotcha: build the C PoC **without** `-fsanitize=address` on macOS — ASan binaries
hang at startup there, which looks like the PoC wedging. Use a plain `-O1` build
(or run ASan in Linux/Docker).

Expected output: genuine frames ACCEPTED, then after the one poisoning frame the
authority's later stops DROPPED (`REPLAY`) and the backup's DROPPED
(`OLD_TIMESTAMP`).

The fix for the pymavlink half is to bump the generator pin past #1300
(`mavlink-pins.env` `PYMAVLINK_REF`). The C half needs an upper bound on an
accepted timestamp (reject one more than a bounded offset past the receiver's own
clock), which is a separate upstream change to `mavlink_helpers.h`.
