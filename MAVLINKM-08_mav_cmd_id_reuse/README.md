# MAVLINKM-08 — MAV_CMD id 53090 reused with inverted meaning; COMMAND_LONG does not fail closed

| | |
|---|---|
| **Product** | MAVLink-M dialect (`military.xml`) |
| **Severity** | 🟡 MEDIUM (cross-version safety) |
| **CWE** | 440 (expected behavior violation) / 696 (incorrect behavior order) / 358 |
| **Affected** | `MAV_CMD_MAVLINK_M_STORE_SAFE` (53090), formerly `STORE_ARM` |
| **Reviewed at** | `mavlink-military` @ `6375c34`; reuse introduced `afcdabb` (2026-10-27) |
| **Interaction** | push: one COMMAND_LONG/INT across a version boundary |
| **Verified** | git history + MAVLink framing semantics |
| **Status** | design/spec-process; no STORE_ARM receiver exists in the demo, so impact is cross-version |

## Summary

MAV_CMD id 53090 was `MAVLINK_M_STORE_ARM` and is now
`MAVLINK_M_MAVLINK_M_STORE_SAFE`, a disarm-only command. MAV_CMD entries travel
inside `COMMAND_LONG` / `COMMAND_INT`, whose `CRC_EXTRA` is computed for the
carrier message and does not change when a command id's parameter meaning changes.
Unlike a dialect message, whose changed `CRC_EXTRA` makes a mismatched peer drop
the frame (fail closed), a reused command id is parsed happily by a peer built
from either revision, each applying its own meaning. A new `STORE_SAFE` (param 2 =
the DISARM codeword 51.0) reaches an old receiver as `STORE_ARM` with param 2 =
51.0, a nonzero value its "0 = disarm, 1 = arm" parameter reads as arm.

## Root cause

### The id was reused, breaking the parameter meaning

Git history of `military.xml`:

```
afcdabb feat(MAV_CMD_MAVLINK_M_STORE_SAFE)!: take 53090 and drop STORE_ARM
```

Current `military.xml`, `MAV_CMD_MAVLINK_M_STORE_SAFE` (53090):

```
p1 Store ID   Target store instance ...
p2 Request    MAVLINK_M_ESAD_REQUEST_DISARM, sent as that value in a float and compared as a float ...
```

The prior `STORE_ARM` at 53090 used param 2 as "0 = safe/disarm, 1 = arm." The `!`
in the commit subject marks the change as breaking, which is the dialect's
changelog mechanism, but that signal is only visible to someone reading the
changelog, not enforced on the wire.

### COMMAND_LONG does not fail closed on a command-id meaning change

`CRC_EXTRA` (`https://mavlink.io/en/guide/serialization.html#crc_extra`) covers
the carrier message's name, field types, and field names, not the semantics of a
`MAV_CMD` value it carries. `COMMAND_LONG` and `COMMAND_INT` keep one `CRC_EXTRA`
across every command. So where two peers built from different dialect revisions
drop each other's *messages* whose layout changed (the dialect relies on this; see
`status_field_encoding.md` "Dialect Revisions"), they silently exchange a reused
command and apply divergent meaning to its parameters.

### The dangerous direction is disarm → arm

An operator on the new revision sends `STORE_SAFE` to disarm, param 2 = 51.0. An
ESAD built from the pre-`afcdabb` revision reads it as `STORE_ARM`, param 2 =
51.0 ≠ 0. With the reference truthiness pattern (see
[MAVLINKM-04](../MAVLINKM-04_reference_esad_handler_unsafe/)) that nonzero value
is an arm. A safing command becomes an arming command across the version boundary.

## Taint trace

```
new-revision GCS: STORE_SAFE (53090), param2 = 51.0 (DISARM codeword), intent = disarm
  → COMMAND_LONG, CRC_EXTRA unchanged, accepted by an old-revision receiver
  → old receiver reads cmd 53090 = STORE_ARM, param2 = 51.0
      STORE_ARM param2: 0 = disarm, nonzero = arm
      → ARM   (a disarm command executed as an arm)
```

## Impact

Across a mixed-revision deployment, a disarm command issued through 53090 can be
executed as an arm by a receiver built before the reuse, with no framing error to
flag it. The carrier-message fail-closed property the dialect relies on for its
other breaking changes does not hold for a reused command id.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| 53090 was STORE_ARM, now STORE_SAFE | ✅ | commit `afcdabb` |
| COMMAND_LONG CRC_EXTRA unchanged by the reuse | ✅ | CRC_EXTRA covers the carrier, not MAV_CMD semantics |
| New disarm reads as old arm | ✅ | param 2 = 51.0 is nonzero in the old "0/1" field |
| Executed as arm by an old receiver | ⚠️ | depends on the old receiver's handling; the reference truthiness pattern does it |
| A STORE_ARM receiver exists in the reviewed code | ❌ | none in the demo; impact is cross-version by construction |

Not claimed: a live old-vs-new exchange was run. The finding is structural: a
reused MAV_CMD id defeats the version fail-closed the dialect depends on.

## Version scope

Reuse introduced at `afcdabb` (2026-10-27); present at `6375c34`. Any receiver
built from a revision at or before `afcdabb`'s parent interprets 53090 as
STORE_ARM.

## Reproduction

```sh
cd <mavlink-military clone>
git log --oneline -S'STORE_ARM' -- military.xml   # shows afcdabb dropping STORE_ARM at 53090
```

The parameter divergence is read directly from the `MAV_CMD_MAVLINK_M_STORE_SAFE`
param 2 description versus the pre-`afcdabb` `STORE_ARM` param 2.

## Fix

Do not reuse a MAV_CMD id with new semantics: keep 53090 reserved and refused, and
assign `STORE_SAFE` a fresh id (the `53094-53099` MAV_CMD growth range is
reserved). More broadly, note in the dialect-revision guidance that `MAV_CMD`
parameter changes do not fail closed on `CRC_EXTRA`, so a command id, once
assigned, is never repurposed.
