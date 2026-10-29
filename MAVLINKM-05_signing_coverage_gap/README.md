# MAVLINKM-05 — Signing mandate leaves the fetch path and bound commands unsigned

| | |
|---|---|
| **Product** | MAVLink-M spec (`military.xml` SAFETY BOUNDARIES) + `nucleo-mavlink-m-demo` reference |
| **Severity** | 🟠 HIGH (authentication gap underpinning MAVLINKM-01/-03) |
| **CWE** | 306 (missing authentication) / 862 / 345 |
| **Affected** | `military.xml:333-337`; demo firmware/host/docs; PX4 integration guidance |
| **Reviewed at** | `mavlink-military` @ `6375c34`; demo @ `4860564`; PX4 main @ `1776a8a` |
| **Interaction** | zero-click |
| **Delivery class** | push / request-response |
| **Verified** | demo-side "accepted unsigned / unknown-key" reproduced by running the handler, 2026-10-28 |
| **Status** | spec design gap + reference-implementation non-conformance |

## Summary

MAVLink-M's security rests entirely on MAVLink 2 signing, but the mandate is scoped
to dialect messages only. The common.xml messages the dialect actually depends on
for catalogue retrieval, time, and bound actions are left outside it, and the
on-hardware reference implements no signing at all. The scoping gap is what lifts
the catalogue forgery ([MAVLINKM-03](../MAVLINKM-03_payload_catalogue_crc_forgery/))
and the target-package SSRF ([MAVLINKM-01](../MAVLINKM-01_target_package_ssrf/))
from "the vehicle is the attacker" to "any on-link attacker," and it lets a late
unsigned ARM/ACTIVATE land after a signed stop.

## Root cause

### The mandate names only dialect frames

`military.xml:333-337` (SAFETY BOUNDARIES):

```
A receiver uses a message of this dialect, a MAV_CMD_MAVLINK_M_STORE_* command
or the COMMAND_ACK answering one only from a frame signed with a key it accepts,
and drops any other without answering.
```

Not covered, though the payload service and TARGET retrieval depend on them:

- `COMPONENT_METADATA`, `FILE_TRANSFER_PROTOCOL` — the catalogue/profile transport
- `MAV_CMD_REQUEST_MESSAGE` and its `COMMAND_ACK` — how the catalogue is solicited
- `EVENT` — payload events
- `TIMESYNC` / `SYSTEM_TIME` — set the time basis the whole "stops win / clock
  offset" model (`military.xml:380-388`) depends on
- the bound actions `MAV_CMD_DO_PARACHUTE`, `DO_GRIPPER`, `DO_WINCH` — a parachute
  RELEASE also stops the motors (`payload_metadata.md:226-233`)

An on-link attacker without the key can inject these, so the catalogue bytes, the
time basis, and a bound release are all reachable unsigned.

### The reference implements no signing at all

The demo, the piece integrators copy, never sets `status->signing` in firmware,
never calls `setup_signing` in the host tools, and documents no signing step
(SETUP.md, PX4_INTEGRATION.md, PX4_CUSTOM_BUILD.md). Verified by running the
handler:

```
[authz] signed with unknown key                 -> ARMED (accepted)
[authz] signed, signature bytes trashed         -> ARMED (accepted)
[authz] unsigned, arbitrary sysid 77 / comp 1   -> ARMED (accepted)
```

Because `mavlink_signature_check` returns true when `signing == NULL`
(`mavlink_helpers.h:131`) and the bad-signature drop branch is guarded by
`if (status->signing && ...)`, the `MAVLINK_FRAMING_BAD_SIGNATURE` path is dead:
every dialect message is accepted unsigned from any identity on both links.

### PX4 and provisioning gaps (code-read)

On PX4 main, routes are learned from unverified frames: with signing off every OK
frame adds a route, and with signing on, unsigned HEARTBEAT / RADIO_STATUS /
ADSB_VEHICLE / COLLISION still return FRAMING_OK via `accept_unsigned`
(`mavlink_sign_control.cpp:48-53, 223-236`), contradicting `military.xml:342-347`.
While signing is uninitialized, `SETUP_SIGNING` is accepted on any instance when
not armed (`mavlink_main.cpp:1200-1258`), so in the demo topology a compromised
TELEM2 peripheral can install its own key first and lock out the GCS.

## Impact

The catalogue, profiles, time basis, and bound release/parachute commands can be
injected or altered by an attacker who holds no signing key, defeating the
guarantees MAVLINKM-01 and MAVLINKM-03 would otherwise bound to the vehicle. The
reference implementation accepts every dialect command unsigned, so an integrator
who follows it has no authentication at all, and the provisioning race lets the
first mover own the key.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Fetch-path messages outside the mandate | ✅ | `military.xml:333-337` names only dialect/STORE frames |
| Bound DO_* commands unsigned | ✅ | not dialect messages |
| Demo accepts unsigned/unknown-key commands | ✅ | reproduced by running the handler |
| PX4 learns routes from unverified frames | ✅ | code-read of `mavlink_receiver.cpp` / `mavlink_sign_control.cpp` |
| SETUP_SIGNING first-mover takeover | ⚠️ | code-read; not run against a live PX4 |

Not claimed: a break of signing where it *is* applied. The gap is coverage, not
the primitive.

## Version scope

Spec: `military.xml` @ `6375c34` (the signing mandate was added `2ae0e5b`, Oct 9).
Demo: `4860564`, with no signing in any revision. PX4: main @ `1776a8a`.

## Reproduction

The demo-side behavior is reproduced by the
[MAVLINKM-04](../MAVLINKM-04_reference_esad_handler_unsafe/poc/) harness (`authz`
cases). The spec and PX4 parts are confirmed by reading the cited lines; no live
PX4 was driven.

## Fix

- Spec: broaden SAFETY BOUNDARIES to "a receiver on a MAVLink-M network uses any
  frame, of any included definition, only if it is signed with a key it accepts,"
  or at minimum enumerate COMPONENT_METADATA, FILE_TRANSFER_PROTOCOL,
  MAV_CMD_REQUEST_MESSAGE + ack, EVENT, TIMESYNC/SYSTEM_TIME, and the bound DO_*
  commands.
- Demo: install `mavlink_signing_t` and streams on both channels with an
  `accept_unsigned_callback` that returns false for every 53xxx message, add a
  signing-provisioning step to the host tools and docs, or carry an explicit
  "bench only, no authentication" banner quoting `military.xml:360-363`.
- Provisioning: require the first `SETUP_SIGNING` to be signed, or gate it to a
  trusted local interface, to close the first-mover takeover.
