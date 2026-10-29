# C5 — PX4 learns routes from unverified frames; SETUP_SIGNING first-mover race

| | |
|---|---|
| **Area** | integration (PX4, the demo's relay) |
| **Severity** | 🟡 MEDIUM |
| **CWE** | 290 (authentication bypass by spoofing) / 306 / 400 |
| **Affected** | PX4 `mavlink_receiver.cpp`, `mavlink_sign_control.cpp`, `mavlink_main.cpp` |
| **Reviewed at** | PX4 main @ `1776a8a` (code-read); contradicts `military.xml:342-347` |
| **State** | code-read only; not run against a live PX4 |

## Summary

The dialect requires that a router learn routes only from signature-verified
frames (`military.xml:342-347`), to stop a forged frame from steering delivery.
PX4, the relay in the project's own demo, does not meet this: it adds routes from
unverified frames, and while signing is uninitialized it accepts `SETUP_SIGNING`
from anyone, so a compromised peripheral can key the link first.

## Root cause

- Signing off (the demo's configuration): every OK frame adds a route via
  `update_rx_stats(msg, true)` (`mavlink_receiver.cpp:4101`).
- Signing on: unsigned HEARTBEAT / RADIO_STATUS / ADSB_VEHICLE / COLLISION still
  return `FRAMING_OK` through `accept_unsigned`
  (`mavlink_sign_control.cpp:48-53, 223-236`), so they still add routes —
  contradicting `military.xml:342-347`.
- The route table holds 16 entries per instance and never frees them
  (`mavlink_receiver.h:332, 340`; `mavlink_receiver.cpp:4296-4316`). Unsigned
  HEARTBEATs from 16 fake IDs fill it; a component appearing later never becomes
  "seen", and addressed messages to it are then not forwarded on that link
  (`mavlink_main.cpp:643-650`). Broadcasts still flow. (PX4 only adds routes and
  never moves them, so mavlink-router's "one forged frame hijacks a station" case
  does not apply directly.)
- Provisioning: while signing is uninitialized, `SETUP_SIGNING` is accepted on any
  instance when not armed (`mavlink_main.cpp:1200-1258`, from
  `mavlink_receiver.cpp:472`). In the demo topology a compromised TELEM2
  peripheral can install its own key first and lock out the GCS. Once signing is
  active, changing the key needs a signed frame (clean).

Unknown dialect message IDs do not add routes (`update_rx_stats(msg, false)` at
`:4112`) — clean.

## Impact

On a MAVLink-M deployment that uses PX4 as the relay, a party without the signing
key can influence routing (fill the route table so a station's addressed messages,
including stops, are not forwarded) and, before signing is provisioned, seize the
signing key. The dialect's routing-integrity assumption does not hold on its own
reference autopilot.

Not claimed: run against live PX4; this is a code-read of PX4 main and may differ
on a release branch (e.g. 1.18). It is an integration/deployment gap, not a dialect
schema bug.

## Fix

Deployment: provision signing before first flight and gate `SETUP_SIGNING` to a
trusted local interface or require the first one to be signed. Upstream PX4 /
spec: reconcile `accept_unsigned` route learning with `military.xml:342-347`
(do not learn routes from unsigned frames on a MAVLink-M link), and bound or age
the route table.
