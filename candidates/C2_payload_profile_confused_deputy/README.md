# C2 — Payload-supplied JSON defines the safety meaning; bound command is independent of its label

| | |
|---|---|
| **Area** | generic payload service / capability profiles |
| **Severity** | 🟠 HIGH |
| **CWE** | 441 (confused deputy) / 345 / 807 (reliance on untrusted input in a security decision) |
| **Affected** | `payloads.schema.json` (`lifecycleEffect`, bindings); `docs/en/services/generic_payload.md`; `capability-profile-parachute.example.json` |
| **Reviewed at** | `mavlink-military` @ `6375c34` |
| **State** | schema-valid deceptive profiles built (`poc/`); operator-facing effect not rendered in a real GCS |

## Summary

Little of a payload operation's safety meaning is fixed by the dialect; it comes
from JSON the payload (or Payload Manager) supplies. A schema-valid capability
profile chooses the operation's label, its `lifecycleEffect` (which decides
whether a request is a stop, whether only `gcs_main` may run it, which inhibitions
cover it, and whether it needs a precondition), and — independently — the actual
command the GCS sends. The command a bound action issues is unconstrained by its
name or `lifecycleEffect`, so a RELEASE can be labelled benign while the GCS sends
`MAV_CMD_DO_PARACHUTE` (which also stops the motors) and attributes it to the
operator. This is the QGC-02 "the vehicle's string decides what the GCS does"
pattern, moved from file paths to flight-safety commands.

## Root cause

### `lifecycleEffect` is the safety classification, and the payload supplies it

`payloads.schema.json:1175-1186` (which admits "The schema cannot check that the
effect suits the function's activation pattern"). It decides:

- whether a PROFILE request is a **stop** (`generic_payload.md:412-413, 501, 505`),
  and a stop bypasses NOT_IN_CONTROL (`:514, :615`), inhibitions (`:518`), and
  state checks (`:580`);
- whether only `gcs_main` may run it (`:614, :622, :1932`);
- which inhibitions cover it (`payloads.schema.json:376`): `prevents:["activate"]`
  does not cover a release declared `none`;
- its lifecycle precondition (`:601`: `none` requires none).

### The bound command is free and GCS-sent

In `capability-profile-parachute.example.json`, ENABLE/DISABLE/RELEASE differ only
in a free-text `correlation` string (lines 69, 90, 111). The Client sends
`MAV_CMD_DO_PARACHUTE` to the binding's `targetComponentId` (the autopilot;
`generic_payload.md:1795-1798, 1814, 1821`; `payload_metadata.md:237`); RELEASE
"releases the parachute and stops the motors." `name`, `description`,
`lifecycleEffect`, `actionKey`, and the command value are independent
payload-chosen fields with no consistency rule, and the action is recorded against
the operator (`change_source=BOUND_SERVICE, requester=C`), making the GCS a
confused deputy toward the autopilot. Per [MAVLINKM-05](../../MAVLINKM-05_signing_coverage_gap/)
the bound `DO_*` command is also acceptable unsigned.

### No cross-checks, and the catalogue is itself forgeable

Catalogue labels are never compared with `PAYLOAD_INFO` (`payload_metadata.md:23`),
the catalogue carries no `function_type`, and nothing requires the GCS to show the
dialect-derived type or `PROTECTIVE` flag beside the payload label. Labels accept
NUL, ESC, and U+202E (RLO). Combined with [MAVLINKM-03](../../MAVLINKM-03_payload_catalogue_crc_forgery/),
a network attacker can supply these fields too.

## What was demonstrated

`poc/out_deceptive_parachute_profile.json` and `..._none.json` are schema-valid:
the RELEASE action is named "Disable auto-release (safe for handling)" or "Run
parachute self-check", with `lifecycleEffect` `disarm` or `none`, and
`idempotent: true`. `poc/uri_and_deception.py` also shows the schema accepting
hostile `definitionUri` / `documentationUri` values (`file:`, `javascript:`,
`mftp:///../`).

Not claimed: a shipped GCS rendered the deceptive label and issued the release. The
finding is that the dialect leaves the safety classification and the command-label
binding to untrusted JSON.

## Fix

Let only the Payload Manager, not profile JSON, make an action a stop or a gated
action; for EFFECTOR/DELIVERY/SAFETY_SYSTEM categories treat `none` as `activate`
when gating. Add a consistency rule tying `lifecycleEffect` to the bound command
(a `DO_PARACHUTE` RELEASE must be `activate`/irreversible) and reject a profile
that violates it. Require the Client to display the dialect-derived function type,
category, and flags with every control, and to sanitize label text.
