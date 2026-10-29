# C6 — Free-text fields flow to the operator UI and logs with no untrusted marking

| | |
|---|---|
| **Area** | message surface (dialect-wide) |
| **Severity** | 🟡 MEDIUM (consumer-dependent) |
| **CWE** | 20 / 117 (log injection) / 116 / 79-adjacent |
| **Affected** | the `char[]` fields across `military.xml` (list below) |
| **Reviewed at** | `mavlink-military` @ `6375c34` |
| **State** | surface map; impact is per-consumer (the MP-03 / DRONEKIT-01 class) |

## Summary

The dialect carries sender-controlled free text in many messages, all shown to the
operator and written to mission logs, with no guidance that the text is untrusted
or must be sanitized before display or logging. Whether any of these bites depends
on the consumer, exactly as in MP-03 (STATUSTEXT markup → `Process.Start`) and
DRONEKIT-01 (trust-boundary handoff): the dialect hands the consumer attacker text
and says nothing about treating it carefully.

## The fields

From a sweep of `military.xml` (`char[]` fields, all null-terminated, all
sender-controlled):

| Message | Field | Size |
|---|---|---|
| TARGET / TARGET_HANDOVER / BDA | `target_name` | 50 |
| TARGET_SET_COORD / TARGET_BOX_COORD | `target_set_name` | 50 |
| TARGET_HANDOVER | `match_media_url` | 50 (also a fetch sink, see [MAVLINKM-01](../../MAVLINKM-01_target_package_ssrf/)) |
| RWS_STATE | `weapon_string` | 50 |
| TARGET_CUE | `name` | 20 |
| MAVLINK_M_ACK | `reason` | 50 |
| TRACK_IDENTITY | `id_basis` | 50 |
| TRACK_IDENTITY / PARTICIPANT_POSITION / STORE_MUNITION | `external_track_number` | 20 |
| TARGET_AUTHORIZATION | `authority_role` | 50 |
| PARTICIPANT_POSITION | `callsign` | 50 |
| STORE_MUNITION | `nomenclature` | 30 |
| PAYLOAD_INFO | `payload_label`, `function_label` | 32 |

## Impact (consumer-dependent)

- **Operator deception on the common operating picture.** A sender sets a
  `target_name`, `callsign`, or `authority_role` to impersonate a friendly, a known
  unit, or a named authority, next to a `target_force` the sender also controls.
- **Log / record injection.** These fields are written to mission records
  (`TARGET_AUTHORIZATION` is an audit record); newline or control characters forge
  or corrupt log lines.
- **Display-layer injection.** If a consumer renders the text as markup or
  auto-links it (the MP-03 / MP-02 pattern), control sequences, URLs, or RLO
  (U+202E) characters reach the UI. The dialect allows any byte except the
  terminating NUL.

Not claimed: a specific consumer is exploitable. The finding is that the dialect
provides no "these fields are untrusted; sanitize before display or logging"
guidance for integrators, who are the ones that turn this into MP-03.

## Fix

Add a `FIELD CONVENTIONS` note that all human-readable `char[]` fields are
sender-controlled and untrusted: a consumer sanitizes control characters and
bidirectional overrides before display, never renders them as markup or
auto-linked, and escapes them before logging. Pair with a recommended display
length and an explicit statement that correlation uses the numeric identity
(`track_uid`, `function_id`), never the label — which several field descriptions
already say and could be generalized.
