# MAVLINKM-06 — Arming/fuze-adjacent enums left sequential, outside the codeword scheme

| | |
|---|---|
| **Product** | MAVLink-M dialect (`military.xml`) |
| **Severity** | 🟡 MEDIUM (safety-enum encoding consistency) |
| **CWE** | 1319 (improper protection against electromagnetic/fault injection) / 704 |
| **Affected** | `MAVLINK_M_WARHEAD_MODE` (`STORE_MUNITION.warhead_mode`, 53035); and the fuze/munition-state enums below |
| **Reviewed at** | `mavlink-military` @ `6375c34`, public draft |
| **Interaction** | fault/corruption, the same threat the codeword scheme targets |
| **Verified** | computed: Hamming distances over the assigned enum values, 2026-10-28 |
| **Status** | design-level; fix is a schema/doc change before freeze |

## Summary

MAVLink-M protects twenty-two safety-critical enums with extended-Hamming
codewords so that no single-, double-, or triple-bit fault turns one valid value
into another (`docs/en/guide/status_field_encoding.md`). Verified: all twenty-two,
and the 16-bit `PAYLOAD_OPERATION_RESULT`, hold a minimum pairwise Hamming
distance of four. But several enums the dialect's own header describes as
arming- or fuze-adjacent are left on sequential values (distance 1), so the fault
the codeword scheme exists to catch silently changes them between valid values.
The clearest case is `MAVLINK_M_WARHEAD_MODE`, which the header calls a "SAFE/ARM
-adjacent coarse selection."

## Root cause

### The protected set holds (clean)

Computed over the assigned values in `military.xml`: each of the twenty-two
in-scope enums uses only the 16-value codebook
(`0x00 0x0F 0x33 0x3C 0x55 0x5A 0x66 0x69 0x96 0x99 0xA5 0xAA 0xC3 0xCC 0xF0 0xFF`),
reserves 0 for UNKNOWN/NONE, never uses `0xFF`, and has a minimum pairwise
distance of four. `PAYLOAD_OPERATION_RESULT` (16-bit) likewise has distance four.
The scheme is correctly specified where it is applied.

### WARHEAD_MODE is arming-adjacent but sequential

`military.xml:1469-1484`:

```
<enum name="MAVLINK_M_WARHEAD_MODE">
  ... This is a SAFE/ARM-adjacent coarse selection, NOT a fuze timing channel ...
  <entry value="0" name="..._UNSPECIFIED">
  <entry value="1" name="..._SURFACE">
  <entry value="2" name="..._PENETRATE">
  <entry value="3" name="..._AIRBURST">
```

Values 0-3 are one bit apart (SURFACE `01` ↔ AIRBURST `11` is a single bit). The
header SAFETY BOUNDARIES reinforces the safety framing (`military.xml:444`):

```
- ESAD_CONFIG and the selectable WARHEAD_MODE set only coarse, device-defined
  SAFE/ARM modes.
```

A single-bit fault on `STORE_MUNITION.warhead_mode` (`military.xml:2598`) changes
the reported warhead effect (surface ↔ airburst ↔ penetrate) to another valid
value, undetected, which is exactly the class of fault
`status_field_encoding.md` builds the codewords to catch for the other arming
state.

### Other arming/fuze-adjacent enums, also sequential (dmin=1)

Computed from `military.xml`: `MAVLINK_M_FUZE_MODE` (9 values),
`MAVLINK_M_MUNITION_WARHEAD` (8), `MAVLINK_M_FUZE_HEALTH` (4),
`MAVLINK_M_ESAD_*` reported *type* fields such as `munition_type`. The dialect's
`status_field_encoding.md` Scope section argues some descriptive assessments
(`PID_STATUS`, `CDE_LEVEL`, `ROE_STATE`, `NOSTRIKE_STATUS`) are deliberately out
of scope because "no receiver acts on them by itself." That rationale is explicit
for those four; it is not stated for WARHEAD_MODE or FUZE_MODE, whose
descriptions carry SAFE/ARM and method-of-engagement language.

## Impact

A fault outside the packet-CRC window (a bit flip in stored state, a buffer or
shared-memory copy) changes an arming- or fuze-adjacent enum to another valid
value with no detection, in the same message families the codeword scheme
otherwise hardens. The concrete effect is a misreported warhead effect or fuze
mode presented to the operator or folded into a consumer's handling, where the
design's stated goal is that such a value be detectably invalid.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| The 22 protected enums are correct | ✅ | computed dmin = 4 for all, plus the 16-bit result code |
| WARHEAD_MODE is sequential (dmin=1) | ✅ | values 0-3 |
| Header frames WARHEAD_MODE as SAFE/ARM-adjacent | ✅ | `military.xml:444`, `:1473` |
| WARHEAD_MODE is a *commanded* field on this dialect | ❌ | it appears only as reported `STORE_MUNITION.warhead_mode` |
| A receiver acts on it autonomously | ⚠️ | not stated; the scope rationale for exclusion is given only for four other enums |

Not claimed: a commanded arm/safe crossing (the commanded arm/safe selectors —
ESAD_ARMING, ESAD_CONFIG.trigger_distance_mode — *are* codeword-protected). The
finding is the inconsistency: a field the header calls SAFE/ARM-adjacent is left
unprotected, with no stated "advisory only" exclusion.

## Version scope

Present at the reviewed draft `6375c34`. Fixable before the November 2026 freeze;
afterward it needs a breaking revision (enum value reassignment changes the wire
value, though not `CRC_EXTRA`).

## Reproduction

```sh
python3 -I poc/check_enum_distances.py <path-to>/military.xml
```

The script parses every enum, confirms the twenty-two in-scope enums and
`PAYLOAD_OPERATION_RESULT` have minimum pairwise Hamming distance four, and lists
the arming/fuze-adjacent enums left at distance one.

## Fix

Either assign `MAVLINK_M_WARHEAD_MODE` (and any other enum the header treats as
SAFE/ARM- or arming-adjacent) codebook values with distance four, as the
twenty-two protected enums use; or, if these are genuinely advisory and never
acted on, state that exclusion explicitly in `status_field_encoding.md` as is
already done for `PID_STATUS` / `CDE_LEVEL` / `ROE_STATE` / `NOSTRIKE_STATUS`, and
soften the SAFE/ARM wording in the WARHEAD_MODE description and SAFETY BOUNDARIES.
