# MAVLink-M security review

Drone/peer-to-consumer attack surface in **MAVLink-M**, the Dronecode
Foundation's draft MAVLink 2 dialect for military payloads and platforms
(arming/ESAD, targeting, fires, loitering-munition consent, remote weapon
stations, and a payload catalogue service). This is a companion to the
[Infected Drones](https://github.com/nicholasaleks/infected-drones) research,
which showed that ground control software trusts whatever the drone sends it.
MAVLink-M inherits that trust model, and in a military mesh the trusting consumer
is the GCS *or* a peer aircraft, a loitering munition, or a C2 gateway.

MAVLink-M is a public draft whose message layouts **freeze in November 2026**, so
the schema- and spec-level items here are timely: a schema change is in scope now
and needs a breaking revision afterward.

[`THREAT_MODEL.md`](THREAT_MODEL.md) is the full model (assets, trust boundaries,
T1-T11, honest negatives, freeze priorities). The findings below are the
reproduced or schema-confirmed items.

## Responsible use

This documents weaknesses in a draft protocol for operators and maintainers to
reproduce and fix before the standard freezes. The proof-of-concepts are a
signing availability bug, a CRC forgery, a parser-contract check, and schema
analysis. Nothing here injects arming, fire, release, or consent commands, and
nothing is packaged for use against a real system. Run the PoCs only against
material you control.

## Scope

Reviewed 2026-10-28 at `mavlink-military` @ `6375c34`,
`mavlink-military-c_library_v2` @ `a957b86`, pymavlink pin `19880422`, and
`nucleo-mavlink-m-demo` @ `4860564`. The controlled gateway ICDs (Link 16 / VMF /
OMS-UCI translation) are not public and are out of scope; so is any specific
vendor GCS implementation, since the dialect is not an implementation.

## Findings

| ID | Sev | CWE | Sink / mechanism | Verified | Fix |
|---|---|---|---|---|---|
| [MAVLINKM-01](MAVLINKM-01_target_package_ssrf/) | 🟠 HIGH | 918/22/494 | `TARGET` carries drone-supplied IP+port+path → consumer SSRF + traversal fetch; integrity is a sender-supplied uint32 | ✅ reproduced (E2E SSRF) | [proposal](MAVLINKM-01_target_package_ssrf/PROPOSAL.md) |
| [MAVLINKM-02](MAVLINKM-02_signing_replay_state_lockout/) | 🟠 HIGH | 294/400 | Signing replay-state poisoned → genuine stops (ABORT/DISARM) dropped as replay | ✅ reproduced (pymavlink + C lib) | pin bump (pymavlink #1300); C needs upper bound |
| [MAVLINKM-03](MAVLINKM-03_payload_catalogue_crc_forgery/) | 🟠 HIGH | 345/354/494 | Catalogue bound to signed status only by a forgeable CRC-32 → network/file-server attacker swaps catalogue content | ✅ reproduced (CRC collision) | add `catalogue_sha256` |
| [MAVLINKM-04](MAVLINKM-04_reference_esad_handler_unsafe/) | 🟠 HIGH | 1284/697 | Reference ESAD handler arms on any nonzero; regeneration inverts DISARM→arm | ✅ reproduced (running code) | exact-match enum switch |
| [MAVLINKM-05](MAVLINKM-05_signing_coverage_gap/) | 🟠 HIGH | 306/345 | Signing mandate excludes the fetch path (metadata/FTP/TIMESYNC) and bound DO_* commands; reference implements no signing | ✅ demo reproduced; spec/PX4 code-read | broaden mandate; sign the reference |
| [MAVLINKM-06](MAVLINKM-06_warhead_mode_unprotected_enum/) | 🟡 MED | 1319/704 | `WARHEAD_MODE` and other arming/fuze-adjacent enums left sequential (dmin=1), so a single-bit fault crosses valid values the codeword scheme exists to protect | ✅ computed | codeword-protect or mark advisory |
| [MAVLINKM-07](MAVLINKM-07_payload_op_len_overrun/) | 🟡 MED | 130/20 | `PAYLOAD_OPERATION_REQUEST.input_len` / `..._STATUS.output_len` are uint8 (0-255) into `uint8_t[64]`; receiver clamp is implied, not mandated | schema | mandate reject `len > 64` |
| [MAVLINKM-08](MAVLINKM-08_mav_cmd_id_reuse/) | 🟡 MED | 440/696 | MAV_CMD 53090 reused (STORE_ARM→STORE_SAFE); `COMMAND_LONG` CRC_EXTRA is unchanged, so an old receiver reads a new DISARM as the old arm | ✅ history-confirmed | never reuse a MAV_CMD id |

All findings are drone/peer→consumer unless noted; MAVLINKM-02 is also a
cross-mesh availability attack. No upstream issues or PRs have been filed yet.
