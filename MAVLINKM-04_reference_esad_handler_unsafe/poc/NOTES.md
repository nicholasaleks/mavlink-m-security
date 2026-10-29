# MAVLink-M nucleo demo review notes

Target: `scratchpad/mavlink-m/nucleo-mavlink-m-demo` @ 4860564 (main). Branch
`origin/mrpollo/px4-custom-build-guide` is fully merged (`git diff main...branch`
and `git log main..branch` both empty; merged as 1703e5a).
Spec: `scratchpad/mavlink-m/mavlink-military` @ 6375c34 (2026-10-28).
PX4 reference: sparse clone of PX4-Autopilot main @ 1776a8a (2026-10-29) in `agent-demo/px4`.

Vendored firmware headers: `nucleo_mavlink_m/mavlink/military/version.h` says built
"Fri Jul 17 2026" = spec b08d5a4 era (pre-addressing d3f8f12 Jul-31, pre-Hamming
1b8851c Sep-21, pre-signing-mandate 2ae0e5b Oct-09). ESAD_ARMING CRC_EXTRA 153 there,
3 in current spec. ESAD_STATE CRC_EXTRA 81 in both (wire-identical, comments only differ).

## Harness

- `agent-demo/harness/arduino_stub.h` - Stream/HardwareSerial/micros/digitalWrite shim.
- `agent-demo/harness/harness.cpp` - `#include "nucleo_mavlink_m.ino"` (copied unchanged into
  `agent-demo/vendored/` and `agent-demo/regen/`), drives `loop()`, inspects `g_arming_status`, LED,
  and parses the firmware's TX bytes.
- `agent-demo/vendored/mavlink` -> symlink to repo headers (read-only).
- `agent-demo/regen/mavlink` = `mavgen.py --lang=C --wire-protocol=2.0` on current military.xml
  (the SETUP.md:103-114 step "regenerate if military.xml changes"). The .ino compiles unchanged.
- macOS Apple clang ASan hangs at startup (even on `int main(){}`), same as the known SITL issue,
  so ASan/UBSan runs are in Docker `gcc:14` (aarch64). A UBSan-only macOS build (`hu_vendored`)
  gives identical sweep results.

Build/run:
```
docker run --rm -v $W:/w -v $REPO/nucleo_mavlink_m/mavlink:/w/vendored/mavlink:ro -w /w/harness gcc:14 bash -c \
 'for v in vendored regen; do g++ -std=c++17 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -fno-omit-frame-pointer -Wno-address-of-packed-member -include arduino_stub.h -I. -I../$v -x c++ harness.cpp -o lx_$v; \
  ./lx_$v all; done'
./lx_{vendored,regen} fuzz 1500000 {1,2,3}
```
Outputs: `harness/out_vendored.txt`, `harness/out_regen.txt`.

Key output (regen = unmodified .ino + headers regenerated from current spec):
```
[named] start=ARMED send MAVLINK_M_ESAD_REQUEST_DISARM (51) -> g_arming_status=51 (ARMED), LED=1, ESAD_STATE.arming_status=51
[sweep] arming_request values that ARM a disarmed ESAD: 255/256
[sweep] arming_request values that DISARM an armed ESAD: 0 (1/256)     <- only NONE(0), which spec says to refuse
[bitflip] DISARM codeword 51 with 1-3 bits changed: 92/92 leave/turn the ESAD ARMED
```
vendored: ARM=1/DISARM=0 behave as named, but 255/256 values arm and 92/92 1-3-bit corruptions of DISARM(0) arm.
Both: unsigned / unknown-key-signed / trashed-signature / sysid 77 / esad_id=0 / store_id=200 /
time_usec 0 or UINT64_MAX / USB link -> all ARMED; DISARM(t=2000) then ARM(t=1000) -> ARMED; byte-identical replay -> ARMED;
0 MAVLINK_M_ACK frames for 256 requests.
xver: current-spec ESAD_ARMING (CRC 3) into vendored firmware -> dropped (CRC_EXTRA mismatch). So the inversion is
not reachable on the wire against the *as-flashed* binary; it is reached as soon as headers are regenerated per SETUP.md.
Fuzz: 6 x 1.5M iterations (valid-CRC frames for every known msgid, any length 0-255, random signed flag/signature,
noise, bit corruption, both channels) -> no ASan/UBSan report.

Host python: current-spec pymavlink dialect + the exact call in fake_pixhawk.py:102 / gcs_via_px4.py:151 ->
`TypeError: esad_arming_send() missing 3 required positional arguments: 'target_system', 'target_component', and 'track_uid'`.
generate_dialect.sh:47-52 auto-picks `../../mavlink-military/military.xml` (current spec), so the documented quick
start is broken against the current spec; the `--arm` flag sends raw 0/1 (fake_pixhawk.py:64, gcs_via_px4.py:84),
which in the current encoding are NONE and an unlisted value; against regen firmware 1->ARMED and 0->DISARMED, so the
repo's PASS test would keep passing while the real DISARM codeword arms.

## Findings (detail in final report)

F1 HIGH (reference-impl safety inversion) nucleo_mavlink_m.ino:135-138 `in.arming_request ? ARMED : DISARMED`.
F2 HIGH (spec non-conformance, auth) no signing anywhere: firmware never sets status->signing; mavlink_helpers.h:131
   signature_check returns true when signing==NULL; parse accepts signed frames with garbage signature. No MAV_SIGN /
   SETUP_SIGNING step in SETUP.md / PX4_INTEGRATION.md / PX4_CUSTOM_BUILD.md / px4_telem2_setup.txt.
F3 MED  no selector/target/challenge/time/replay checks: ino:131 accepts esad_id 0 for ARM; store_id ignored; challenge
   ignored and advertised as constant 0 (ino:102); time_usec ignored; no stop records; any sysid; both links.
F4 MED  no MAVLINK_M_ACK, no refusal, refusal-not-recorded-as-stop; ESAD_STATE only on command, echoes request
   instead of device state (ino:107), reports PIN_PRESENT while ARMED.
F5 MED  host tools/docs encode the old enum (PROTOCOL.md:45-51,105-147 "line up on 0/1 by design"; gcs_via_px4.py:166-172;
   fake_pixhawk.py:116-122) and break against current spec.
F6 LOW  USB VCP is a second, unauthenticated arming path that bypasses PX4 (ino:15-25,181-182) and all replies are
   broadcast to both links.
F7 LOW  TX amplification/back-pressure: each 26-byte ESAD_ARMING -> ~55-byte ESAD_STATE on BOTH links via blocking write
   (ino:60-66); flood on one link can starve RX (64-byte STM32duino default ring, not verified on HW) -> lost DISARMs.
F8 LOW  compid 190 = MAV_COMP_ID_MISSIONPLANNER (minimal.xml:632) used for the ESAD and the host GCS alike.
F9 INFO docs claim PX4 drops unknown dialect frames (PROTOCOL.md:176-182, PX4_INTEGRATION.md:14-23,
   TROUBLESHOOTING.md:163-168). Current PX4 main forwards unknown msgids as FrameCheck::ForwardOnly
   (mavlink_receiver.cpp:4215-4235, forwarded at :4118) - a common-only PX4 is not a filter.

PX4 (code-read, main @1776a8a):
- Signing only via SETUP_SIGNING; no MAV_SIGN_CFG param in mavlink_params.yaml/module.yaml.
- Route learning: update_rx_stats(msg, true) on FrameCheck::Ok (mavlink_receiver.cpp:4101). With signing off (demo),
  every frame. With signing on, unsigned HEARTBEAT/RADIO_STATUS/ADSB_VEHICLE/COLLISION are FRAMING_OK via
  accept_unsigned (mavlink_sign_control.cpp:48-53,223-236) -> routes learned from unverified frames, contrary to
  military.xml:342-347. Table is 16 entries per instance, never freed (mavlink_receiver.h:332,340;
  mavlink_receiver.cpp:4296-4316) -> unsigned HEARTBEATs from 16 fake IDs exhaust it; later components never become
  "seen", so addressed (target_system!=0) messages to them are not forwarded on that link (forward_message
  mavlink_main.cpp:643-650). Broadcast still flows. PX4's model adds routes, does not move them, so the
  "one forged frame hijacks a station" mavlink-router case does not apply directly.
- Unknown msgids (ForwardOnly) do not add routes (update_rx_stats(msg,false), :4112) - clean.
- SETUP_SIGNING accepted on any instance (Mavlink::handle_message mavlink_main.cpp:1200-1258, called from
  mavlink_receiver.cpp:472) when signing not yet initialized; only gated by "not armed". In the demo topology a
  compromised TELEM2 peripheral can provision PX4's key first (lock-out). New key while signing active must arrive in a
  frame that passed signature check (unsigned SETUP_SIGNING is not in accept_unsigned list) - clean.

Spec observation (mavlink-military afcdabb, 2026-10-27): MAV_CMD 53090 changed meaning from STORE_ARM (Jul-17:
param2 "0 = safe/disarm, 1 = arm", param3 challenge; vendored military.h:1267) to STORE_SAFE (param2 = 51.0 DISARM
codeword, param3 NaN). COMMAND_LONG/COMMAND_INT CRC_EXTRA never changes, so unlike the dialect messages (whose CRC_EXTRA
changed and so fail closed), a receiver built from the Jul-17 file - which this demo vendors and PX4_INTEGRATION.md
tells integrators to compile in - parses a new safe as the old arm command with param2=51. Under the demo's
truthiness pattern that is an arm; NaN->uint32 for the challenge is UB in C and commonly 0, which is what this demo
advertises. Not demonstrated (no STORE_ARM receiver exists in this repo). Suggest never reusing a MAV_CMD id with
different semantics; keep 53090 reserved/refused and give STORE_SAFE a fresh id.

Mixed-version status messages with unchanged CRC_EXTRA but re-encoded enums: ESAD_STATE 53030, STORE_STATUS 53033,
STORE_SENSOR_STATUS 53034, RWS_STATE 53041 (plus 53000/1/3/10-13/22/35/40). Old/new values overlap only at 0 (old
DISARMED / IGNITION_OPEN -> new UNKNOWN) so exact-match receivers degrade to "unknown"; demo-style receivers do not.

## Clean / negative results

- Receive path memory safety: parser is upstream mavlink_helpers.h; per-channel static buffers
  (MAVLINK_COMM_NUM_BUFFERS 2, mavlink_config.h:11) correctly separate the two links; len > MAVLINK_MAX_PAYLOAD_LEN
  impossible (uint8); unknown msgid -> BAD_CRC -> dropped; short payloads zero-filled to max_msg_len;
  esad_arming_decode clamps len. Firmware handler reads only two uint8 fields, no strings/arrays/indexes.
  6 x 1.5M-iteration ASan+UBSan fuzz clean on both header generations.
- broadcast() buffer is MAVLINK_MAX_PACKET_LEN (ino:62) - fine. send_statustext string is a constant < 50 chars.
- No secrets, keys or tokens in any commit (`git log --all -p` grep); only a leaked local path
  `/Users/rroche/Work/Dronecode/PX4-Autopilot/.claude/worktrees/...` in generate_dialect.sh, removed in 2506852.
  One deleted file (mavlink_msg_target_coord.h, regenerated header). No debug backdoors / hidden commands in firmware.
- Host Python: no eval/pickle/yaml/shell=True. diagnose_link.py subprocess calls use fixed argv lists
  (systemctl, id) with timeouts; count_frames/classify are bounds-checked pure-Python over bytes read from the port.
  pymavlink_compat.py only monkeypatches add_message() with an extra None guard (no new attack surface).
  generate_dialect.sh: `set -euo pipefail`, quoted paths, mktemp; runs mavgen on a user-supplied XML (trusted input).
  Attacker-controlled link data only reaches pymavlink's own parser (out of scope here).
