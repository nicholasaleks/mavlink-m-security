# MAVLink-M — Threat Model

A drone-to-consumer threat model for **MAVLink-M**, the Dronecode Foundation's
draft MAVLink 2 dialect for military payloads and platforms
(`github.com/Dronecode/mavlink-military`, reviewed at commit `6375c34`,
2026-10-28). The dialect is a public draft whose layouts freeze in
**November 2026**, so the design-level items below are timely.

This model extends the [Infected Drones](README.md) thesis: a ground control
station, and in a military mesh also a peer aircraft, a loitering munition, or a
C2 gateway, trusts what the drone sends it. MAVLink-M inherits that trust model
and adds new sinks on top of it, sometimes in the schema itself.

The emphasis is drone→GCS, as the wider research is, but MAVLink-M is a mesh:
TARGET, TARGET_HANDOVER and the fires messages travel system-to-system, so a
compromised platform also attacks its peers. Both directions are covered.

---

## Scope

In scope: the dialect schema (`military.xml`), the payload catalogue / Component
Metadata service and its JSON schemas, the generated C library
(`mavlink-military-c_library_v2`), the pinned pymavlink generator, the CI/release
pipeline, and the on-hardware demo (`nucleo-mavlink-m-demo`).

Out of scope: the controlled gateway ICDs that translate to Link 16 / VMF /
OMS-UCI (not public), and any specific vendor GCS implementation (the dialect is
not an implementation). Where a flaw is "whatever the consumer does with this
field," that is called out as consumer-dependent rather than asserted as RCE.

This is defensive research for responsible disclosure. Nothing here injects
arming, fire, release or consent commands; the proof-of-concepts are a signing
availability bug, a CRC forgery, and schema analysis.

---

## Assets

| Asset | Why it matters |
|---|---|
| Operator's targeting picture (COP) integrity | A spoofed target name, class, or affiliation changes what the operator decides. |
| The GCS / C2 host and its LAN | Fetch sinks reach internal services; a write/RCE sink reaches the operator's workstation. |
| Mission logs and accountability records | TARGET_AUTHORIZATION and free-text fields are written to the permanent record. |
| The "stops win over starts" guarantee | ABORT / CHECK_FIRE / DISARM must always land. Its whole value is availability. |
| The loitering-munition human-consent gate | A hard gate per SAFETY BOUNDARIES; its integrity is safety-critical. |
| The integrator supply chain | The generated C headers are vendored into every implementer's flight software. |

---

## Actors and trust boundaries

MAVLink-M's only on-link authentication is **MAVLink 2 message signing**, with a
**single key shared by every system that checks it** (`military.xml` SAFETY
BOUNDARIES, lines 332-363). That shared-key model sets the boundary ladder:

| # | Actor | What it can put on the wire | Authentication in the way |
|---|---|---|---|
| A | Compromised payload / peripheral on the aircraft | any dialect message the FMU relays; its own PAYLOAD_* catalogue | signing is *per-bus*; the FMU/bridge re-originates with the network key, so the payload's lies inherit trust |
| B | Compromised-but-keyed aircraft or munition | validly-signed anything, as any system ID | the shared key — the spec admits "any holder can sign as any system ID ... an aircraft or munition that can be lost included" |
| C | On-link / MITM without the key | injected or replayed frames | signing drops unsigned/replayed dialect frames — but only dialect frames (see T5), and the replay state itself is attackable (see T4) |
| D | Network or file-server attacker on the fetch path | altered catalogue/profile/package bytes fetched off the MAVLink link | none on the HTTP(S) fetch; CRC-32 only on the catalogue (see T2) |
| E | Malicious contributor to the dialect repo | a merged `military.xml` pull request | author + one approval; CI (see T6) |
| F | Anyone, on a bench / sim link | everything | signing is optional off-deployment, so there is none |

Actor B is the center of gravity: the shared key means a single lost airframe is
indistinguishable from the human authority to every receiver on the mesh.

---

## Threats

Severities are the research team's estimate for the dialect as written; a
specific integrator may rate higher or lower. "Verified" marks what has a
reproduced proof-of-concept in this repository.

### T1 — Target-package retrieval is SSRF + path traversal, by design *(HIGH, schema)*

`TARGET` (53010) carries, all from the sender: `package_endpoint_ip_1/2/3` (raw
IPv4), `package_endpoint_port` (TCP port), `package_transport`
(`MAVLINK_M_TARGET_PACKAGE_TRANSPORT`, where HTTP cleartext is a listed value),
and `package_path` (`char[80]`). A consumer that follows the schema connects
*out* to a sender-named host and GETs a sender-named path to retrieve "an
externally hosted target package." The only integrity field is
`package_id_hash`, a **uint32** — not a cryptographic binding, and the sender
supplies it for its own payload. No scheme allowlist, size cap, host restriction
or path-handling rule appears anywhere in the dialect or docs.

This is the QGC-02 / MAVSDK-01 SSRF and the MAVSDK-02 / QGC-03 traversal
patterns, specified rather than accidental. The sink is the consumer's HTTP
client and local filesystem. The consumer is the GCS *or* a peer system taking a
handover, so this is drone→GCS and drone→drone.

Mapped finding: [MAVLINKM-01](MAVLINKM-01_target_package_ssrf/). Contrast: the
payload catalogue service (below) is meticulous about exactly these dangers
(size caps, scheme allowlist, "documentation URIs are never fetched"); the
TARGET package path has none of that discipline.

### T2 — Payload catalogue integrity is a forgeable CRC-32 *(HIGH, verified)*

A consumer binds the downloaded catalogue to the one signed message
(`PAYLOAD_CATALOGUE_STATUS`, 53107) only through `catalogue_file_crc`, a CRC-32.
Every profile's SHA-256 lives *inside* the catalogue, so the whole chain of trust
reduces to that CRC-32. MAVLink's CRC-32 is linear, so an attacker who can change
the catalogue bytes but cannot sign the status (actor D: the HTTPS file server,
or an unsigned-FTP / COMPONENT_METADATA injector) can produce a byte-different,
schema-valid catalogue with the same CRC, then redirect every profile to an
attacker host with an attacker-chosen hash.

Verified: a forged catalogue with an identical MAVLink CRC-32 to the genuine
example. The `definition_manifest_sha256` field in the same message is SHA-256
but covers only the schema-release manifest, not the catalogue content, so it
does not help. Mapped finding:
[MAVLINKM-03](MAVLINKM-03_payload_catalogue_crc_forgery/).

### T3 — UI / record / command deception from payload-supplied JSON *(HIGH, design)*

Almost nothing about a payload operation's *safety meaning* is fixed by the
dialect; it comes from JSON the payload (or Payload Manager) supplies. A
schema-valid capability profile can label a RELEASE as "Disable auto-release
(safe for handling)", declare an irreversible action's `lifecycleEffect` as
`disarm` or `none` (which bypasses in-control checks, inhibitions and state
checks), and make it `idempotent`. The command a bound action actually sends
(e.g. `MAV_CMD_DO_PARACHUTE`, which also stops the motors) is independent of its
name, description and `lifecycleEffect`, so the GCS becomes a confused deputy
toward the autopilot, with the action recorded against the operator.

Alongside this, the dialect's own free-text `char[]` fields — `target_name`,
`weapon_string`, `callsign`, `nomenclature`, `authority_role`, `reason`,
`payload_label`, `name`, `id_basis`, plus `match_media_url` in TARGET_HANDOVER —
are sender-controlled, shown to the operator and written to logs, with no
"untrusted" marker. Whether they bite depends on the consumer (format strings,
markup auto-linking as in MP-03, log injection, COP spoofing). This is the MP-03
/ DRONEKIT-01 trust-boundary class.

### T4 — Signing replay-state poisoning suppresses stops *(HIGH, verified)*

SAFETY BOUNDARIES promises "a frame that fails the signature check changes no
replay state" and "a receiver never rejects a stop for its time." Both the
pinned pymavlink generator and the generated C library break these:

- pymavlink commits the per-stream replay timestamp *before* verifying the
  signature, so one bad-signature frame with timestamp `2^48-1` (keyless, actor
  C) locks out every later genuine signed frame from that stream.
- The C library has no upper bound on the timestamp, so one validly-signed frame
  (actor B, a key holder) claiming the authority's stream with timestamp
  `2^48-1` makes the authority's later ABORT/DISARM frames drop as REPLAY and an
  unheard backup station's drop as OLD_TIMESTAMP.

Verified for both. The pymavlink half is fixed upstream (ArduPilot/pymavlink
#1300, 15 commits ahead of the pin); the C-library / key-holder half is not.
Mapped finding: [MAVLINKM-02](MAVLINKM-02_signing_replay_state_lockout/).

### T5 — The signing mandate does not cover the fetch path *(HIGH, design)*

The signing rule covers "a message of this dialect, a MAV_CMD_MAVLINK_M_STORE_*
command or the COMMAND_ACK answering one." It does **not** cover the common.xml
messages the payload service and the TARGET package rely on:
`COMPONENT_METADATA`, `FILE_TRANSFER_PROTOCOL`, `MAV_CMD_REQUEST_MESSAGE` and its
ack, `EVENT`, `TIMESYNC` (sets the time basis the whole safety-time model
depends on), and the bound commands `MAV_CMD_DO_PARACHUTE` / `DO_GRIPPER` /
`DO_WINCH`. An on-link attacker without the key (actor C) can inject these. This
is what lifts T1 and T2 from "the vehicle is the attacker" to "any on-link or
file-server attacker," and lets a late unsigned ARM/ACTIVATE land after a signed
stop because the payload service is outside the stops-win rule.

### T6 — Shared-key blast radius *(HIGH, design, acknowledged)*

The key is shared by every checking system, so one captured airframe or payload
can sign as the human authority, as the Payload Manager, or as a peer: forged
DISARMED-while-armed state, forged acceptance of a stop, forged requester IDs to
cancel another station's operation. "Packet source identifies the payload
manager" is not authentication under a shared key. The spec acknowledges this but
offers no mitigation (per-domain keys, asymmetric signatures).

### T7 — Build-time: dialect text becomes code in the generated library *(MEDIUM, verified)*

`military.xml` description text is copied unescaped into the generated C (inside
comments; a `*/ ... /*` break in a field description adds a hidden struct member
that silently shifts every later field) and into Python docstrings (a `"""`
break reached `__import__`). Both survive xmllint, mavgen validation, and the
`-Werror` CI compile, and the wire-compat CRC check stays byte-identical. This
lands in the vendored C library every integrator builds against. Precondition:
actor E merges a crafted PR. Current XML is clean. (From the CI review; see
scratchpad `agent-ci/NOTES.md`.)

### T8 — Catalogue/schema resource exhaustion *(MEDIUM)*

The JSON schema encodes almost no bounds (limits live in prose), so a
schema-valid catalogue can drive a validator into O(n²) `uniqueItems` work:
~17 s for one 112 KB profile, ~175 s for an 858 KB `prevents` array, repeated on
every catalogue revision. The PYULOG-01 / MAVSDK-03 amplification class, moved
into the metadata validator.

### T9 — The reference implementation teaches the unsafe pattern *(HIGH, verified)*

The on-hardware demo (`nucleo-mavlink-m-demo`), the project's worked example, maps
ESAD_ARMING with a C truthiness test, so it arms on any nonzero `arming_request`
and on every 1-3-bit corruption of DISARM; regenerating its headers from the
current spec (the demo's own documented step) inverts safety, so DISARM=51 arms.
It also implements no MAVLink 2 signing anywhere in firmware, host, or docs, so
every ESAD command is accepted unsigned from any sysid. Both reproduced by running
the handler. Integrators copy the reference, so these propagate. Mapped findings:
[MAVLINKM-04](MAVLINKM-04_reference_esad_handler_unsafe/) and
[MAVLINKM-05](MAVLINKM-05_signing_coverage_gap/) (which also carries the spec-level
signing-coverage gap behind T5).

### T10 — Arming/fuze-adjacent enums left outside the codeword scheme *(MEDIUM, computed)*

The codeword scheme that protects the twenty-two safety enums (verified: all hold
minimum Hamming distance 4) is not applied to several enums the dialect's own
header calls arming- or fuze-adjacent: `WARHEAD_MODE` (which SAFETY BOUNDARIES
calls a "SAFE/ARM-adjacent coarse selection"), `FUZE_MODE`, `MUNITION_WARHEAD`,
`FUZE_HEALTH`, all left sequential (distance 1). A single-bit fault, the exact
threat the codewords exist to catch, crosses them between valid values undetected.
Mapped finding: [MAVLINKM-06](MAVLINKM-06_warhead_mode_unprotected_enum/).

### T11 — Reused MAV_CMD id defeats version fail-closed *(MEDIUM, confirmed)*

MAV_CMD 53090 was `STORE_ARM` and is now `STORE_SAFE` (disarm-only). Dialect
messages fail closed across revisions via `CRC_EXTRA`, but `COMMAND_LONG` /
`COMMAND_INT` keep one `CRC_EXTRA` regardless of the command they carry, so a
reused id is parsed by either revision with its own meaning. A new `STORE_SAFE`
(param 2 = DISARM codeword 51.0) reaches a pre-change receiver as `STORE_ARM` with
a nonzero arm parameter: a disarm executed as an arm. Separately, the payload
operation length fields (`input_len` / `output_len`, uint8 into `uint8_t[64]`)
rely on an implied receiver clamp. Mapped findings:
[MAVLINKM-08](MAVLINKM-08_mav_cmd_id_reuse/),
[MAVLINKM-07](MAVLINKM-07_payload_op_len_overrun/).

---

## What the dialect gets right (honest negatives)

- Signing is *mandated* for every dialect message including stops, and unsigned
  dialect frames are dropped.
- Safety-critical enums use extended-Hamming codewords with an exact-match,
  no-correction receiver rule, so a bit flip into "armed" or past a consent gate
  is detectable rather than silently valid. Verified by computation: all
  twenty-two in-scope enums and the 16-bit `PAYLOAD_OPERATION_RESULT` hold minimum
  pairwise Hamming distance 4 (the gap is which enums are *in* scope, see T10).
- "Stops win over starts" with per-engagement time records, for the dialect
  messages it covers.
- The payload **catalogue** fetch has real discipline: 8 MiB / 64-profile caps
  enforced during decode, an XZ decompression bound (closing MAVSDK-03 for that
  path), a scheme allowlist with certificate validation, per-profile SHA-256 over
  exact bytes, documentation URIs never fetched, and a logical (non-path) cache
  key.
- Request IDs in the generic payload service are sound: a repeat never executes
  twice, and a third party cannot cancel another station's operation without
  forging its identity.
- CI is unusually hardened: SHA-pinned actions, no `pull_request_target` /
  `workflow_run` / `issue_comment`, read-only default token, hash-locked
  wheel-only pip, GPG-signed release tags, fork-commit rejection.

The recurring gap is the seam between the hardened dialect/catalogue core and
everything reached through common.xml or through payload-supplied JSON: T1, T2,
T3 and T5 all live on that seam.

---

## Priorities before the November 2026 freeze

1. **T1** — bind the target package by hash, allowlist the scheme, forbid raw-IP
   SSRF and bound the size; mirror the catalogue service's discipline.
   ([proposal](MAVLINKM-01_target_package_ssrf/PROPOSAL.md))
2. **T2** — add a `catalogue_sha256` to `PAYLOAD_CATALOGUE_STATUS` and check it
   first; drop the "CRC protects the file bytes" wording.
3. **T5** — extend the signing mandate to every frame of any included definition
   used on a MAVLink-M network, or at least the fetch-path and bound-command
   messages.
4. **T3** — let only the Payload Manager, not payload JSON, decide what is a stop
   or a gated action; require the GCS to show the dialect-derived type and flags.
5. **T4 / T7** — bump the pymavlink pin past #1300; add a timestamp upper bound;
   reject comment/quote-breaking sequences in dialect description text.

---

*Findings reproduced on 2026-10-28 against `mavlink-military` @ `6375c34`,
`mavlink-military-c_library_v2` @ `a957b86`, pymavlink pin `19880422`, and
`nucleo-mavlink-m-demo` @ `4860564`.*
