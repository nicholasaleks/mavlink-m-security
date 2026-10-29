# MAVLINKM-03 — Payload catalogue integrity is a forgeable CRC-32

| | |
|---|---|
| **Product** | MAVLink-M payload catalogue / Component Metadata service |
| **Severity** | 🟠 HIGH |
| **CWE** | 345 (insufficient verification of authenticity) / 354 (improper integrity check value) / 494 |
| **Affected** | `PAYLOAD_CATALOGUE_STATUS` (53107) `catalogue_file_crc`; `docs/en/services/payload_metadata.md` |
| **Reviewed at** | `mavlink-military` @ `6375c34` (2026-10-28), public draft |
| **Interaction** | zero-click: on catalogue download and on every revision |
| **Delivery class** | request/response (catalogue fetch), with content from the fetch path |
| **Verified** | forged catalogue with identical MAVLink CRC-32 produced and checked 2026-10-28 |
| **Status** | design-level, confirmed; fix is a schema/doc change before freeze |
| **Fix** | add `catalogue_sha256` to `PAYLOAD_CATALOGUE_STATUS`; check it first |

## Summary

A client binds the payload catalogue it downloads to the one signed message that
describes it, `PAYLOAD_CATALOGUE_STATUS`, only through `catalogue_file_crc`, a
CRC-32. Every referenced profile's SHA-256 lives *inside* the catalogue, so the
entire chain of trust reduces to that CRC-32. MAVLink's CRC-32 is linear, so an
attacker who can alter the catalogue bytes but cannot sign the status, the HTTPS
file server that hosts it, or an on-link attacker injecting unsigned FILE_TRANSFER_PROTOCOL
/ COMPONENT_METADATA frames (the fetch path is outside the signing mandate, see
[MAVLINKM-05](../MAVLINKM-05_signing_coverage_gap/)), can produce a byte-different,
schema-valid catalogue with the same CRC and redirect every profile to an attacker
host with an attacker-chosen hash.

This gives a *network or file-server* attacker the catalogue-content control that
QGC-02 and MAVSDK-01 required *vehicle* access for.

## Root cause

### The only content binding is a CRC-32

`military.xml` `PAYLOAD_CATALOGUE_STATUS` (53107):

```
<field type="uint32_t" name="catalogue_file_crc">CRC-32 of the exact catalogue file ...
   computed with MAVLink's CRC32 ...: the reflected polynomial 0x04C11DB7
   (0xEDB88320 in reflected form), initial value 0, and no final XOR.
   The check value for the ASCII string 123456789 is 0x2DFD2D88. ...</field>
```

`docs/en/services/payload_metadata.md:42` states "the catalogue CRC protects the
file bytes," and `:159` makes a CRC match the acceptance test. A CRC-32 detects
accidental corruption; it is not an integrity check against an active attacker.
The code is linear (init 0, no final XOR), so for any desired CRC an attacker
solves a small linear system over editable bytes (e.g. whitespace) to hit it.

### SHA-256 is present but covers the wrong thing

The same message carries `definition_manifest_sha256` (`uint8_t[32]`), but its
description scopes it to the schema-release manifest ("SHA-256 digest of the
definition manifest of the MAVLink-M release ... It equals the sha256 of the
catalogue's definitionManifest"). It authenticates *which schema version* the
catalogue claims, not the catalogue's entries. A forged catalogue keeps the
genuine `definitionManifest` and this field still matches.

### Per-profile hashes live inside the forgeable file

Profiles are verified by SHA-256 (`payload_metadata.md:65-68`), but those hashes
are fields *inside the catalogue*. Once the catalogue itself is forgeable, the
profile hashes are attacker-chosen, so the strong per-profile check protects
nothing above the CRC-32.

## Taint trace

```
attacker on the fetch path (HTTPS file server, or unsigned-FTP/COMPONENT_METADATA injector)
  genuine catalogue bytes  → edit entries (profile URIs, SHA-256s, labels)
                           → pad/toggle whitespace to restore catalogue_file_crc
  → client fetches forged catalogue
      CRC-32 matches signed PAYLOAD_CATALOGUE_STATUS.catalogue_file_crc   → ACCEPTED
      definition_manifest_sha256 unchanged                                → ACCEPTED
  → client fetches each profile from attacker URI, verifies against attacker SHA-256
  → attacker controls every profile's content, URIs, labels, lifecycle semantics
```

## Impact

An attacker positioned on the catalogue fetch path, without any signing key,
substitutes the catalogue a client accepts as authentic. The client then fetches
profiles from attacker-named hosts (reaching the SSRF surface of MAVSDK-01 and the
deception surface of the capability profiles) and renders attacker-chosen operation
labels and lifecycle semantics to the operator, all while the signed status message
reports the catalogue as verified.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Byte-different catalogue, same MAVLink CRC-32 | ✅ | reproduced: `0x6f6f8b8c` for both files |
| Forged catalogue is schema-valid | ✅ | reproduced: parses and validates |
| `definition_manifest_sha256` does not help | ✅ | it covers the schema manifest, not entries |
| Reaches a keyless network/file-server attacker | ✅ | fetch path is outside the signing mandate |
| Works when the vehicle itself is the attacker | ➖ | then no forgery is needed; it signs its own status |
| Breaks signing of dialect messages | ❌ | the status frame is still authentic; only its CRC referent is forgeable |

Not claimed: a break of MAVLink 2 signing. The attack is on the integrity
*referent*, a CRC-32, not the signature.

## Version scope

Present wherever `catalogue_file_crc` is the catalogue binding; present at the
reviewed draft `6375c34`. Fixable by a schema addition before the November 2026
freeze.

## Reproduction

```sh
cd poc
python3 -I verify_crc_forgery.py genuine_catalogue.json forged_catalogue.json
```

Expected:

```
genuine_catalogue.json: crc=0x6f6f8b8c bytes=11880
forged_catalogue.json: crc=0x6f6f8b8c bytes=12007
identical bytes: False
identical CRC  : True
RESULT: FORGERY CONFIRMED (different bytes, same CRC)
```

`genuine_catalogue.json` is the upstream `payloads.example.json`;
`forged_catalogue.json` is a schema-valid edit padded to the same MAVLink CRC-32.
The script implements MAVLink's CRC-32 directly (stdlib `zlib.crc32` is the wrong
parameterization: its check value for `123456789` is `0xCBF43926`, not the
`0x2DFD2D88` MAVLink specifies) and self-tests against the spec check value.

## Fix

Add `catalogue_sha256` (`uint8_t[32]`) to `PAYLOAD_CATALOGUE_STATUS`, the SHA-256
of the exact catalogue bytes, and make verifying it the first acceptance step; do
the same for the events metadata. Demote `catalogue_file_crc` to a quick
pre-download screen and strike the "CRC protects the file bytes" wording at
`payload_metadata.md:42`. The message already carries a 32-byte SHA field, so the
~32-byte addition is consistent with the existing layout.
