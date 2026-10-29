# MAVLINKM-07 — Payload-operation length fields exceed their buffers; receiver clamp only implied

| | |
|---|---|
| **Product** | MAVLink-M generic payload service (`military.xml`) |
| **Severity** | 🟡 MEDIUM (parser contract) |
| **CWE** | 130 (improper handling of length) / 20 / 125 |
| **Affected** | `PAYLOAD_OPERATION_REQUEST.input_len` + `input` (53105); `PAYLOAD_OPERATION_STATUS.output_len` + `output` (53106) |
| **Reviewed at** | `mavlink-military` @ `6375c34`, public draft |
| **Interaction** | push: one operation request/status |
| **Delivery class** | push / request-response |
| **Status** | schema design; consumer-dependent sink |

## Summary

The generic payload operation carries a variable-length blob as a `uint8_t[64]`
array plus a separate `uint8_t` length field. The length field holds 0-255 while
the buffer is 64 bytes, and the dialect states the bound as a sender rule ("Must
not exceed 64") and tells the receiver it "ignores the remainder," without
mandating that a receiver reject a length greater than 64. A consumer that copies
or iterates `input_len` bytes from the 64-byte array, the natural reading, reads
64-191 bytes out of bounds. This is the QGC-01 / MAVROS-02 "trust the peer's
length field" pattern.

## Root cause

`military.xml`, `PAYLOAD_OPERATION_REQUEST` (53105):

```
<field type="uint8_t"    name="input_len"> Number of bytes of input in use, starting at index 0. Must not exceed 64. ... </field>
<field type="uint8_t[64]" name="input">    ... Only the first input_len bytes are defined; the receiver ignores the remainder and the sender is not required to zero it. </field>
```

`PAYLOAD_OPERATION_STATUS` (53106) is identical with `output_len` and
`output[64]`. `input_len` and `output_len` are `uint8_t`, so a sender (or a fault)
can set them to any value up to 255. The array is fixed at 64. The description
frames the limit as the sender's obligation and describes receiver behavior only
for the in-bounds case ("ignores the remainder"); `docs/en/services/generic_payload.md`
states receivers "match the complete value, reject an unknown operation" for
enums but gives no "reject `input_len > 64`" rule for these length fields.

A conforming receiver that reads `input[0 .. input_len)` to deserialize the
RFC 8785 JSON value, exactly what the field is for, indexes past the 64-byte
array for any length in 65-255.

## Taint trace

```
PAYLOAD_OPERATION_REQUEST.input_len  (uint8, sender-chosen 0-255)
PAYLOAD_OPERATION_REQUEST.input      (uint8_t[64], fixed)
  → consumer deserializes input[0 .. input_len)
      input_len <= 64 : in bounds
      input_len 65..255 : out-of-bounds read of 1..191 bytes past the struct field
  (same for PAYLOAD_OPERATION_STATUS.output_len / output on the GCS side)
```

## Impact

A consumer of a payload operation request or status that trusts the length field
reads beyond the fixed buffer: an out-of-bounds read of up to 191 bytes, feeding
a crash or disclosure depending on what follows the field in the decoded struct.
The direction cuts both ways: `input_len` reaches the Payload Manager (a drone-side
consumer), and `output_len` reaches the GCS in the status reply.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Length field can exceed the buffer | ✅ | `uint8_t` (0-255) vs `uint8_t[64]` |
| Spec frames the bound as a sender rule | ✅ | "Must not exceed 64" on the length field |
| Spec mandates receiver rejection of `len > 64` | ❌ | only "ignores the remainder" (in-bounds case) |
| OOB in a consumer that trusts the length | ⚠️ | consumer-dependent; the contract invites it |
| Reachable past signing | ⚠️ | the operation request is a dialect message (signed); a compromised/keyed sender is the threat, and per [MAVLINKM-05](../MAVLINKM-05_signing_coverage_gap/) parts of the service are reachable unsigned |

Not claimed: a specific consumer crashed. The finding is that the wire contract
permits a length past the buffer and leaves the clamp implicit.

## Version scope

Present at the reviewed draft `6375c34`, in both 53105 and 53106.

## Reproduction

Schema reading: the `uint8_t` length field against the `uint8_t[64]` array in
`military.xml` 53105/53106, and the absence of a receiver-side rejection rule in
`docs/en/services/generic_payload.md`. A consumer PoC would decode a frame with
`input_len = 255` and observe the over-read; it is not built here because the sink
is the consumer's deserializer, not specified by the dialect.

## Fix

Add a normative receiver rule to `generic_payload.md`: a receiver rejects a
`PAYLOAD_OPERATION_REQUEST` whose `input_len > 64` (and a client ignores a
`PAYLOAD_OPERATION_STATUS` whose `output_len > 64`), answering
`PAYLOAD_OPERATION_RESULT` appropriately, before reading `input`/`output`. State
it next to the existing enum exact-match rule so integrators apply the same
discipline to the length fields.
