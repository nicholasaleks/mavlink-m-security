# Upstream proposal — bind and bound TARGET package retrieval

For `military.xml` `TARGET` (53010) and the `match_media_url` leg of
`TARGET_HANDOVER` (53002), before the November 2026 freeze. The goal is to give
the package-retrieval fields the same discipline the payload catalogue service
already has (`docs/en/services/payload_metadata.md:106-150`), so a conforming
consumer is not routed into an SSRF / traversal / unverified-fetch sink.

The dialect does not implement fetching, so the fix is partly schema (fields that
make a safe implementation expressible and a hash binding mandatory) and partly
normative receiver text in the `military.xml` header and the service docs.

## 1. Mandate a real integrity binding

`package_id_hash` (uint32) cannot bind content. Replace or supplement it:

- Add `package_sha256` (`uint8_t[32]`) as a message extension, the SHA-256 of the
  exact package bytes, computed by the *authority that created the target*, not by
  whatever host serves the file.
- A consumer rejects a retrieved package whose SHA-256 does not match, and
  retrieves nothing when the field is absent (all-zero) unless an application
  profile explicitly allows unverified packages on a closed network.
- Keep `package_id_hash` only as a non-security correlation/cache key, and say so
  in its description.

This mirrors the per-profile SHA-256 the catalogue service already requires
(`payload_metadata.md:65-68`) and closes the "attacker serves its own bytes and
its own hash" gap.

## 2. Constrain the endpoint (no raw-IP SSRF, no cleartext)

Add normative receiver text (header `FIELD CONVENTIONS` or a new
`EXTERNAL RETRIEVAL` section):

- A consumer resolves a target package only when `package_transport` is HTTPS.
  Remove `..._HTTP` from `MAVLINK_M_TARGET_PACKAGE_TRANSPORT`, or mark it
  reserved/forbidden for retrieval.
- A consumer rejects, before any connection, an endpoint that is a loopback,
  link-local (including `169.254.0.0/16`), or otherwise non-routable address, and
  resolves packages only to hosts an application profile or local policy allows.
  Raw-IP endpoints are permitted only within a configured package-server range.
- A consumer bounds the retrieved size (profile-defined, with a specified
  default) and fails closed when exceeded, as the catalogue download does
  (`payload_metadata.md:106-131`).

## 3. Constrain `package_path`

- State that `package_path` is a URL path component only, used solely to form the
  request to the already-validated endpoint, and is never used to construct a
  local filesystem path.
- A consumer rejects a `package_path` containing `..`, a NUL, or (after
  percent-decoding) `%2F`, `%5C`, or `\`.
- The local store names the package by a logical key (e.g. `package_sha256`), not
  by `package_path`, as the catalogue cache key is logical
  (`payload_metadata.md:319`).

## 4. Same treatment for `match_media_url`

- A consumer never fetches `match_media_url` during message handling or display
  unless an application profile opts in; by default it is a display reference
  only, exactly as the catalogue's documentation URIs are "never fetched"
  (`payload_metadata.md:144`).
- When a profile does opt in, the HTTPS-only, host-policy and size-bound rules of
  §2 apply, and the media is bound by a hash carried alongside it.

## 5. State the trust boundary

Add one line to the header SAFETY BOUNDARIES: the target package and any match
media are retrieved over a transport **outside** the MAVLink signing boundary, so
their authenticity rests entirely on the §1 hash, which a receiver must verify;
signing of the `TARGET` message authenticates the *reference*, not the *content*.

## Minimal-diff option

If a schema change is too large this late in the draft, the smallest safe change
is: (a) add `package_sha256` as an extension and require verification, and (b)
add the §2-§4 receiver rules as normative text without new fields, since they
constrain consumer behavior rather than the wire format. That keeps CRC_EXTRA
stable for existing `TARGET` senders while closing the fetch sink.
