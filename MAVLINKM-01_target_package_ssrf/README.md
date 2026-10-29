# MAVLINKM-01 — TARGET package retrieval is SSRF + path traversal by design

| | |
|---|---|
| **Product** | MAVLink-M (Dronecode military MAVLink 2 dialect) |
| **Severity** | 🟠 HIGH (schema design gap) |
| **CWE** | 918 (SSRF) / 22 (path traversal) / 494 (download of code without integrity check) / 770 |
| **Affected** | `military.xml` `TARGET` (53010); the `match_media_url` leg of `TARGET_HANDOVER` (53002) |
| **Reviewed at** | `mavlink-military` @ `6375c34` (2026-10-28), public draft |
| **Interaction** | zero-click: a `TARGET` arriving at a consumer that resolves the package |
| **Delivery class** | push (the message carries the endpoint; no handshake) |
| **Verified** | ✅ end-to-end: a packed TARGET drives a spec-faithful consumer to GET an internal endpoint and exfiltrate its contents ([poc/](poc/)) |
| **Status** | schema design gap; mechanism reproduced against a reference consumer, no shipped GCS tested |
| **Fix** | upstream proposal in [PROPOSAL.md](PROPOSAL.md) |

## Summary

`TARGET` carries, entirely from the sender, the network location and path a
consumer uses to fetch an "externally hosted target package": three raw IPv4
endpoints, a TCP port, a transport enum whose listed values include cleartext
HTTP, and an 80-byte path. A consumer that implements the field as described
connects out to a sender-named host and retrieves a sender-named path. The only
integrity field is a 32-bit `package_id_hash`, which the same sender supplies.

The sender is any system that can emit a signed `TARGET`: a compromised payload
whose message the FMU relays, or a compromised-but-keyed aircraft (the shared-key
model of MAVLink-M's SAFETY BOUNDARIES). The consumer is the GCS or a peer
system taking a handover. This is the QGC-02 / MAVSDK-01 SSRF and the MAVSDK-02 /
QGC-03 traversal patterns, specified in the schema rather than introduced by an
implementation.

## Root cause

### The endpoint is sender-controlled and unvalidated

`military.xml`, `TARGET` (53010):

```
1855  <field type="uint32_t" name="package_endpoint_ip_1"> Primary IPv4 endpoint address for target package retrieval, packed as (a<<24)|(b<<16)|(c<<8)|d ... </field>
1856  <field type="uint32_t" name="package_endpoint_ip_2"> Secondary IPv4 endpoint address for target package retrieval ... </field>
1857  <field type="uint32_t" name="package_endpoint_ip_3"> Third IPv4 endpoint address for target package retrieval ... </field>
1863  <field type="uint16_t" name="package_endpoint_port"> TCP port for target package retrieval. 0 if no package is associated. </field>
1865  <field type="uint8_t"  name="package_transport" enum="MAVLINK_M_TARGET_PACKAGE_TRANSPORT"> Transport protocol used to retrieve the target package. </field>
1866  <field type="char[80]" name="package_path">       Path component for target package retrieval, null-terminated. Empty if no package is associated. </field>
```

The transport enum admits cleartext HTTP (`military.xml:601-606`):

```
<enum name="MAVLINK_M_TARGET_PACKAGE_TRANSPORT">
  <entry value="1" name="..._HTTP">  HTTP target package transport.  </entry>
  <entry value="2" name="..._HTTPS"> HTTPS target package transport. </entry>
</enum>
```

A raw IPv4 address field is an SSRF primitive: the sender, not the consumer's
configuration, names the host the consumer dials. There is no host restriction
(loopback, link-local `169.254.169.254`, RFC1918), no scheme allowlist beyond
"HTTP or HTTPS," and no bound on the retrieved size.

### No integrity binding

```
1838  <field type="uint32_t" name="package_id_hash"> Compact hash or identifier for the associated target package. 0 if no package is associated. </field>
```

`package_id_hash` is 32 bits and described as a "compact hash or identifier." It
is supplied by the same sender that names the endpoint, so it binds nothing: a
malicious sender serves its own package and the matching hash. The
`MAVLINK_M_TARGET_FLAG_INTEGRITY_PRESENT` flag (`military.xml:617`) asserts that
the package "contains integrity material" but no scheme, key, or verification
step is specified.

### `package_path` is an unconstrained path

`char[80]`, "path component for target package retrieval," with no statement that
`..`, `%2F`, `%5C`, `\` or NUL are rejected, and no rule against building a local
filesystem path from it. A consumer that caches the package by its path reaches
the MAVSDK-02 / QGC-03 traversal-write class.

### The dialect validates this nowhere

There is no counterpart to the payload catalogue service's fetch discipline
(`docs/en/services/payload_metadata.md:106-150`: size caps, scheme allowlist,
certificate validation, "documentation URIs are never fetched"). The TARGET
package path has no size cap, no allowlist, no host policy, and no "validate
before I/O" rule in `military.xml` or in any doc.

### `match_media_url` is the same shape

`TARGET_HANDOVER` (53002) and the match record carry a sender-controlled URL
(`military.xml:1958`):

```
<field type="char[50]" name="match_media_url"> Short URL referencing matching media asset (null-terminated). </field>
<field type="uint8_t"  name="match_media_type" enum="MAVLINK_M_MATCH_MEDIA_TYPE"> Type of matching media referenced by match_media_url. </field>
```

A consumer that prefetches or renders handover media follows a sender-named URL —
the same fetch sink, with `match_media_type` telling it the asset is imagery or
video and likely to be auto-rendered.

## Taint trace

```
compromised payload / keyed peer
  → signed TARGET (53010)
      package_endpoint_ip_{1,2,3}  ─┐
      package_endpoint_port         ├─ consumer builds a URL from sender data
      package_transport (HTTP ok)   │
      package_path (char[80])      ─┘
  → consumer HTTP(S) client  →  GET http://<attacker-ip>:<port>/<attacker-path>
        ├─ SSRF: internal/loopback/link-local host on the GCS or C2 LAN
        ├─ no size cap: unbounded response (disk / memory)
        └─ package_path → local cache path → traversal write
  → package_id_hash (uint32, sender-supplied) "verifies" the attacker's own bytes
```

## Impact

A consumer that resolves the target package can be driven to issue an outbound
request to any host and port the sender chooses, including services only reachable
from the operator's workstation or the C2 LAN, over cleartext HTTP if the sender
selects it. The retrieved bytes are integrity-checked only against a value the
sender also chose, so the consumer treats attacker content as the authoritative
target package. Where the consumer stores the package by `package_path`, the path
is an unconstrained write location.

### Bounding it

| Claim | Holds? | Why |
|---|---|---|
| Sender names the outbound host | ✅ | raw IPv4 fields, no consumer-side allowlist in the spec |
| Reaches internal/loopback services | ✅ | no host restriction specified |
| Cleartext on the wire | ✅ | HTTP is a listed transport value |
| Attacker content accepted as the package | ✅ | only integrity is a sender-supplied uint32 |
| Traversal write via `package_path` | ⚠️ | consumer-dependent; spec neither forbids nor sanitizes it |
| Memory/RCE in the consumer | ⚠️ | consumer-dependent; the dialect supplies the primitive, not the sink |
| Blocked by message signing | ❌ | `TARGET` is signed, and a keyed/compromised sender is the threat; the fetch is off-link and unauthenticated |

Not claimed: a specific shipped GCS was driven end-to-end. This is a schema
design gap; the finding is that a conforming consumer is routed into the sink.

## Version scope

Present since the package-retrieval fields were added to `TARGET`; present at the
reviewed draft `6375c34`. Because layouts freeze in November 2026, a schema change
is in scope now and out of scope after the freeze without a breaking revision.

## Reproduction

[poc/ssrf_e2e.py](poc/ssrf_e2e.py) demonstrates it end-to-end, entirely on
`127.0.0.1`:

```sh
cd poc
pip install pymavlink          # military_dialect.py is committed; regenerate with generate_dialect.sh
python3 -I ssrf_e2e.py
```

Expected:

```
internal service (should be unreachable by the drone) on 127.0.0.1:NNNNN
malicious TARGET frame: 198 bytes, from sysid 42
  consumer builds URL from TARGET fields: http://127.0.0.1:NNNNN/latest/meta-data/secret
internal service was reached by the consumer: [('127.0.0.1', '/latest/meta-data/secret')]
consumer exfiltrated: 'INTERNAL-ONLY: ...'
RESULT: SSRF CONFIRMED — the TARGET sender chose the consumer's outbound request
```

The PoC builds a real TARGET message, packs it, and hands the frame to
`consume_target()`, which implements the package-retrieval fields exactly as
`military.xml` describes them (IPv4 endpoint unpacked as `(a<<24)|(b<<16)|(c<<8)|d`,
`package_transport` → scheme, `package_path` as the request path) and performs the
GET. The consumer is a faithful reference, not a shipped GCS: it shows that a
conforming implementation is routed to a sender-chosen host, port, and path. The
`package_path` traversal and the unverified `package_id_hash` are read directly
from the schema (`military.xml` fields at 1855-1866, enum at 601-606, hash at
1838); no validation rule for these fields exists in `military.xml` or
`docs/en/services/`.

The upstream fix proposal is in [PROPOSAL.md](PROPOSAL.md).
