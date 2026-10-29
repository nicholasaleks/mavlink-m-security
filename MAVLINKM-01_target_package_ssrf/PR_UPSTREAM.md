# Upstream PR — staged, awaiting your review

The change is **staged but not committed** in a working clone:

- **Repo:** `/Users/nick/Projects/mavlink-military` (clone of `Dronecode/mavlink-military`)
- **Branch:** `harden-target-package-retrieval` (off `main` @ `6375c34`)
- **Staged:** `military.xml` (28 insertions, 3 deletions) — review with `git -C /Users/nick/Projects/mavlink-military diff --cached`

To finish it yourself:

```sh
cd /Users/nick/Projects/mavlink-military
git diff --cached                      # review
git commit                             # your sign-off / DCO per CONTRIBUTING.md
git remote add fork git@github.com:<you>/mavlink-military.git
git push -u fork harden-target-package-retrieval
# then open the PR against Dronecode/mavlink-military
```

I did not commit, add a Co-Authored-By line, or touch your git identity.

---

## What the change does

Implements the minimal-diff option from [PROPOSAL.md](PROPOSAL.md) for
[MAVLINKM-01](README.md), entirely in `military.xml`:

1. **Adds `package_sha256` (`uint8_t[32]`) as a TARGET extension field** — a real
   integrity binding the sender's host cannot forge, verified before the package is
   used. `package_id_hash` is demoted to a correlation/cache key in its role.
2. **Adds an `EXTERNAL TARGET PACKAGE RETRIEVAL` section** to the header
   (normative for implementers), stating: verify `package_sha256` first; retrieve
   only over HTTPS; reject non-routable/loopback/link-local endpoints and resolve
   only to allowed hosts; bound the size; treat `package_path` as a URL path only,
   never a local path, and reject `..`, NUL, `%2F`, `%5C`. The same rules extend to
   `match_media_url`.
3. **Points the `package_endpoint_ip_1`, `package_transport`, and `package_path`
   field descriptions** at that section, where consumers read them.

It is scoped to `military.xml` (the normative source). A `docs/en/services/` page
can follow; flagged in the PR body below.

## Backward compatibility (verified)

`package_sha256` is an **extension** field, so it is excluded from `CRC_EXTRA` and
old senders/receivers interoperate unchanged. Confirmed by generating Python
bindings from `main` and from this branch (pymavlink, pinned common.xml) and
comparing:

```
TARGET crc_extra: orig 71  edit 71  -> SAME
new field only in edit: {'package_sha256'}
all 270 messages' CRC_EXTRA identical: True
```

XML is well-formed (`xmllint --noout`).

## Suggested PR title and body

**Title:** `TARGET: bind the external package by hash and constrain its retrieval`

**Body:**

> TARGET (53010) carries a sender-chosen IPv4 endpoint, port, transport, and path
> for a consumer to fetch an externally hosted target package, with only a 32-bit
> `package_id_hash` — supplied by the same sender — as integrity. A conforming
> consumer is therefore steered to a sender-named host (SSRF, including internal and
> link-local addresses), accepts attacker bytes as the package, and may use
> `package_path` as a local path (traversal). Message signing authenticates the
> reference, not the package, which is fetched outside the signing boundary.
>
> This mirrors the discipline the payload catalogue service already applies
> (size caps, scheme allowlist, per-object SHA-256, "documentation URIs are never
> fetched"):
>
> - adds `package_sha256` as a TARGET extension (CRC_EXTRA unchanged; verified), to
>   be checked before the package is used;
> - adds normative retrieval rules (HTTPS-only, host policy, size bound, path
>   handling) in a new header section, referenced from the package fields;
> - extends the same handling to `match_media_url`.
>
> Raised against the November draft freeze. A follow-up can add a
> `docs/en/services/` page; this PR keeps the change in the normative `military.xml`.
