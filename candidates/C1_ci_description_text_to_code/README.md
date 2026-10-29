# C1 — Dialect description text becomes code in the generated C and Python

| | |
|---|---|
| **Area** | supply chain (CI generator, inherited from upstream mavgen) |
| **Severity** | 🟠 HIGH (code execution in every integrator's build) |
| **CWE** | 94 (code injection) / 1236 / 829 |
| **Affected** | `military.xml` description/param text → generated `military/*.h` and `military.py`; `check_dialect_policy.py` |
| **Reviewed at** | `mavlink-military` @ `6375c34`; pins `MAVLINK_REF=87da370c`, `PYMAVLINK_REF=19880422` |
| **State** | tested by the CI-review agent on the real `military.xml`; current XML is clean |

## Summary

mavgen copies a dialect's description, param, and deprecation text into generated
output without escaping it. In C the text goes inside comments; in Python inside
`"""..."""` docstrings. A contributor whose `military.xml` pull request is merged
(author plus one approval; no required status checks, see
[C4](../C4_c_library_repo_unprotected/) and CI review F5) can break out of the
comment or string and emit attacker-chosen C at file scope, add a hidden struct
member that silently shifts every later field, or run code at Python import. The
output is published to the C library every integrator vendors and into the
SLSA-signed release archives.

## Root cause

Upstream pymavlink at the pin:

- C: `generator/mavgen_c.py:116` (`/** @brief ${description} */`), `:121` (enum
  entry `/* ${description} |...*/`), `:181` (struct member
  `/*< ${units} ${description}*/`), `:219/253/290/363` (`@param`). None escape the
  text.
- Python: `generator/mavgen_python.py:494-518` put enum-entry and param
  descriptions into `"""%s"""` with only tab→space substitution.

The dialect schema types description as `xs:string` (`mavschema.xsd:8`), and
`check_dialect_policy.py` never inspects the text.

## What was demonstrated

Tested on the real `military.xml` with a single description changed (agent
artifacts `agent-ci/t1` C, `agent-ci/t2` Python):

- An enum-entry description containing (as XML character references) `*/`, a
  newline, `#define ...`, a `static inline` function, and `/*` emitted file-scope
  C into `military/military.h`.
- A field description `*/ uint8_t injected_member[64]; /*` added a hidden member
  to `mavlink_target_set_coord_t`; field offsets shift, so a memcpy decode misreads
  every later field.
- Both passed `xmllint --schema mavschema.xsd`, mavgen's own validation, and the
  CI compile (`-std=c11 -Wall -Wextra -Werror`). `MAVLINK_MESSAGE_CRCS` was
  byte-identical, so `CRC_EXTRA` did not change and the wire-compat check stayed
  silent.
- A Python enum-entry description `x"""); __import__(...); ("""` produced
  `military.py:419` and ran code on import (it wrote a marker file).
- XML character references (`&#42;` etc.) hide `*/`, newlines, and quotes in the
  PR diff, so a reviewer sees entity noise inside prose.

## Impact

A merged dialect change plants code in the generated C library (which integrators
submodule into flight software) and in the signed release C and Python archives,
and runs code in the CI jobs that import the generated module. Precondition: one
merged `military.xml` PR.

Not claimed: a live merge happened. Current `military.xml` contains none of these
sequences, and the published `military/` directory equals a clean regeneration at
the pins.

## Fix

In `check_dialect_policy.py`, reject description/deprecated/param text containing
`*/`, `/*`, `"""`, `\`, `{{`, `${`, or `<` followed by a letter or `/`, and reject
any `&#` character reference in the raw dialect files so the diff shows what the
generator sees. Upstream (ArduPilot/pymavlink): escape `*/` in `mavgen_c` and use
`repr()` for Python string literals. The same check also closes C2's docs-site
variant (unescaped text rendered as HTML / Vue templates on
mavlink-m.dronecode.org).
