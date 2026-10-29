# Candidate findings

Items from the deeper review that are real but either lower-confidence, not fully
verified end-to-end, or outside the core drone→consumer message surface (supply
chain, service semantics, deployment configuration). They are filed here for
triage rather than promoted to `MAVLINKM-0N`. Each says plainly what is proven and
what is assumed.

| ID | Sev | Area | One line | State |
|---|---|---|---|---|
| [C1](C1_ci_description_text_to_code/) | 🟠 HIGH | supply chain | Dialect description text is copied unescaped into the generated C and Python; a merged PR can plant code in every integrator's build | tested by agent; current XML clean |
| [C2](C2_payload_profile_confused_deputy/) | 🟠 HIGH | service semantics | A payload's own JSON decides what counts as a stop/irreversible action, and the bound command is independent of its label → confused-deputy `DO_PARACHUTE` | schema-valid deceptive profiles built |
| [C3](C3_catalogue_schema_uniqueitems_dos/) | 🟡 MED | service DoS | A schema-valid catalogue drives the validator into O(n²) `uniqueItems` work, within every prose limit | measured (17 s / 175 s) |
| [C4](C4_c_library_repo_unprotected/) | 🟡 MED | supply chain | The published C-library repo has no branch protection and unsigned, forgeable commit identity | config, read via public API |
| [C5](C5_px4_unsigned_route_learning/) | 🟡 MED | integration | PX4 learns routes from unverified frames and `SETUP_SIGNING` has a first-mover race, against the dialect's routing requirement | code-read of PX4 main |
| [C6](C6_freetext_fields_display_sink/) | 🟡 MED | message surface | Free-text `char[]` fields (target name, callsign, nomenclature…) flow to the operator UI and logs with no "untrusted" marking | schema |

Promotion criteria: C1 and C2 are the strongest and closest to the project's
drone→consumer thesis; C3 has a measured PoC; C4/C5 depend on deployment and are
best raised as hardening notes; C6 is a surface map whose impact is
consumer-specific (the MP-03 / DRONEKIT-01 class).
