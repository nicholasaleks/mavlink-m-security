#!/usr/bin/env python3
"""Verify the MAVLink-M safety-enum codeword claim, and flag arming/fuze-adjacent
enums left on sequential values. Usage: python3 -I check_enum_distances.py military.xml"""
import itertools
import re
import sys
import xml.etree.ElementTree as ET

CODEBOOK = {0x00, 0x0F, 0x33, 0x3C, 0x55, 0x5A, 0x66, 0x69,
            0x96, 0x99, 0xA5, 0xAA, 0xC3, 0xCC, 0xF0, 0xFF}
INSCOPE = {
    "MAVLINK_M_ESAD_ARMING_STATUS", "MAVLINK_M_ESAD_ARMING_REQUEST",
    "MAVLINK_M_ESAD_MUNITION_STATUS", "MAVLINK_M_ESAD_IGNITION_STATUS",
    "MAVLINK_M_ESAD_PIN_STATE", "MAVLINK_M_ESAD_ARM_DELAY_SETTING",
    "MAVLINK_M_ESAD_TRIGGER_DISTANCE_MODE", "MAVLINK_M_RWS_ARMING_STATE",
    "MAVLINK_M_LM_CONSENT_STATE", "MAVLINK_M_LM_TERMINATE", "MAVLINK_M_STORE_READINESS",
    "MAVLINK_M_SENSOR_HEALTH", "MAVLINK_M_ENGAGEMENT_DIRECTIVE", "MAVLINK_M_CAS_CLEARANCE",
    "MAVLINK_M_TAC_TYPE", "ABORT_AUTHORITY", "MAVLINK_M_FIRE_MISSION_COMMAND",
    "MAVLINK_M_FIRE_CONTROL_METHOD", "DANGER_CLOSE", "MAVLINK_M_SENSOR_MODE",
    "MAVLINK_M_TASKING_STATUS", "MAVLINK_M_ACK_RESULT",
}
SAFETY = re.compile(r"arm|safe|fire|consent|terminate|releas|clear|abort|danger|"
                    r"warhead|fuze|ignit|detonat|engage|lethal", re.I)


def hd(a, b):
    return bin(a ^ b).count("1")


def dmin(vals):
    s = set(vals)
    return min((hd(a, b) for a, b in itertools.combinations(s, 2)), default=99)


root = ET.parse(sys.argv[1]).getroot()
enums = {}
for en in root.iter("enum"):
    vals = []
    for e in en.findall("entry"):
        try:
            vals.append(int(e.get("value")))
        except (TypeError, ValueError):
            pass
    enums[en.get("name")] = vals

print("in-scope (must be distance 4, codebook only):")
ok = True
for nm in sorted(INSCOPE):
    v = enums.get(nm, [])
    d = dmin(v)
    codebook_ok = all(x in CODEBOOK for x in v)
    status = "OK" if d >= 4 and codebook_ok else "FAIL"
    if status == "FAIL":
        ok = False
    print(f"  {nm:40} n={len(v):2} dmin={d} codebook={codebook_ok} {status}")
por = enums.get("PAYLOAD_OPERATION_RESULT", [])
print(f"  {'PAYLOAD_OPERATION_RESULT (16-bit)':40} n={len(por):2} dmin={dmin(por)}")
print("protected set:", "all OK" if ok else "PROBLEM")

print("\narming/fuze-adjacent enums left sequential (dmin < 4):")
for nm, v in sorted(enums.items()):
    if nm in INSCOPE or not v:
        continue
    if all(x in CODEBOOK for x in v):
        continue
    if SAFETY.search(nm) and dmin(v) < 4:
        print(f"  {nm:40} n={len(v):2} dmin={dmin(v)}")
