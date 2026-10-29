#!/usr/bin/env python3
"""Confirm that a catalogue bound to a signed PAYLOAD_CATALOGUE_STATUS only by
its catalogue_file_crc (a CRC-32) can be forged: a byte-different, schema-valid
catalogue with the same MAVLink CRC-32 as the genuine one.

Usage: python3 -I verify_crc_forgery.py <genuine.json> <forged.json>
MAVLink CRC-32: reflected poly 0xEDB88320, init 0, no final XOR
(https://mavlink.io/en/guide/crc.html). Check value for b"123456789" is 0x2DFD2D88.
"""
import json
import sys


def mavlink_crc32(data, crc=0):
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1))
            crc &= 0xFFFFFFFF
    return crc


assert mavlink_crc32(b"123456789") == 0x2DFD2D88

a, b = sys.argv[1], sys.argv[2]
ba, bb = open(a, "rb").read(), open(b, "rb").read()
json.loads(ba); json.loads(bb)  # both must be valid JSON
ca, cb = mavlink_crc32(ba), mavlink_crc32(bb)
print(f"{a}: crc={ca:#010x} bytes={len(ba)}")
print(f"{b}: crc={cb:#010x} bytes={len(bb)}")
print("identical bytes:", ba == bb)
print("identical CRC  :", ca == cb)
print("RESULT:", "FORGERY CONFIRMED (different bytes, same CRC)"
      if ca == cb and ba != bb else "not a forgery")
