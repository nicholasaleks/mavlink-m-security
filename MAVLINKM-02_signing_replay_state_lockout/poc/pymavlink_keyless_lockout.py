"""pymavlink signing: a frame with a BAD signature still advances the replay
timestamp of the (link_id, sysid, compid) stream it claims to come from.

Bench-only, in-process: one signed sender (the "GCS", sysid 255), one signed
receiver (sysid 1), and an attacker who does NOT know the key. No sockets.

Expected (MAVLink-M SAFETY BOUNDARIES): "A frame that fails the signature
check changes no replay state, so a forgery cannot lock a sender out."
"""
import os
import time

from pymavlink.dialects.v20 import common as mav

KEY = os.urandom(32)
EPOCH_2015 = 1420070400


def now_ts():
    # MAVLink signing timestamp: 10 us units since 2015-01-01
    return int((time.time() - EPOCH_2015) * 100000)


def signed_endpoint(sysid, compid, key):
    m = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.robust_parsing = True
    m.signing.secret_key = key
    m.signing.link_id = 0
    m.signing.timestamp = now_ts()
    m.signing.sign_outgoing = True
    return m


gcs = signed_endpoint(255, 190, KEY)
rx = signed_endpoint(1, 1, KEY)


def gcs_frame():
    msg = mav.MAVLink_heartbeat_message(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0, 3)
    return bytearray(msg.pack(gcs))


def deliver(buf, label):
    try:
        msgs = rx.parse_buffer(bytes(buf)) or []
        ok = any(m.get_type() == "HEARTBEAT" for m in msgs)
    except mav.MAVError as e:
        ok = False
        msgs = [str(e)]
    print(f"  {label:<44} -> {'ACCEPTED' if ok else 'DROPPED'}"
          f"   (goodsig={rx.signing.goodsig_count} badsig={rx.signing.badsig_count})")
    return ok


print("1. genuine signed frames from the GCS")
for i in range(2):
    deliver(gcs_frame(), f"GCS heartbeat #{i + 1}")

print("2. attacker WITHOUT the key: copy a GCS frame header, set timestamp to 2^48-1")
forged = gcs_frame()
# signature block = link_id(1) | timestamp(6) | signature(6), at the end of the frame.
# The frame CRC does not cover it, so the frame still parses; only the signature is now wrong.
forged[-12:-6] = b"\xff" * 6
deliver(forged, "forged frame (bad signature)")
key_tuple = (0, 255, 190)
print(f"  receiver replay state for stream {key_tuple}: {rx.signing.stream_timestamps.get(key_tuple)}"
      f"  (2^48-1 = {2**48 - 1})")

print("3. genuine signed frames from the GCS afterwards")
ok_after = [deliver(gcs_frame(), f"GCS heartbeat #{i + 3}") for i in range(3)]

print()
print("RESULT:", "VULNERABLE: keyless lockout of a signed sender" if not any(ok_after)
      else "not reproduced")
