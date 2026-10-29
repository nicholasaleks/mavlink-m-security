// Host harness for nucleo_mavlink_m.ino. Built twice:
//   -I ../vendored  : firmware exactly as committed (headers from Jul 2026 spec)
//   -I ../regen     : same .ino, headers regenerated from current military.xml
//                     (the SETUP.md "regenerate if military.xml changes" step)
#include "arduino_stub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <random>

uint32_t g_fake_micros = 0;
int g_led = 0;
HardwareSerial Serial;

#include "nucleo_mavlink_m.ino"

#if MAVLINK_MSG_ID_ESAD_ARMING_CRC == 153
#define VARIANT "vendored (ESAD_ARMING CRC_EXTRA 153, sequential enums)"
#define SPEC_ARM 1
#define SPEC_DISARM 0
#else
#define VARIANT "regen (ESAD_ARMING CRC_EXTRA 3, Hamming codewords)"
#define SPEC_ARM 15
#define SPEC_DISARM 51
#endif

static uint16_t build_arming(uint8_t *buf, uint8_t sysid, uint8_t compid, uint64_t t,
			     uint8_t esad_id, uint32_t hash, uint8_t req, uint8_t store,
			     bool sign = false, bool corrupt_sig = false)
{
	mavlink_message_t m;
	mavlink_status_t st;
	memset(&st, 0, sizeof(st));
	mavlink_signing_t sg;
	memset(&sg, 0, sizeof(sg));
	if (sign) {
		for (int i = 0; i < 32; i++) sg.secret_key[i] = (uint8_t)(0xA5 ^ i); // a key the ESAD never saw
		sg.flags = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;
		sg.timestamp = 1;
		st.signing = &sg;
	}
#if MAVLINK_MSG_ID_ESAD_ARMING_CRC == 153
	mavlink_msg_esad_arming_pack_status(sysid, compid, &st, &m, t, esad_id, hash, req, store);
#else
	uint8_t uid[16] = {0};
	mavlink_msg_esad_arming_pack_status(sysid, compid, &st, &m, t, 2, 190, esad_id, hash, req, store, uid);
#endif
	uint16_t n = mavlink_msg_to_send_buffer(buf, &m);
	if (sign && corrupt_sig) {
		for (int i = n - 6; i < n; i++) buf[i] ^= 0xFF; // trash the 48-bit signature
	}
	return n;
}

// Parse what the firmware transmitted; return last ESAD_STATE.arming_status or -1.
static int last_tx_arming_status(Stream &s, int *n_state)
{
	mavlink_message_t rx, out;
	mavlink_status_t st, rst;
	memset(&rx, 0, sizeof(rx)); memset(&st, 0, sizeof(st));
	int last = -1; int cnt = 0;
	for (uint8_t c : s.tx) {
		if (mavlink_frame_char_buffer(&rx, &st, c, &out, &rst) == MAVLINK_FRAMING_OK &&
		    out.msgid == MAVLINK_MSG_ID_ESAD_STATE) {
			last = mavlink_msg_esad_state_get_arming_status(&out);
			cnt++;
		}
	}
	if (n_state) *n_state = cnt;
	s.tx.clear();
	return last;
}

static void reset_state(uint8_t st) { g_arming_status = st; FCLink.tx.clear(); USBLink.tx.clear(); }

static uint8_t deliver(Stream &link, const uint8_t *b, uint16_t n)
{
	link.feed(b, n);
	loop();
	return g_arming_status;
}

static int popcount8(uint8_t x) { return __builtin_popcount(x); }

static void test_sweep()
{
	uint8_t buf[MAVLINK_MAX_PACKET_LEN];
	int arms_from_disarmed = 0, disarms_from_armed = 0;
	printf("[sweep] %s\n", VARIANT);
	printf("[sweep] firmware ARMED status value = %d, DISARMED = %d\n",
	       MAVLINK_M_ESAD_ARMING_ARMED, MAVLINK_M_ESAD_ARMING_DISARMED);
	printf("[sweep] arming_request values that ARM a disarmed ESAD: ");
	for (int v = 0; v < 256; v++) {
		reset_state(MAVLINK_M_ESAD_ARMING_DISARMED);
		uint16_t n = build_arming(buf, 255, 190, 1000, 1, 0xDEADBEEF, (uint8_t)v, 0);
		if (deliver(FCLink, buf, n) == MAVLINK_M_ESAD_ARMING_ARMED) arms_from_disarmed++;
	}
	printf("%d/256\n", arms_from_disarmed);
	printf("[sweep] arming_request values that DISARM an armed ESAD: ");
	for (int v = 0; v < 256; v++) {
		reset_state(MAVLINK_M_ESAD_ARMING_ARMED);
		uint16_t n = build_arming(buf, 255, 190, 1000, 1, 0xDEADBEEF, (uint8_t)v, 0);
		if (deliver(FCLink, buf, n) == MAVLINK_M_ESAD_ARMING_DISARMED) { disarms_from_armed++; printf("%d ", v); }
	}
	printf("(%d/256)\n", disarms_from_armed);

	// The named spec values for this header generation.
	for (int pass = 0; pass < 2; pass++) {
		uint8_t req = pass ? SPEC_DISARM : SPEC_ARM;
		reset_state(pass ? MAVLINK_M_ESAD_ARMING_ARMED : MAVLINK_M_ESAD_ARMING_DISARMED);
		uint16_t n = build_arming(buf, 255, 190, 1000, 1, 0xDEADBEEF, req, 0);
		uint8_t r = deliver(FCLink, buf, n);
		int ns; int tx = last_tx_arming_status(FCLink, &ns);
		printf("[named] start=%s send %s (%u) -> g_arming_status=%u (%s), LED=%d, ESAD_STATE.arming_status=%d\n",
		       pass ? "ARMED" : "DISARMED", pass ? "MAVLINK_M_ESAD_REQUEST_DISARM" : "MAVLINK_M_ESAD_REQUEST_ARM",
		       req, r, r == MAVLINK_M_ESAD_ARMING_ARMED ? "ARMED" : "DISARMED", g_led, tx);
	}

	// 1-3 bit corruptions of the DISARM codeword: how many arm?
	int tot = 0, armed = 0;
	for (int v = 0; v < 256; v++) {
		int d = popcount8((uint8_t)v ^ SPEC_DISARM);
		if (d < 1 || d > 3) continue;
		tot++;
		reset_state(MAVLINK_M_ESAD_ARMING_ARMED);
		uint16_t n = build_arming(buf, 255, 190, 1000, 1, 0xDEADBEEF, (uint8_t)v, 0);
		if (deliver(FCLink, buf, n) == MAVLINK_M_ESAD_ARMING_ARMED) armed++;
	}
	printf("[bitflip] DISARM codeword %d with 1-3 bits changed: %d/%d leave/turn the ESAD ARMED (spec: refuse all, record as stop)\n",
	       SPEC_DISARM, armed, tot);
}

static void test_authz()
{
	uint8_t buf[MAVLINK_MAX_PACKET_LEN];
	uint16_t n;
	struct { const char *name; uint8_t sys, comp; uint64_t t; uint8_t esad, store; uint32_t hash; bool sign, bad; Stream *link; } cases[] = {
		{"unsigned, sysid 255 via FC link",              255, 190, 1000, 1, 0,   0xDEADBEEF, false, false, &FCLink},
		{"unsigned, arbitrary sysid 77/comp 1",           77,   1, 1000, 1, 0,   0x00000000, false, false, &FCLink},
		{"signed with unknown key",                      255, 190, 1000, 1, 0,   0x11111111, true,  false, &FCLink},
		{"signed, signature bytes trashed",              255, 190, 1000, 1, 0,   0x22222222, true,  true,  &FCLink},
		{"ARM with esad_id=0 (spec: reject)",            255, 190, 1000, 0, 0,   0x33333333, false, false, &FCLink},
		{"ARM with store_id=200 (no such store)",        255, 190, 1000, 1, 200, 0x44444444, false, false, &FCLink},
		{"ARM with time_usec=0",                         255, 190, 0,    1, 0,   0x55555555, false, false, &FCLink},
		{"ARM with time_usec=UINT64_MAX (far future)",   255, 190, UINT64_MAX, 1, 0, 0x66666666, false, false, &FCLink},
		{"ARM via USB VCP link (bypasses PX4)",          255, 190, 1000, 1, 0,   0x77777777, false, false, &USBLink},
	};
	for (auto &c : cases) {
		reset_state(MAVLINK_M_ESAD_ARMING_DISARMED);
		n = build_arming(buf, c.sys, c.comp, c.t, c.esad, c.hash, SPEC_ARM, c.store, c.sign, c.bad);
		uint8_t r = deliver(*c.link, buf, n);
		printf("[authz] %-45s frame_len=%3u incompat=0x%02x -> %s\n", c.name, n, buf[2],
		       r == MAVLINK_M_ESAD_ARMING_ARMED ? "ARMED (accepted)" : "not armed");
	}

	// Stop-wins-over-starts: DISARM at t=2000, then an ARM issued earlier (t=1000).
	reset_state(MAVLINK_M_ESAD_ARMING_ARMED);
	n = build_arming(buf, 255, 190, 2000, 1, 0, SPEC_DISARM, 0);
	deliver(FCLink, buf, n);
	n = build_arming(buf, 255, 190, 1000, 1, 0, SPEC_ARM, 0);
	uint8_t r = deliver(FCLink, buf, n);
	printf("[stopwins] DISARM(t=2000) then stale ARM(t=1000): %s\n",
	       r == MAVLINK_M_ESAD_ARMING_ARMED ? "ARMED (stale start overrides stop)" : "held");

	// Exact replay of a captured ARM frame after a DISARM.
	reset_state(MAVLINK_M_ESAD_ARMING_DISARMED);
	uint8_t cap[MAVLINK_MAX_PACKET_LEN];
	uint16_t capn = build_arming(cap, 255, 190, 5000, 1, 0xABCD, SPEC_ARM, 0);
	deliver(FCLink, cap, capn);
	n = build_arming(buf, 255, 190, 6000, 1, 0, SPEC_DISARM, 0);
	deliver(FCLink, buf, n);
	r = deliver(FCLink, cap, capn);
	printf("[replay] byte-identical replay of earlier ARM after DISARM: %s\n",
	       r == MAVLINK_M_ESAD_ARMING_ARMED ? "ARMED" : "not armed");

	// Does the firmware ever emit MAVLINK_M_ACK?
	int acks = 0;
	{
		mavlink_message_t rx, out; mavlink_status_t st, rst;
		memset(&rx, 0, sizeof(rx)); memset(&st, 0, sizeof(st));
		reset_state(MAVLINK_M_ESAD_ARMING_DISARMED);
		for (int v = 0; v < 256; v++) { n = build_arming(buf, 255, 190, 1000, 1, 0, (uint8_t)v, 0); deliver(FCLink, buf, n); }
		for (uint8_t c : FCLink.tx)
			if (mavlink_frame_char_buffer(&rx, &st, c, &out, &rst) == MAVLINK_FRAMING_OK && out.msgid == MAVLINK_MSG_ID_MAVLINK_M_ACK) acks++;
	}
	printf("[ack] MAVLINK_M_ACK frames emitted for 256 ESAD_ARMING requests (incl. unlisted values): %d\n", acks);
}

// Craft an ESAD_ARMING frame in the CURRENT spec layout (CRC_EXTRA 3, 33-byte payload)
// and feed it to whichever firmware variant this is.
static void test_cross_version()
{
	uint8_t p[33] = {0};
	uint64_t t = 1000; memcpy(p, &t, 8);
	uint32_t h = 0; memcpy(p + 8, &h, 4);
	p[12] = 2; p[13] = 190; p[14] = 1; p[15] = 51 /* DISARM codeword */; p[16] = 0;
	uint8_t len = 33; while (len > 1 && p[len - 1] == 0) len--;
	uint8_t f[300]; int i = 0;
	f[i++] = 0xFD; f[i++] = len; f[i++] = 0; f[i++] = 0; f[i++] = 0; f[i++] = 255; f[i++] = 190;
	f[i++] = 53031 & 0xFF; f[i++] = (53031 >> 8) & 0xFF; f[i++] = (53031 >> 16) & 0xFF;
	memcpy(f + i, p, len); i += len;
	uint16_t crc = crc_calculate(f + 1, i - 1); crc_accumulate(3, &crc);
	f[i++] = crc & 0xFF; f[i++] = crc >> 8;
	reset_state(MAVLINK_M_ESAD_ARMING_ARMED);
	uint32_t before = mavlink_get_channel_status(MAVLINK_COMM_0)->packet_rx_success_count;
	deliver(FCLink, f, i);
	uint32_t after = mavlink_get_channel_status(MAVLINK_COMM_0)->packet_rx_success_count;
	printf("[xver] current-spec ESAD_ARMING (CRC_EXTRA 3, DISARM=51) into this firmware: %s, state=%s\n",
	       after > before ? "ACCEPTED" : "dropped (CRC_EXTRA mismatch)",
	       g_arming_status == MAVLINK_M_ESAD_ARMING_ARMED ? "ARMED" : "DISARMED");
}

// Random structurally-valid frames (correct CRC for any known msgid, any length,
// random signed flag + signature) interleaved with noise, on both links.
static void fuzz(unsigned long iters, unsigned seed)
{
	static const mavlink_msg_entry_t table[] = MAVLINK_MESSAGE_CRCS;
	const size_t nt = sizeof(table) / sizeof(table[0]);
	std::mt19937 rng(seed);
	uint8_t f[300];
	unsigned long accepted_arming = 0;
	for (unsigned long it = 0; it < iters; it++) {
		Stream &link = (rng() & 1) ? (Stream &)FCLink : (Stream &)USBLink;
		int mode = rng() % 8;
		if (mode == 0) { // noise
			int n = rng() % 64;
			for (int k = 0; k < n; k++) f[k] = (rng() % 4 == 0) ? 0xFD : rng();
			link.feed(f, n);
		} else {
			const mavlink_msg_entry_t &e = (mode < 4) ? table[nt - 1 - (rng() % 32)] : table[rng() % nt];
			uint32_t id = (mode == 3) ? MAVLINK_MSG_ID_ESAD_ARMING : e.msgid;
			uint8_t extra = (mode == 3) ? MAVLINK_MSG_ID_ESAD_ARMING_CRC : e.crc_extra;
			uint8_t len = (rng() % 3 == 0) ? (uint8_t)(rng() % 256) : (uint8_t)(rng() % ((mode == 3 ? 15 : e.max_msg_len) + 1));
			uint8_t inc = (rng() % 4 == 0) ? 1 : (rng() % 16 == 0 ? (uint8_t)rng() : 0);
			int i = 0;
			f[i++] = 0xFD; f[i++] = len; f[i++] = inc; f[i++] = rng(); f[i++] = rng(); f[i++] = rng(); f[i++] = rng();
			f[i++] = id & 0xFF; f[i++] = (id >> 8) & 0xFF; f[i++] = (id >> 16) & 0xFF;
			for (int k = 0; k < len; k++) f[i++] = rng();
			uint16_t crc = crc_calculate(f + 1, i - 1); crc_accumulate(extra, &crc);
			f[i++] = crc & 0xFF; f[i++] = crc >> 8;
			if (inc & 1) for (int k = 0; k < 13; k++) f[i++] = rng();
			if (rng() % 50 == 0) f[rng() % i] ^= 1 << (rng() % 8); // occasional corruption
			link.feed(f, i);
			if (id == MAVLINK_MSG_ID_ESAD_ARMING) accepted_arming++;
		}
		g_fake_micros += rng() % 5000;
		loop();
		if (FCLink.tx.size() > 1 << 20) FCLink.tx.clear();
		if (USBLink.tx.size() > 1 << 20) USBLink.tx.clear();
	}
	printf("[fuzz] %lu iterations (seed %u), %lu ESAD_ARMING-shaped frames, finished without sanitizer report\n",
	       iters, seed, accepted_arming);
}

int main(int argc, char **argv)
{
	setup();
	FCLink.tx.clear(); USBLink.tx.clear();
	const char *mode = argc > 1 ? argv[1] : "all";
	if (!strcmp(mode, "all") || !strcmp(mode, "sweep")) test_sweep();
	if (!strcmp(mode, "all") || !strcmp(mode, "authz")) test_authz();
	if (!strcmp(mode, "all") || !strcmp(mode, "xver")) test_cross_version();
	if (!strcmp(mode, "fuzz")) fuzz(argc > 2 ? strtoul(argv[2], 0, 10) : 1000000, argc > 3 ? atoi(argv[3]) : 1);
	return 0;
}
