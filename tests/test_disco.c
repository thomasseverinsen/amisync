/* test_disco.c - host unit check for the discovery Announce builder
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the host (see `make test-disco`). DISCO_HOST_TEST excludes
 * the Amiga-only broadcaster, leaving the pure packet builder, which we decode
 * with pbuf and verify field by field against the localdisco-v4 layout.
 */

#define DISCO_HOST_TEST
#include "../src/disco.c"

#include "pbuf.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

int main(void)
{
    unsigned char id[32];
    const char   *addrs[1] = { "tcp://0.0.0.0:22000" };
    unsigned char pkt[256];
    int           len, i;
    PbufReader    r;
    uint32_t      field;
    int           wt;
    int           saw_id = 0, saw_addr = 0, saw_iid = 0;

    for (i = 0; i < 32; i++)
        id[i] = (unsigned char)(i * 7 + 1);

    len = disco_build_announce(pkt, sizeof(pkt), id, addrs, 1, 0x0123456789ABCDEFll);
    ok("announce builds", len > 4);

    /* magic is big-endian 0x2EA7D90B */
    ok("magic byte 0", pkt[0] == 0x2E);
    ok("magic byte 1", pkt[1] == 0xA7);
    ok("magic byte 2", pkt[2] == 0xD9);
    ok("magic byte 3", pkt[3] == 0x0B);

    pbuf_reader_init(&r, pkt + 4, len - 4);
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *d;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {
            pbuf_read_bytes(&r, &d, &n);
            ok("id is 32 bytes", n == 32 && memcmp(d, id, 32) == 0);
            saw_id = 1;
        } else if (field == 2 && wt == PBUF_WT_LEN) {
            pbuf_read_bytes(&r, &d, &n);
            ok("address value", n == strlen(addrs[0]) && memcmp(d, addrs[0], n) == 0);
            saw_addr = 1;
        } else if (field == 3 && wt == PBUF_WT_VARINT) {
            uint64_t v;
            pbuf_read_varint(&r, &v);
            ok("instance id", v == 0x0123456789ABCDEFull);
            saw_iid = 1;
        } else {
            pbuf_skip(&r, wt);
        }
    }
    ok("no decode error", !r.error);
    ok("saw all three fields", saw_id && saw_addr && saw_iid);

    /* overflow is reported, not overrun */
    ok("tiny buffer rejected", disco_build_announce(pkt, 8, id, addrs, 1, 1) == 0);

    /* parse round-trip: build then parse the announce back */
    {
        unsigned char gid[32];
        char          a0[96];
        ok("announce parses",
           disco_parse_announce(pkt /* still the last good build */, len, gid, a0, sizeof(a0)));
        /* rebuild a fresh known packet and parse it */
        len = disco_build_announce(pkt, sizeof(pkt), id, addrs, 1, 42);
        ok("parse ok",      disco_parse_announce(pkt, len, gid, a0, sizeof(a0)));
        ok("parse id",      memcmp(gid, id, 32) == 0);
        ok("parse addr",    strcmp(a0, "tcp://0.0.0.0:22000") == 0);
        /* bad magic rejected */
        pkt[0] ^= 0xFF;
        ok("bad magic",    !disco_parse_announce(pkt, len, gid, a0, sizeof(a0)));
    }

    /* tcp address parsing */
    {
        char           h[64];
        unsigned short pt = 0;
        ok("tcp parse",      disco_parse_tcp_addr("tcp://192.168.1.5:22000", h, sizeof(h), &pt));
        ok("tcp host",       strcmp(h, "192.168.1.5") == 0 && pt == 22000);
        ok("tcp wildcard",   disco_parse_tcp_addr("tcp://0.0.0.0:22000", h, sizeof(h), &pt) &&
                             strcmp(h, "0.0.0.0") == 0);
        ok("non-tcp rejected", !disco_parse_tcp_addr("quic://1.2.3.4:22000", h, sizeof(h), &pt));
        ok("no port rejected", !disco_parse_tcp_addr("tcp://1.2.3.4", h, sizeof(h), &pt));
        ok("port 65535 ok",  disco_parse_tcp_addr("tcp://1.2.3.4:65535", h, sizeof(h), &pt) &&
                             pt == 65535);
        ok("port overflow rejected",
                             !disco_parse_tcp_addr("tcp://1.2.3.4:87464", h, sizeof(h), &pt));
        ok("dns name ok",    disco_parse_tcp_addr("tcp://nas.local:22000", h, sizeof(h), &pt) &&
                             strcmp(h, "nas.local") == 0);
        ok("dashes ok",      disco_parse_tcp_addr("tcp://my-nas-1:22000", h, sizeof(h), &pt));
        /* The announce is unauthenticated broadcast and this host string ends
         * up in amisync.conf when the user adds the device, so a newline here
         * would write a config line of its own (a folder rooted at SYS:, say)
         * that the next start obeys. */
        ok("newline in host rejected",
                             !disco_parse_tcp_addr(
                                 "tcp://1.2.3.4\nfolder = sys SYS: sendreceive:22000",
                                 h, sizeof(h), &pt));
        ok("tab in host rejected",
                             !disco_parse_tcp_addr("tcp://1.2\t3.4:22000", h, sizeof(h), &pt));
        ok("space in host rejected",
                             !disco_parse_tcp_addr("tcp://1.2.3.4 x:22000", h, sizeof(h), &pt));
        ok("quote in host rejected",
                             !disco_parse_tcp_addr("tcp://\"x\":22000", h, sizeof(h), &pt));
    }

    /* The seen-list ring: new IDs are added, known IDs refresh in place, and
     * the oldest is overwritten once DISCO_SEEN_MAX distinct devices are in. */
    {
        DiscoSeenList l;
        char          idbuf[16];
        int           j;

        memset(&l, 0, sizeof(l));
        ok("seen: first is new",  disco_seen_add(&l, "AAA", "10.0.0.1", 22000) == 1);
        ok("seen: counted",       l.n == 1);
        ok("seen: repeat not new", disco_seen_add(&l, "AAA", "10.0.0.2", 22001) == 0);
        ok("seen: still one",     l.n == 1);
        ok("seen: address refreshed",
           strcmp(l.e[0].host, "10.0.0.2") == 0 && l.e[0].port == 22001);
        ok("seen: empty id refused", disco_seen_add(&l, "", "10.0.0.3", 1) == 0);

        for (j = 0; j < DISCO_SEEN_MAX; j++) {      /* fill past AAA */
            sprintf(idbuf, "DEV%d", j);
            disco_seen_add(&l, idbuf, "10.0.0.9", 1);
        }
        ok("seen: caps at max",   l.n == DISCO_SEEN_MAX);
        ok("seen: oldest evicted", disco_seen_add(&l, "AAA", "10.0.0.1", 22000) == 1);
    }

    if (failures) {
        printf("\n%d disco check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall disco checks passed\n");
    return 0;
}
