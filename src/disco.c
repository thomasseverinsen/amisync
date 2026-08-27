/* disco.c - Syncthing local discovery (UDP 21027) for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See disco.h. disco_build_announce() is pure and host-tested
 * (tests/test_disco.c via DISCO_HOST_TEST); the broadcaster process and its
 * supervisor are Amiga-only and compiled into the daemon. The broadcaster
 * derives our device key from the configured certificate, then sends an
 * Announce to the link-local broadcast address every DISCO_INTERVAL seconds
 * until the daemon signals it to stop.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "disco.h"
#include "pbuf.h"

int disco_build_announce(void *buf, int cap,
                         const unsigned char id_raw[32],
                         const char *const *addresses, int naddr,
                         int64_t instance_id)
{
    unsigned char *p = (unsigned char *)buf;
    PbufWriter     w;
    int            i;

    if (cap < 4)
        return 0;

    /* 4-byte big-endian magic, then the Announce protobuf. */
    p[0] = (unsigned char)(DISCO_MAGIC >> 24);
    p[1] = (unsigned char)(DISCO_MAGIC >> 16);
    p[2] = (unsigned char)(DISCO_MAGIC >> 8);
    p[3] = (unsigned char)(DISCO_MAGIC);

    pbuf_writer_init(&w, p + 4, (size_t)(cap - 4));
    pbuf_write_bytes(&w, 1, id_raw, 32);            /* Announce.id           */
    for (i = 0; i < naddr; i++)
        pbuf_write_string(&w, 2, addresses[i]);     /* Announce.addresses    */
    if (instance_id)
        pbuf_write_int64(&w, 3, instance_id);       /* Announce.instance_id  */

    if (w.error)
        return 0;
    return 4 + (int)w.len;
}

int disco_parse_announce(const void *buf, int len,
                         unsigned char id_out[32], char *addr0, int addrcap)
{
    const unsigned char *p = (const unsigned char *)buf;
    PbufReader           r;
    uint32_t             field;
    int                  wt, have_id = 0;

    if (addrcap > 0)
        addr0[0] = '\0';
    if (len < 4)
        return 0;
    if ((((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  |  (uint32_t)p[3]) != DISCO_MAGIC)
        return 0;

    pbuf_reader_init(&r, p + 4, (size_t)(len - 4));
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *d;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {              /* Announce.id */
            if (!pbuf_read_bytes(&r, &d, &n))
                return 0;
            if (n == 32) {
                memcpy(id_out, d, 32);
                have_id = 1;
            }
        } else if (field == 2 && wt == PBUF_WT_LEN) {       /* Announce.addresses */
            if (!pbuf_read_bytes(&r, &d, &n))
                return 0;
            if (addrcap > 0 && addr0[0] == '\0') {          /* keep the first */
                int c = (int)n;
                if (c > addrcap - 1)
                    c = addrcap - 1;
                memcpy(addr0, d, c);
                addr0[c] = '\0';
            }
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return have_id;
}

/* One character of a dotted-quad or DNS host name. The announce is unauthenticated
 * broadcast, and its address ends up in amisync.conf when the user adds the
 * device - where a control character would write a config line of its own - so
 * the host is held to the charset a real host name uses rather than merely
 * stripped of the bytes that hurt. */
static int host_char_ok(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

int disco_parse_tcp_addr(const char *url, char *host, int hostcap,
                         unsigned short *port)
{
    const char *p = url;
    const char *colon;
    int         hl, i;

    if (strncmp(p, "tcp://", 6) != 0)
        return 0;                          /* v1: tcp only */
    p += 6;
    colon = strrchr(p, ':');
    if (!colon)
        return 0;
    hl = (int)(colon - p);
    if (hl <= 0 || hl >= hostcap)
        return 0;
    for (i = 0; i < hl; i++)
        if (!host_char_ok((unsigned char)p[i]))
            return 0;
    memcpy(host, p, hl);
    host[hl] = '\0';
    {
        /* Range-check before narrowing: a peer-supplied "tcp://h:87464" would
         * otherwise truncate to a plausible-looking 21928 and be dialled. */
        long pn = atol(colon + 1);
        if (pn <= 0 || pn > 65535)
            return 0;
        *port = (unsigned short)pn;
    }
    return 1;
}

int disco_seen_add(DiscoSeenList *l, const char *id, const char *host,
                   unsigned short port)
{
    int i;

    if (!l || !id || !id[0])
        return 0;

    for (i = 0; i < l->n; i++) {                   /* already known: refresh */
        if (strcmp(l->e[i].id, id) == 0) {
            strncpy(l->e[i].host, host, sizeof(l->e[i].host) - 1);
            l->e[i].host[sizeof(l->e[i].host) - 1] = '\0';
            l->e[i].port = port;
            return 0;
        }
    }

    {                                              /* new: add at ring cursor */
        DiscoSeenEntry *e = &l->e[l->next];
        strncpy(e->id, id, sizeof(e->id) - 1);
        e->id[sizeof(e->id) - 1] = '\0';
        strncpy(e->host, host, sizeof(e->host) - 1);
        e->host[sizeof(e->host) - 1] = '\0';
        e->port = port;
        l->next = (l->next + 1) % DISCO_SEEN_MAX;
        if (l->n < DISCO_SEEN_MAX)
            l->n++;
    }
    return 1;
}

#ifndef DISCO_HOST_TEST

#include <exec/memory.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <dos/dos.h>
#include <dos/dostags.h>

#include "netbase.h"         /* pulls in <proto/bsdsocket.h> bound to this task's base */
#include "worker.h"          /* WORKER_SIG_STOP */
#include "ssl.h"
#include "device_id.h"
#include "log.h"

#define DISCO_INTERVAL   30  /* seconds between broadcasts */
#define DISCO_STACK   131072

struct DiscoHandle {
    struct MsgPort *port;
    struct Process *proc;
    DiscoStartup   *startup;
};

/* A loose per-run identifier from the system clock (any nonzero value works;
 * Syncthing uses it only to notice that a peer has restarted). */
static int64_t make_instance_id(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return ((int64_t)ds.ds_Days * 1440 + ds.ds_Minute) * 3000 + ds.ds_Tick + 1;
}

/* Wall-clock seconds, for pacing the broadcast independently of recv traffic. */
static int64_t now_secs(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (int64_t)ds.ds_Days * 86400 + (int64_t)ds.ds_Minute * 60
         + (int64_t)ds.ds_Tick / TICKS_PER_SECOND;
}

/* Post a discovery event to the daemon's port (fire-and-forget; daemon frees). */
static void post_disco(struct MsgPort *to, int kind, const char *id,
                       const char *host, unsigned short port)
{
    DiscoEvent *df = AllocVec(sizeof(*df), MEMF_PUBLIC | MEMF_CLEAR);
    if (!df)
        return;
    df->msg.mn_Node.ln_Type = NT_MESSAGE;
    df->msg.mn_Length       = sizeof(*df);
    df->msg.mn_ReplyPort    = NULL;
    df->kind                = kind;
    strncpy(df->id,   id,   sizeof(df->id)   - 1); /* df is MEMF_CLEAR: */
    strncpy(df->host, host, sizeof(df->host) - 1); /* tails stay NUL    */
    df->port = port;
    PutMsg(to, (struct Message *)df);
}

/* Handle a received announce. A match against a configured peer posts a
 * DISCO_FOUND (the daemon dials it); an announce from any other device posts a
 * DISCO_SEEN (the daemon notifies the user). */
static void disco_recv_announce(DiscoStartup *st, const unsigned char *pkt,
                                int n, struct sockaddr_in *from)
{
    unsigned char  id_raw[32];
    char           addr0[96];
    char           host[64];
    char           idstr[DEVICE_ID_BUFSZ];
    unsigned short port;
    int            i;

    if (!disco_parse_announce(pkt, n, id_raw, addr0, sizeof(addr0)))
        return;
    if (!addr0[0] || !disco_parse_tcp_addr(addr0, host, sizeof(host), &port))
        return;

    if (strcmp(host, "0.0.0.0") == 0) {            /* use the datagram's source */
        STRPTR dotted = Inet_NtoA(from->sin_addr.s_addr);
        if (!dotted)
            return;
        strncpy(host, (char *)dotted, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    for (i = 0; i < st->cfg->num_peers; i++) {
        unsigned char praw[32];
        if (device_id_to_raw(st->cfg->peers[i].id, praw) &&
            memcmp(praw, id_raw, 32) == 0) {
            post_disco(st->found_port, DISCO_FOUND, st->cfg->peers[i].id,
                       host, port);
            return;                                /* first match wins */
        }
    }

    /* No configured peer matched: surface the sighting for the user. */
    device_id_from_raw(id_raw, idstr);
    post_disco(st->found_port, DISCO_SEEN, idstr, host, port);
}

static int disco_run(DiscoStartup *st)
{
    char               idstr[DEVICE_ID_BUFSZ];
    unsigned char      id_raw[32];
    char               addr[64];
    const char        *addrs[1];
    unsigned char      pkt[512];
    struct sockaddr_in dst;
    int                sock, on = 1;
    int64_t            iid, last_bcast;

    /* ssl_subtask_init() brings up this task's bsdsocket base (for UDP) and
     * binds it to the daemon's shared AmiSSL instance (for reading the cert
     * below). */
    if (!ssl_subtask_init()) {
        log_printf(LOG_ERROR, "disco: ssl_subtask_init() failed");
        return 1;   /* init self-cleans on failure; must NOT call cleanup */
    }

    if (!device_id_from_cert_file(st->cert_path, idstr) ||
        !device_id_to_raw(idstr, id_raw)) {
        log_printf(LOG_ERROR, "disco: cannot derive device key from %s",
                   st->cert_path);
        ssl_subtask_cleanup();
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_printf(LOG_ERROR, "disco: socket() failed (errno %ld)", (long)Errno());
        ssl_subtask_cleanup();
        return 1;
    }
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    /* Sharing a UDP port with another live listener needs REUSEPORT on
     * BSD-derived stacks (Roadshow); REUSEADDR alone is not enough. Only
     * matters if something else also listens on 21027; harmless otherwise. */
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* Bind the discovery port so we also receive peers' announcements. A bind
     * failure is non-fatal: we just keep broadcasting (send-only). The errno
     * is the diagnosis: 48 (EADDRINUSE) = someone else holds 21027 - e.g. a
     * previous instance that never fully exited. */
    {
        struct sockaddr_in me;
        memset(&me, 0, sizeof(me));
        me.sin_family      = AF_INET;
        me.sin_port        = htons(DISCO_PORT);
        me.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, (struct sockaddr *)&me, sizeof(me)) < 0)
            log_printf(LOG_WARN, "disco: cannot bind UDP %d (errno %ld); "
                       "receive disabled", DISCO_PORT, (long)Errno());
    }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(DISCO_PORT);
    dst.sin_addr.s_addr = htonl(0xFFFFFFFFUL);   /* 255.255.255.255 */

    /* 0.0.0.0 tells the receiver to use the packet's source IP. With
     * listenport = 0 there is no listener, hence nothing dialable to
     * announce - discovery becomes receive-only (we still find peers). */
    sprintf(addr, "tcp://0.0.0.0:%u", (unsigned)st->listen_port);
    addrs[0] = addr;
    iid = make_instance_id();

    if (st->listen_port != 0)
        log_printf(LOG_INFO, "disco: announcing %s on UDP %d every %ds (and listening)",
                   idstr, DISCO_PORT, DISCO_INTERVAL);
    else
        log_printf(LOG_INFO, "disco: listening on UDP %d (listenport=0: "
                   "nothing to announce)", DISCO_PORT);

    last_bcast = now_secs() - DISCO_INTERVAL;      /* broadcast immediately */
    for (;;) {
        unsigned long  sigs = WORKER_SIG_STOP;
        struct timeval tv;
        fd_set         rfds;
        int64_t        now = now_secs();
        int            remaining;
        long           rc;

        if (now - last_bcast >= DISCO_INTERVAL) {
            if (st->listen_port != 0) {          /* listenport=0: nothing to announce */
                int len = disco_build_announce(pkt, sizeof(pkt), id_raw,
                                               addrs, 1, iid);
                if (len > 0)
                    sendto(sock, pkt, len, 0,
                           (struct sockaddr *)&dst, sizeof(dst));
            }
            last_bcast = now;
        }
        remaining = (int)(DISCO_INTERVAL - (now - last_bcast));
        if (remaining < 1)
            remaining = 1;

        /* Wait for an inbound announce, the broadcast deadline, or the stop
         * signal, whichever comes first. */
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        tv.tv_sec  = remaining;
        tv.tv_usec = 0;
        rc = WaitSelect(sock + 1, (APTR)&rfds, NULL, NULL,
                        (struct __timeval *)(void *)&tv, &sigs);
        if (sigs & WORKER_SIG_STOP)
            break;
        if (rc > 0 && FD_ISSET(sock, &rfds)) {
            struct sockaddr_in from;
            socklen_t          fl = sizeof(from);
            int                n  = recvfrom(sock, pkt, sizeof(pkt), 0,
                                             (struct sockaddr *)&from, &fl);
            if (n > 0)
                disco_recv_announce(st, pkt, n, &from);
        }
    }

    CloseSocket(sock);
    ssl_subtask_cleanup();
    return 0;
}

void disco_entry(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    DiscoStartup   *st;

    WaitPort(&me->pr_MsgPort);
    st = (DiscoStartup *)GetMsg(&me->pr_MsgPort);
    if (!st)
        return;

    disco_run(st);
    ReplyMsg((struct Message *)st);
}

DiscoHandle *disco_start(const Config *cfg, struct MsgPort *found_port)
{
    DiscoHandle    *h;
    DiscoStartup   *st;
    struct Process *proc;

    if (!cfg->discovery)
        return NULL;

    /* The receiver posts found peers to found_port; a NULL port (its
     * CreateMsgPort failed under memory pressure) would make the subprocess
     * PutMsg(NULL) on the first received announce -> Guru. Refuse to start. */
    if (!found_port)
        return NULL;

    h = AllocVec(sizeof(*h), MEMF_PUBLIC | MEMF_CLEAR);
    if (!h)
        return NULL;

    h->port = CreateMsgPort();
    if (!h->port) {
        FreeVec(h);
        return NULL;
    }

    st = AllocVec(sizeof(*st), MEMF_PUBLIC | MEMF_CLEAR);
    if (!st) {
        DeleteMsgPort(h->port);
        FreeVec(h);
        return NULL;
    }
    st->msg.mn_Node.ln_Type = NT_MESSAGE;
    st->msg.mn_Length       = sizeof(*st);
    st->msg.mn_ReplyPort    = h->port;
    st->cfg                 = cfg;
    st->found_port          = found_port;
    st->cert_path           = cfg->cert_path;
    st->listen_port         = cfg->listen_port;

    proc = CreateNewProcTags(NP_Entry,     (ULONG)disco_entry,
                             NP_Name,      (ULONG)"amisync-disco",
                             NP_StackSize,  DISCO_STACK,
                             TAG_DONE);
    if (!proc) {
        FreeVec(st);
        DeleteMsgPort(h->port);
        FreeVec(h);
        return NULL;
    }

    h->proc    = proc;
    h->startup = st;
    PutMsg(&proc->pr_MsgPort, (struct Message *)st);
    return h;
}

void disco_stop(DiscoHandle *h)
{
    if (!h)
        return;

    /* The broadcaster can exit on its own (every init failure in disco_run
     * replies and terminates), and disco_entry's process is freed just after
     * ReplyMsg - so a reply already waiting on the port means h->proc is freed
     * memory. Take it off the port under Forbid before deciding to signal;
     * Forbid alone cannot protect a Task that died before we were called. */
    Forbid();
    if (GetMsg(h->port))
        h->proc = NULL;
    if (h->proc)
        Signal(&h->proc->pr_Task, WORKER_SIG_STOP);
    Permit();

    if (h->proc) {
        WaitPort(h->port);
        GetMsg(h->port);
    }

    FreeVec(h->startup);
    DeleteMsgPort(h->port);
    FreeVec(h);
}

#endif /* DISCO_HOST_TEST */
