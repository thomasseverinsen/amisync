/* disco.h - Syncthing local discovery (UDP 21027) for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Local discovery lets a Syncthing peer on the same LAN see amisync in its
 * "nearby devices" without a static address, and lets amisync find a configured
 * peer's address the same way. The broadcaster process periodically *sends* an
 * Announce on UDP 21027 and also *receives* others': an announce whose device
 * ID matches a configured peer yields a DiscoEvent to the daemon, which
 * points that peer's dialer at the discovered address (peers may be configured
 * by device ID alone, with no host:port). No auto-accept: only configured peers
 * are ever dialled.
 *
 * Packet (per the localdisco-v4 spec): a 4-byte big-endian magic (0x2EA7D90B,
 * the same word BEP uses) followed by the Announce protobuf:
 *
 *   message Announce {
 *       bytes           id          = 1;   // raw 32-byte device key
 *       repeated string addresses   = 2;   // e.g. "tcp://0.0.0.0:22000"
 *       int64           instance_id = 3;
 *   }
 *
 * The Announce builder is pure and host-tested; the broadcaster runs in its
 * own process (subject to the same single-active-process library-base caveat
 * as the workers - see worker.h), and is off unless enabled in the config.
 */

#ifndef AMISYNC_DISCO_H
#define AMISYNC_DISCO_H

#include <stdint.h>

#include "config.h"      /* CONFIG_HOST_MAX sizes the address fields; also
                          * brings device_id.h for DEVICE_ID_BUFSZ */

#define DISCO_PORT   21027
#define DISCO_MAGIC  0x2EA7D90Bu

/* Build a discovery packet (magic + Announce) into buf/cap. 'id_raw' is the
 * 32-byte device key; 'addresses'/'naddr' are announce URLs; 'instance_id'
 * identifies this run. Returns the packet length, or 0 on overflow. Pure. */
int disco_build_announce(void *buf, int cap,
                         const unsigned char id_raw[32],
                         const char *const *addresses, int naddr,
                         int64_t instance_id);

/* Parse a received discovery packet: validate the magic, extract the device id
 * (field 1, 32 bytes) into 'id_out' and the first address string (field 2) into
 * 'addr0' (capacity 'addrcap'). Returns 1 if the magic and a 32-byte id were
 * present ('addr0' is "" if the announce carried no address). Pure. */
int disco_parse_announce(const void *buf, int len,
                         unsigned char id_out[32], char *addr0, int addrcap);

/* Parse a "tcp://host:port" URL into 'host' (capacity 'hostcap') and 'port'.
 * Returns 1 for a well-formed tcp URL with a non-zero port; 'host' may be
 * "0.0.0.0", meaning the caller should use the datagram's source IP. Pure. */
int disco_parse_tcp_addr(const char *url, char *host, int hostcap,
                         unsigned short *port);

/* Daemon-side record of unconfigured devices seen on the LAN, for the ARexx
 * DISCOVERED verb: the most recent DISCO_SEEN_MAX distinct devices, deduped by
 * ID. Owned and written only by the main daemon process, so it needs no lock.
 * Pure (ring + dedupe over char arrays), so it lives above the Amiga guard and
 * the host tests can reach it. */
#define DISCO_SEEN_MAX  16
#define DISCO_HOST_MAX  CONFIG_HOST_MAX   /* addresses end up in ConfigPeer */

typedef struct {
    char           id[DEVICE_ID_BUFSZ];
    char           host[DISCO_HOST_MAX];
    unsigned short port;
} DiscoSeenEntry;

typedef struct {
    DiscoSeenEntry e[DISCO_SEEN_MAX];
    int            n;             /* valid entries (caps at DISCO_SEEN_MAX) */
    int            next;          /* ring write cursor                      */
} DiscoSeenList;

/* Record a sighting of 'id' at 'host:port'. A known ID has its address
 * refreshed; a new ID is added (overwriting the oldest when full). Returns 1 if
 * 'id' was NEW (caller should log/notify), else 0. Pure. */
int disco_seen_add(DiscoSeenList *l, const char *id, const char *host,
                   unsigned short port);

#ifndef DISCO_HOST_TEST   /* Amiga-only process plumbing */

#include <exec/ports.h>

/* Kind of discovery event posted broadcaster -> daemon. */
typedef enum {
    DISCO_FOUND = 0,  /* announce matched a configured peer: dial it       */
    DISCO_SEEN  = 1   /* announce from an UNconfigured device: notify only */
} DiscoEventKind;

/* A discovery event, sent broadcaster -> daemon. Fire-and-forget: the daemon
 * frees it (no reply). Carries both kinds, hence the neutral name. */
typedef struct {
    struct Message  msg;                 /* MUST be first                   */
    DiscoEventKind  kind;                /* which of the two above          */
    char            id[DEVICE_ID_BUFSZ]; /* device ID (formatted)           */
    char            host[DISCO_HOST_MAX];/* resolved dotted-quad or name    */
    unsigned short  port;
} DiscoEvent;

/* Parameters handed to the discovery process via its process port. */
typedef struct {
    struct Message  msg;          /* MUST be first: replied to main's port  */
    const Config   *cfg;          /* configured peers, to filter announces  */
    struct MsgPort *found_port;   /* where DiscoEvents are delivered        */
    const char     *cert_path;    /* derive our device key from this cert   */
    unsigned short  listen_port;  /* the BEP port we advertise              */
} DiscoStartup;

/* CreateNewProc entry point for the broadcaster (pass as NP_Entry). */
void disco_entry(void);

/* Supervisor handle owned by the daemon. */
typedef struct DiscoHandle DiscoHandle;

/* Start the broadcaster if cfg->discovery is set; returns NULL if disabled or
 * on failure (the daemon simply runs without discovery). Discovered addresses
 * are posted to 'found_port'. */
DiscoHandle *disco_start(const Config *cfg, struct MsgPort *found_port);

/* Signal the broadcaster, wait for it, and free the handle. NULL-safe. */
void disco_stop(DiscoHandle *h);

#endif /* DISCO_HOST_TEST */

#endif /* AMISYNC_DISCO_H */
