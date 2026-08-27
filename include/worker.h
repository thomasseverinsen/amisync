/* worker.h - per-peer connection worker (process) for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Each peer connection is handled by its own process (CreateNewProc), so every
 * blocking SSL_read/SSL_write stays simple and a hung or crashing peer is
 * isolated from the rest of the daemon. A worker owns one socket and one SSL
 * session, runs the BEP state machine, and reports back to the main process
 * over an exec message port.
 *
 * Lifecycle:
 *   1. main CreateNewProc()s a worker with worker_entry as NP_Entry.
 *   2. main PutMsg()s a WorkerStartup to the worker's process port.
 *   3. the worker dials (or obtains an accepted socket), does the TLS + BEP
 *      handshake, then loops until the peer closes or main signals it.
 *   4. the worker ReplyMsg()s the WorkerStartup as its final act; main treats
 *      that reply as "worker finished" and may re-dial with backoff.
 *
 * Shutdown signal: main calls Signal(worker_task, WORKER_SIG_STOP); the worker
 * notices it in net_wait() and tears down cleanly.
 *
 * The worker neither scans nor hashes. It is pure transport over the
 * shared per-folder index (FolderState, owned by main): it announces records to
 * its peer via a per-peer sequence cursor, and on receive writes results back
 * into the shared index (which auto-relays to other peers). The scanner process
 * owns all local scanning/hashing.
 */

#ifndef AMISYNC_WORKER_H
#define AMISYNC_WORKER_H

#include <exec/ports.h>
#include <dos/dos.h>       /* SIGBREAKF_CTRL_E/F, below */

#include "device_id.h"
#include "config.h"
#include "bep.h"           /* BEP_NAME_MAX sizes the Hello fields */
#include "foldstate.h"

/* Exec signals main uses to poke a worker. CTRL-C/D are reserved by convention
 * for the CLI; these background processes use CTRL-F to stop and CTRL-E to
 * trigger an immediate folder rescan (otherwise rescans happen on the idle
 * tick). */
#define WORKER_SIG_STOP    SIGBREAKF_CTRL_F
#define WORKER_SIG_RESCAN  SIGBREAKF_CTRL_E

typedef enum {
    WORKER_DIAL    = 0,   /* worker opens its own socket to host:port      */
    WORKER_INBOUND = 1    /* worker adopts an accepted socket           */
} WorkerMode;

/* Tagged so config.h can type ConfigPeer.inbound_st as a pointer to it
 * without including this header (which includes config.h). */
typedef struct WorkerStartup {
    struct Message  msg;        /* MUST be first: replied to main's port    */

    /* --- inputs (filled by main before PutMsg) --- */
    WorkerMode      mode;
    char            host[CONFIG_HOST_MAX];      /* WORKER_DIAL target host  */
    unsigned short  port;
    char            peer_id[DEVICE_ID_BUFSZ];   /* allowed/expected dev id  */
    /* The peer's config slot, carrying the shared runtime pause/inbound
     * state (see ConfigPeer in config.h). Dialers get it from the peer
     * manager at spawn; an inbound worker resolves it itself once the peer
     * has authenticated. NULL until known. */
    ConfigPeer     *peer_cfg;
    long            socket_id;                  /* WORKER_INBOUND handoff   */
    const char     *cert_path;                  /* our identity cert.pem    */
    const char     *key_path;                   /* our identity key.pem     */
    const char     *device_name;                /* our Hello device name    */
    const Config   *cfg;                        /* folders + peer list      */
    /* The shared index, allocated at [CONFIG_MAX_FOLDERS] and never moved -
     * runtime folder-add depends on that, and folders are indexed by config
     * slot, which can exceed cfg->num_folders' live count. */
    FolderState    *folders;
    int             connect_timeout;            /* seconds (0 = stack dflt) */
    int             initial_delay;              /* backoff sleep before dial */
    /* The peer manager's PeerSlot *, opaque to the worker: never dereferenced
     * or written here, just returned untouched on ReplyMsg so the manager can
     * find the slot to re-dial. */
    void           *slot;

    /* --- outputs (filled by worker before ReplyMsg) --- */
    volatile int    connected;                  /* reached BEP connected     */
    /* Live sync backlog: files this worker still wants to fetch (queued +
     * in-flight), updated as the connection runs. 0 while connected means
     * this peer is up to date. Read by the daemon (volatile) to aggregate an
     * overall status; never latched, so a stale value at teardown is fine. */
    volatile int    pending;
    /* The same backlog split by folder (config slot index): feeds the
     * status window's per-folder "Syncing (N files)" state. Same volatile
     * live-read contract as 'pending'. */
    volatile int    pending_f[CONFIG_MAX_FOLDERS];
    /* Files a peer says are deleted that we are deliberately KEEPING, because
     * our copy won the version comparison (the data-beats-a-delete rule in
     * sync_classify_incoming). We are not fetching anything for them, so they
     * are not 'pending' - but the peer counts us out of sync for exactly these
     * and will go on doing so, and a status that says "Up to Date" over them
     * is the one answer that is certainly wrong. Per folder, and the total. */
    volatile int    kept_f[CONFIG_MAX_FOLDERS];
    volatile int    kept;
    /* Local edits in a RECEIVE-ONLY folder that the peer's copy has replaced,
     * counted since this worker started. Unlike 'kept' this is a tally of
     * events, not a set of names: once replaced the file matches the peer and
     * there is nothing left to disagree about, so nothing would ever clear a
     * set. It is reported because the alternative is a folder that quietly
     * says "Up to Date" having just overwritten something the user wrote, with
     * the only copy now in .stversions and no reason to go looking. */
    volatile int    reverted_f[CONFIG_MAX_FOLDERS];
    volatile int    reverted;
    /* Set just before the worker closes a HEALTHY session on purpose, to be
     * re-dialled at once for the rest of an oversized index or a changed need
     * (see the recycle in worker_run). The peer manager keeps it on the slot
     * so the gap between the two sessions - where there is no worker and so no
     * backlog to count - is not reported as "Up to Date" in the middle of a
     * transfer. Cleared by the next session that ends any other way. */
    volatile int    resync;
    /* Raised once this session has actually processed an Index from the peer.
     * Until then "backlog 0" only means the peer has not spoken yet, which is
     * not the same as having nothing to do - the difference matters for the
     * second or two after each reconnect of a batched transfer. */
    volatile int    indexed;
    /* Block-payload bytes moved this connection (received = downloads, sent
     * = blocks served). Same volatile live-read contract as 'pending'; the
     * peer manager folds them into per-peer running totals at worker exit.
     * STATUS display only, so an occasionally torn 64-bit read is harmless. */
    volatile unsigned long long bytes_in;
    volatile unsigned long long bytes_out;
    /* The peer's Hello identity ("uae4000", "syncthing v2.1.2"), captured
     * before 'connected' is raised; empty until then. For STATUS display. */
    char            peer_name[BEP_NAME_MAX];
    /* client_name + ' ' + client_version, so two BEP_NAME_MAX fields joined -
     * which is what the doubling is for. Keep it if the format changes. */
    char            peer_client[2 * BEP_NAME_MAX];
    int             result;                     /* 0 ok/clean, else error    */
    char            peer_actual_id[DEVICE_ID_BUFSZ]; /* observed peer id     */
} WorkerStartup;

/* CreateNewProc entry point (pass as NP_Entry). */
void worker_entry(void);

#endif /* AMISYNC_WORKER_H */
