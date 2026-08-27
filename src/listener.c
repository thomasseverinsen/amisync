/* listener.c - inbound BEP listener for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See listener.h. The listener process accepts connections and hands each off
 * to an inbound worker via the bsdsocket ReleaseSocket/ObtainSocket mechanism
 * (the released-socket table is shared across openers of the library, so the
 * worker can re-adopt the socket in its own task). The accept loop waits on
 * the listening socket, its inbound-worker reply port, and the stop signal at
 * once via WaitSelect (net_wait).
 */

#include <string.h>

#include <exec/ports.h>
#include <exec/memory.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <dos/dostags.h>
#include <libraries/bsdsocket.h>     /* UNIQUE_ID */

#include "netbase.h"     /* pulls in <proto/bsdsocket.h> bound to this task's base */
#include "listener.h"
#include "worker.h"
#include "net.h"
#include "log.h"

#define LISTEN_BACKLOG       4
#define LISTEN_MAX_INBOUND   8

/* Inbound workers do TLS, cert parsing and block hashing: match WORKER_STACK. */
#define INBOUND_STACK   131072

/* The listener process itself only waits, accepts, ReleaseSockets and logs -
 * no TLS, no recursion, nothing deep - so it does not need a worker's stack.
 * Kept far above what that call graph uses: stack sizing has bitten this
 * project before, and an overflow here corrupts the heap rather than faulting. */
#define LISTENER_STACK   32768

typedef struct {
    struct Process *proc;
} InboundSlot;

/* Parameters handed to the listener process. */
typedef struct {
    struct Message  msg;
    const Config   *cfg;
    FolderState    *folders;     /* shared per-folder index, handed to workers */
} ListenerStartup;

struct ListenerHandle {
    struct MsgPort  *port;
    struct Process  *proc;      /* NULL once the listener has replied and exited */
    ListenerStartup *startup;
    int              exited;    /* the startup message has been taken off port */
};

/* Null h->proc if the listener already replied; caller MUST hold Forbid().
 * listener_entry frees its Process just after ReplyMsg, so a reply waiting on
 * the port means h->proc is about to be (or already is) freed memory - the same
 * window drain_inbound_locked closes for inbound workers. The message itself is
 * h->startup, freed by listener_stop, so it is only taken off the port here. */
static void drain_listener_locked(ListenerHandle *h)
{
    if (!h->exited && GetMsg(h->port)) {
        h->exited = 1;
        h->proc   = NULL;
    }
}

/* Fold a finished inbound session's byte counters into the shared ConfigPeer so
 * STATUS keeps counting traffic with a peer that dials us. Called from BOTH
 * reap paths below - totals folded by one and dropped by the other would go
 * missing exactly as often as they were counted (peer.c's slot_fold carries
 * the same warning for the dial side). Pure memory, so Forbid-safe. */
static void fold_inbound(WorkerStartup *st)
{
    ConfigPeer *pc = st->peer_cfg;

    if (!pc)
        return;               /* never authenticated: no peer, and no blocks */
    pc->in_bytes_in  += st->bytes_in;
    pc->in_bytes_out += st->bytes_out;
}

/* Reap any inbound workers that have replied, freeing their startup blocks. */
static void reap_inbound(struct MsgPort *reply)
{
    struct Message *m;
    while ((m = GetMsg(reply)) != NULL) {
        WorkerStartup *st = (WorkerStartup *)m;
        InboundSlot   *s  = (InboundSlot *)st->slot;
        log_printf(LOG_INFO, "listener: inbound worker ended (peer %s, rc=%d)",
                   st->peer_actual_id[0] ? st->peer_actual_id : "?", st->result);
        s->proc = NULL;
        fold_inbound(st);
        FreeVec(st);
    }
}

/* Reap queued replies WITHOUT logging; caller MUST hold Forbid(). A worker
 * frees its Process just after ReplyMsg, so before signalling slots[i].proc we
 * must null any slot whose worker already replied - otherwise the Signal hits
 * freed memory. Pure GetMsg/FreeVec, so Forbid-safe (unlike reap_inbound, which
 * logs). Used to close the window before the RESCAN/STOP signal loops. */
static void drain_inbound_locked(struct MsgPort *reply)
{
    struct Message *m;
    while ((m = GetMsg(reply)) != NULL) {
        InboundSlot *s = (InboundSlot *)((WorkerStartup *)m)->slot;
        s->proc = NULL;
        fold_inbound((WorkerStartup *)m);
        FreeVec(m);
    }
}

/* Hand an accepted socket to a new inbound worker. Returns 1 on success; on
 * failure the socket is closed. */
static int handoff(const Config *cfg, FolderState *folders,
                   struct MsgPort *reply, InboundSlot *slots,
                   int sock, const char *peer_ip)
{
    WorkerStartup  *st;
    struct Process *proc;
    InboundSlot    *slot = NULL;
    long            id;
    int             i;

    for (i = 0; i < LISTEN_MAX_INBOUND; i++)
        if (!slots[i].proc) { slot = &slots[i]; break; }
    if (!slot) {
        log_printf(LOG_WARN, "listener: inbound table full, dropping %s", peer_ip);
        net_close(sock);
        return 0;
    }

    st = AllocVec(sizeof(*st), MEMF_PUBLIC | MEMF_CLEAR);
    if (!st) {
        log_printf(LOG_WARN, "listener: out of memory, dropping %s", peer_ip);
        net_close(sock);
        return 0;
    }

    /* Detach the socket from this task so the worker can adopt it. */
    id = ReleaseSocket(sock, UNIQUE_ID);
    if (id < 0) {
        log_printf(LOG_WARN, "listener: ReleaseSocket failed, dropping %s",
                   peer_ip);
        FreeVec(st);
        net_close(sock);
        return 0;
    }

    st->msg.mn_Node.ln_Type = NT_MESSAGE;
    st->msg.mn_Length       = sizeof(*st);
    st->msg.mn_ReplyPort    = reply;
    st->mode                = WORKER_INBOUND;
    st->socket_id           = id;
    /* peer_id left empty: an inbound peer is validated against the peer list. */
    st->cert_path   = cfg->cert_path;
    st->key_path    = cfg->key_path;
    st->device_name = cfg->device_name;
    st->cfg         = cfg;
    st->folders     = folders;
    st->slot        = slot;

    proc = CreateNewProcTags(NP_Entry,     (ULONG)worker_entry,
                             NP_Name,      (ULONG)"amisync-inbound",
                             NP_StackSize,  INBOUND_STACK,
                             TAG_DONE);
    if (!proc) {
        /* We already released the socket; the worker would have closed it, so
         * adopt-and-close it here to avoid leaking it in the released table. */
        int s = ObtainSocket(id, AF_INET, SOCK_STREAM, 0);
        if (s != NET_INVALID_SOCKET)
            net_close(s);
        FreeVec(st);
        log_printf(LOG_WARN, "listener: cannot start a worker, dropping %s",
                   peer_ip);
        return 0;
    }

    slot->proc = proc;
    PutMsg(&proc->pr_MsgPort, (struct Message *)st);
    log_printf(LOG_INFO, "listener: inbound connection from %s", peer_ip);
    return 1;
}

static void listener_run(ListenerStartup *ls)
{
    const Config   *cfg     = ls->cfg;
    FolderState    *folders = ls->folders;
    struct MsgPort *reply;
    InboundSlot     slots[LISTEN_MAX_INBOUND];
    int             lsock;
    unsigned long   replysig;
    int             i, live;
    int             accept_fails;   /* consecutive; paces the backoff log */

    memset(slots, 0, sizeof(slots));

    /* The listener only does plain sockets (accept + hand off); it never does
     * TLS itself - the inbound worker does. So it needs just this task's own
     * bsdsocket base, not the AmiSSL instance. */
    if (!netbase_open()) {
        log_printf(LOG_ERROR, "listener: netbase_open() failed");
        return;
    }

    reply = CreateMsgPort();
    if (!reply)
        goto out_netbase;
    replysig = 1UL << reply->mp_SigBit;

    lsock = net_listen(cfg->listen_port, LISTEN_BACKLOG);
    if (lsock == NET_INVALID_SOCKET) {
        log_printf(LOG_ERROR, "listener: cannot bind port %u", cfg->listen_port);
        goto out_port;
    }
    log_printf(LOG_INFO, "listener: accepting BEP on port %u", cfg->listen_port);

    accept_fails = 0;
    for (;;) {
        unsigned long got = 0;
        int           r   = net_wait(lsock, 0,
                                     replysig | WORKER_SIG_STOP | WORKER_SIG_RESCAN,
                                     &got);

        if (r < 0) {
            /* Tearing the listener down silently left the daemon running with
             * no inbound service and nothing in the log to say why - every
             * other net_wait consumer reports before it gives up. */
            log_printf(LOG_ERROR, "listener: wait failed; no longer accepting "
                       "inbound connections");
            break;
        }
        if (got & WORKER_SIG_STOP)
            break;
        if (got & WORKER_SIG_RESCAN) {         /* forward to inbound workers */
            reap_inbound(reply);        /* reap finished (logs) first  */
            Forbid();
            drain_inbound_locked(reply);       /* close the freed-Task window  */
            for (i = 0; i < LISTEN_MAX_INBOUND; i++)
                if (slots[i].proc)
                    Signal(&slots[i].proc->pr_Task, WORKER_SIG_RESCAN);
            Permit();
            continue;
        }
        if (got & replysig) {
            reap_inbound(reply);
            continue;
        }
        /* Listening socket is readable: accept and hand off. */
        {
            char ip[24];
            int  s = net_accept(lsock, ip, sizeof(ip));
            if (s != NET_INVALID_SOCKET) {
                accept_fails = 0;      /* a run of failures has ended */
                handoff(cfg, folders, reply, slots, s, ip);
            } else {
                /* An accept that fails for a reason which DEQUEUES the
                 * connection (ECONNABORTED - a peer that hung up between the
                 * select and the accept) is routine and self-correcting. One
                 * that does not - ENOBUFS, ENOMEM, plausible on this machine -
                 * leaves the connection queued and the socket readable, so
                 * returning straight to net_wait spins as fast as the CPU
                 * allows, with nothing logged. Pause briefly instead: it costs
                 * a real peer a moment and costs a spin everything. */
                if (accept_fails++ == 0)
                    log_printf(LOG_WARN, "listener: accept failed (errno %ld); "
                               "backing off", (long)Errno());
                Delay(TICKS_PER_SECOND / 5);
            }
        }
    }

    /* Shutdown: stop accepting, signal inbound workers, wait for them. */
    net_close(lsock);

    /* Reap already-exited workers INSIDE the Forbid before signalling, so a
     * still-set slot->proc is guaranteed live (see drain_inbound_locked). */
    Forbid();
    drain_inbound_locked(reply);
    for (i = 0; i < LISTEN_MAX_INBOUND; i++)
        if (slots[i].proc)
            Signal(&slots[i].proc->pr_Task, WORKER_SIG_STOP);
    Permit();

    do {
        reap_inbound(reply);
        live = 0;
        for (i = 0; i < LISTEN_MAX_INBOUND; i++)
            if (slots[i].proc)
                live++;
        if (live)
            WaitPort(reply);
    } while (live);

out_port:
    DeleteMsgPort(reply);
out_netbase:
    netbase_close();
}

void listener_entry(void)
{
    struct Process  *me = (struct Process *)FindTask(NULL);
    ListenerStartup *ls;

    WaitPort(&me->pr_MsgPort);
    ls = (ListenerStartup *)GetMsg(&me->pr_MsgPort);
    if (!ls)
        return;

    listener_run(ls);
    ReplyMsg((struct Message *)ls);
}

ListenerHandle *listener_start(const Config *cfg, FolderState *folders)
{
    ListenerHandle  *h;
    ListenerStartup *ls;
    struct Process  *proc;

    if (cfg->listen_port == 0)
        return NULL;

    h = AllocVec(sizeof(*h), MEMF_PUBLIC | MEMF_CLEAR);
    if (!h)
        return NULL;

    h->port = CreateMsgPort();
    if (!h->port) {
        FreeVec(h);
        return NULL;
    }

    ls = AllocVec(sizeof(*ls), MEMF_PUBLIC | MEMF_CLEAR);
    if (!ls) {
        DeleteMsgPort(h->port);
        FreeVec(h);
        return NULL;
    }
    ls->msg.mn_Node.ln_Type = NT_MESSAGE;
    ls->msg.mn_Length       = sizeof(*ls);
    ls->msg.mn_ReplyPort    = h->port;
    ls->cfg                 = cfg;
    ls->folders             = folders;

    proc = CreateNewProcTags(NP_Entry,     (ULONG)listener_entry,
                             NP_Name,      (ULONG)"amisync-listener",
                             NP_StackSize,  LISTENER_STACK,
                             TAG_DONE);
    if (!proc) {
        FreeVec(ls);
        DeleteMsgPort(h->port);
        FreeVec(h);
        return NULL;
    }

    h->proc    = proc;
    h->startup = ls;
    PutMsg(&proc->pr_MsgPort, (struct Message *)ls);
    return h;
}

void listener_rescan(ListenerHandle *h)
{
    if (!h)
        return;
    Forbid();
    drain_listener_locked(h);
    if (h->proc)
        Signal(&h->proc->pr_Task, WORKER_SIG_RESCAN);
    Permit();
}

void listener_stop(ListenerHandle *h)
{
    if (!h)
        return;

    Forbid();
    drain_listener_locked(h);
    if (h->proc)
        Signal(&h->proc->pr_Task, WORKER_SIG_STOP);
    Permit();

    if (!h->exited) {
        WaitPort(h->port);
        GetMsg(h->port);
    }

    FreeVec(h->startup);
    DeleteMsgPort(h->port);
    FreeVec(h);
}
