/* peer.c - main-side peer table and worker supervision for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See peer.h. One PeerSlot per configured peer tracks its current worker (if
 * any) and the backoff to use for the next dial. Workers run as separate
 * processes (worker.c) and report completion by replying their WorkerStartup
 * to our reply port; that reply is also how we learn a worker has exited, so
 * we can re-dial.
 *
 * Concurrency: each worker binds its own per-task bsdsocket base (netbase)
 * and shares the daemon's AmiSSL instance via ssl_subtask_init(), so several
 * can run at once without clobbering a shared library base.
 */

#include <stdio.h>
#include <string.h>

#include <exec/ports.h>
#include <exec/memory.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <dos/dostags.h>

#include "peer.h"
#include "worker.h"
#include "wreg.h"
#include "bep.h"          /* BEP_NAME_MAX sizes the Hello fields below */
#include "device_id.h"    /* device_id_equal/_normalize, DEVICE_ID_BUFSZ */
#include "log.h"

#define PEER_BACKOFF_MIN   2
#define PEER_BACKOFF_MAX  60
#define WORKER_STACK   131072   /* TLS 1.3 + cert parsing want real headroom, and
                                 * the debug (-O0) build's frames are much larger */

typedef struct {
    ConfigPeer       *cfg;       /* points into the daemon's Config; also
                                  * carries the shared runtime pause /
                                  * inbound-connection state every worker
                                  * checks (see config.h)                 */
    struct Process   *proc;      /* current worker process, or NULL       */
    WorkerStartup    *startup;   /* its in-flight startup message         */
    int               backoff;   /* seconds to wait before the next dial  */
    /* Effective dial address: seeded from the config, and updated by local
     * discovery. 'have_addr' is 0 for a peer configured by device ID alone,
     * which stays idle until discovery supplies an address. */
    char              host[CONFIG_HOST_MAX];
    unsigned short    port;
    int               have_addr;
    /* STATUS bookkeeping: block bytes moved across ALL this peer's
     * connections since daemon start (folded in at worker exit; the live
     * worker's own counters are added on read), and the identity the peer
     * last presented in its Hello. */
    unsigned long long tot_in, tot_out;
    char              rname[BEP_NAME_MAX];
    char              rclient[2 * BEP_NAME_MAX];
    int               spawn_warned;   /* a failed spawn has been logged      */
} PeerSlot;

struct PeerManager {
    Config         *cfg;         /* peer table extended by peer_manager_add */
    FolderState    *folders;     /* shared per-folder index, handed to workers */
    struct MsgPort *port;        /* reply port for worker completions     */
    int             shutting_down;
    int             n;
    PeerSlot        slots[CONFIG_MAX_PEERS];
};

/* Length-bounded string copy that always NUL-terminates (and keeps the
 * compiler from warning about strncpy of equal-sized fixed buffers). */
static void scopy(char *dst, const char *src, int cap)
{
    int n = (int)strlen(src);
    if (n > cap - 1)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Point 'slot' at host:port (port 0 = the default BEP port). Does nothing
 * without a host: 'have_addr' is set if and only if there is one to dial,
 * which is what every dial decision keys off. */
static void slot_set_addr(PeerSlot *slot, const char *host, unsigned short port)
{
    if (!host || !host[0])
        return;
    scopy(slot->host, host, sizeof(slot->host));
    slot->port      = port ? port : CONFIG_DEFAULT_PORT;
    slot->have_addr = 1;
}

/* Is there a live INBOUND connection from this peer (it dialed us)? Reads the
 * WorkerStartup the inbound worker published in the shared ConfigPeer. The
 * pointer is cleared by the worker and the block freed by the listener - both
 * other tasks - so the load AND the dereference sit inside Forbid(), which
 * the publishing side also holds while flipping the pointer. 'fidx' selects
 * one folder's backlog, or -1 for the peer's total; if 'pending' is non-NULL
 * it receives that count. */
static int inbound_connected(const ConfigPeer *pc, int fidx, int *pending)
{
    WorkerStartup *ist;
    int            up = 0;

    Forbid();
    ist = pc->inbound_st;
    if (ist && ist->connected) {
        int n = fidx < 0 ? ist->pending : ist->pending_f[fidx];
        up = 1;
        if (pending)
            *pending = n > 0 ? n : 0;
    }
    Permit();
    return up;
}

/* Is this peer connected, in either direction, and how far behind is it?
 * The dial worker's live counters are preferred and an inbound connection is
 * the FALLBACK, never a second addend: the dialer stands down while
 * inbound_st is live, so at most one direction is meant to be up, and summing
 * them would double-count a peer during the moment both are. 'fidx' selects
 * one folder's backlog, or -1 for the peer's total. */
static int slot_connected(const PeerSlot *s, int fidx, int *pending)
{
    if (pending)
        *pending = 0;
    if (s->startup && s->startup->connected) {
        if (pending) {
            int n = fidx < 0 ? s->startup->pending
                             : s->startup->pending_f[fidx];
            *pending = n > 0 ? n : 0;
        }
        return 1;
    }
    return inbound_connected(s->cfg, fidx, pending);
}

/* Local edits this peer's copies have replaced (receive-only), counted from
 * BOTH of its sessions and added, not read from whichever one is preferred.
 *
 * slot_kept above picks a single session deliberately: kept files are a
 * property of the last index read, and a dial and an inbound connection to the
 * same peer both name the same files, so adding them would report one kept
 * file twice. A revert is the opposite kind of number - an EVENT, performed
 * once by whichever worker won the race to fetch the replacement. Prefer one
 * session and a revert done by the other is simply invisible.
 *
 * Measured on the three-node rig: a local edit was reverted (the worker logged
 * it, .stversions held the edit) while STATUS showed no counter at all,
 * because uae4000 had both a dial and an inbound session up and the inbound
 * one did the fetch. Same reasoning as peer_manager_status's summing across
 * peers, applied one level down. */
static int revert_count(const WorkerStartup *st, int fidx)
{
    if (!st || !st->connected)
        return 0;
    if (fidx < 0)
        return st->reverted > 0 ? st->reverted : 0;
    if (fidx >= CONFIG_MAX_FOLDERS)
        return 0;
    return st->reverted_f[fidx] > 0 ? st->reverted_f[fidx] : 0;
}

static int slot_reverted(const PeerSlot *s, int fidx)
{
    return revert_count(s->startup, fidx) +
           revert_count((const WorkerStartup *)s->cfg->inbound_st, fidx);
}

static int slot_kept(const PeerSlot *s, int fidx)
{
    const WorkerStartup *st = NULL;

    if (s->startup && s->startup->connected)
        st = s->startup;
    else if (s->cfg->inbound_st && s->cfg->inbound_st->connected)
        st = (const WorkerStartup *)s->cfg->inbound_st;
    if (!st)
        return 0;
    if (fidx < 0)
        return st->kept > 0 ? st->kept : 0;
    if (fidx >= CONFIG_MAX_FOLDERS)
        return 0;
    return st->kept_f[fidx] > 0 ? st->kept_f[fidx] : 0;
}

/* Is this peer mid-transfer with nothing to count right now? Three windows in
 * a row look identical from outside and all three are this: the tail of a
 * session that has dropped the rest of an oversized index and drained what it
 * did queue (connected, backlog 0); the teardown, before the manager has folded
 * the block; and the gap until the re-dial connects. A CONNECTED session speaks
 * for itself - its own flag, not the last one's - so a peer that really is idle
 * says so; otherwise the live block and then the folded copy carry it across.
 * Any session ending for another reason folds a 0 and clears it, so a peer that
 * dies mid-batch stops claiming to be busy. */
static int slot_resyncing(const PeerSlot *s)
{
    const WorkerStartup *st = NULL;

    if (s->startup && s->startup->connected)
        st = s->startup;
    else if (s->cfg->inbound_st && s->cfg->inbound_st->connected)
        st = (const WorkerStartup *)s->cfg->inbound_st;

    /* A session that has heard an Index knows its own backlog and speaks for
     * itself. One that has only just connected has not been told anything
     * yet, and between sessions there is no worker at all: both fall back to
     * what the last session left on the shared peer state. */
    if (st && st->indexed)
        return st->resync;
    return s->cfg->resyncing;
}

/* May this slot be dialled right now? The precondition every dial decision
 * shares: an address to dial, no worker already running, a peer that is
 * neither paused nor removed, and a daemon that is not shutting down. */
static int dialable(const PeerManager *pm, const PeerSlot *slot)
{
    return !pm->shutting_down && slot->have_addr && !slot->proc &&
           !slot->cfg->paused && !slot->cfg->removed;
}

PeerManager *peer_manager_create(Config *cfg, FolderState *folders)
{
    PeerManager *pm = AllocVec(sizeof(*pm), MEMF_PUBLIC | MEMF_CLEAR);
    int          i;

    if (!pm)
        return NULL;

    pm->port = CreateMsgPort();
    if (!pm->port) {
        FreeVec(pm);
        return NULL;
    }

    pm->cfg     = cfg;
    pm->folders = folders;
    pm->n       = cfg->num_peers;
    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        slot->cfg     = &cfg->peers[i];
        slot->backoff = PEER_BACKOFF_MIN;
        /* Address from the config; without one the peer awaits discovery. */
        slot_set_addr(slot, cfg->peers[i].host, cfg->peers[i].port);
    }
    return pm;
}

unsigned long peer_manager_sigmask(PeerManager *pm)
{
    return pm ? (1UL << pm->port->mp_SigBit) : 0;
}

/* Report a spawn failure ONCE per outage. peer_manager_retry re-attempts on
 * every status tick, and what defeats a spawn is low memory - exactly when a
 * per-tick ERROR line would roll the size-capped log over and erase the
 * evidence of the failure being reported. Cleared by the next success. */
static void spawn_failed(PeerSlot *slot, const char *why)
{
    if (slot->spawn_warned)
        return;
    log_printf(LOG_ERROR, "peer: cannot start a worker for %s (%s)",
               slot->host[0] ? slot->host : "?", why);
    slot->spawn_warned = 1;
}

/* Launch a dialer worker for 'slot', delaying its connect by 'delay' seconds
 * (the backoff). Returns 1 on success. */
static int spawn(PeerManager *pm, PeerSlot *slot, int delay)
{
    WorkerStartup  *st;
    struct Process *proc;

    st = AllocVec(sizeof(*st), MEMF_PUBLIC | MEMF_CLEAR);
    if (!st) {
        spawn_failed(slot, "out of memory");
        return 0;
    }

    st->msg.mn_Node.ln_Type = NT_MESSAGE;
    st->msg.mn_Length       = sizeof(*st);
    st->msg.mn_ReplyPort    = pm->port;

    st->mode = WORKER_DIAL;
    scopy(st->host, slot->host, sizeof(st->host));   /* effective address */
    st->port = slot->port;
    scopy(st->peer_id, slot->cfg->id, sizeof(st->peer_id));
    st->cert_path       = pm->cfg->cert_path;
    st->key_path        = pm->cfg->key_path;
    st->device_name     = pm->cfg->device_name;
    st->cfg             = pm->cfg;
    st->folders         = pm->folders;
    st->connect_timeout = 30;
    st->initial_delay   = delay;
    st->slot            = slot;
    st->peer_cfg        = slot->cfg;   /* shared pause/inbound runtime state */

    proc = CreateNewProcTags(NP_Entry,     (ULONG)worker_entry,
                             NP_Name,      (ULONG)"amisync-worker",
                             NP_StackSize,  WORKER_STACK,
                             TAG_DONE);
    if (!proc) {
        FreeVec(st);
        spawn_failed(slot, "no process");
        return 0;
    }

    slot->spawn_warned = 0;
    slot->proc    = proc;
    slot->startup = st;
    PutMsg(&proc->pr_MsgPort, (struct Message *)st);
    return 1;
}

void peer_manager_start(PeerManager *pm)
{
    int i;
    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (slot->have_addr) {
            log_printf(LOG_INFO, "peer: starting worker for %s:%u",
                       slot->host, slot->port);
            spawn(pm, slot, 0);
        } else {
            log_printf(LOG_INFO, "peer: %.7s awaiting local discovery",
                       slot->cfg->id);
        }
    }
}

/* Fold a finished session into its slot and mark the slot free. Called from
 * both reap paths, so the byte totals and the Hello identity cannot end up
 * folded by one and dropped by the other. Forbid-safe: pure memory. */
static void slot_fold(PeerSlot *s, WorkerStartup *st)
{
    s->tot_in  += st->bytes_in;         /* fold the session into the   */
    s->tot_out += st->bytes_out;        /* per-peer running totals     */
    if (st->peer_name[0])
        scopy(s->rname, st->peer_name, sizeof(s->rname));
    if (st->peer_client[0])
        scopy(s->rclient, st->peer_client, sizeof(s->rclient));
    s->proc    = NULL;
    s->startup = NULL;
}

void peer_manager_handle(PeerManager *pm)
{
    struct Message *m;

    while ((m = GetMsg(pm->port)) != NULL) {
        WorkerStartup *st   = (WorkerStartup *)m;
        PeerSlot      *slot = (PeerSlot *)st->slot;
        int            was_connected = st->connected;
        int            delay;

        log_printf(LOG_INFO, "peer: worker for %s ended (connected=%d, rc=%d)",
                   slot->host, was_connected, st->result);

        slot_fold(slot, st);
        FreeVec(st);

        /* Paused, removed, shutting down or with no address: stay down. */
        if (!dialable(pm, slot))
            continue;

        /* A session that actually connected retries quickly and resets the
         * backoff; repeated failures back off geometrically. */
        if (was_connected) {
            slot->backoff = PEER_BACKOFF_MIN;
            delay = PEER_BACKOFF_MIN;
        } else {
            delay = slot->backoff;
            slot->backoff = (slot->backoff < PEER_BACKOFF_MAX / 2)
                          ? slot->backoff * 2 : PEER_BACKOFF_MAX;
        }
        spawn(pm, slot, delay);
    }
}

/* Re-dial any peer that should have a worker but does not. spawn() can fail
 * (no memory for the startup block, or CreateNewProc refusing a 128 KB stack
 * on a fragmented heap), and nothing else would restart it: the manager is
 * otherwise driven purely by worker replies, so a slot that never got a
 * worker never produces one and the peer stays down until a resume, a
 * discovery event or a restart. Called from the daemon's status tick, the
 * same best-effort retry the AppIcon placement uses. Cheap: a pointer scan.
 *
 * A peer connected INBOUND still gets a dialer here; it stands down as soon
 * as it sees peer_cfg->inbound_st and exits rc=0, which is the existing
 * design (the manager's backoff paces the re-check). */
void peer_manager_retry(PeerManager *pm)
{
    int i;

    if (!pm || pm->shutting_down)
        return;
    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (!dialable(pm, slot))
            continue;
        if (spawn(pm, slot, slot->backoff))
            log_printf(LOG_INFO, "peer: worker for %s:%u started on retry",
                       slot->host, slot->port);
    }
}

/* Reap every queued worker reply WITHOUT respawning. The caller MUST hold
 * Forbid(): a worker frees its Process just after ReplyMsg(), but slot->proc
 * is cleared only when its reply is reaped, so signalling a still-set slot->proc
 * for a worker that already replied would hit freed memory. Draining here (pure
 * GetMsg/FreeVec, Forbid-safe) nulls those slots, and Forbid keeps any not-yet-
 * replied worker from exiting - so after this, a still-set slot->proc is live
 * and safe to Signal. Stats are folded so a reaped session is not lost. */
static void pm_drain_locked(PeerManager *pm)
{
    struct Message *m;
    while ((m = GetMsg(pm->port)) != NULL) {
        WorkerStartup *st = (WorkerStartup *)m;
        slot_fold((PeerSlot *)st->slot, st);
        FreeVec(m);
    }
}

/* Which live slots a signalling pass targets. */
typedef enum {
    PM_ALL,        /* every slot with a running worker */
    PM_PAUSED,     /* only slots whose peer is marked paused  */
    PM_REMOVED     /* only slots whose peer is marked removed */
} PmWho;

/* Signal the selected peers' workers, safely.
 *
 * Reap finished workers the normal way first (which respawns the ones that
 * should keep running), then drain inside Forbid before signalling: a worker
 * frees its Process just after ReplyMsg, but slot->proc is cleared only when
 * its reply is reaped, so signalling a still-set proc for a worker that
 * already replied would hit freed memory. After the drain, Forbid keeps any
 * not-yet-replied worker from exiting, so a still-set slot->proc is live.
 *
 * This sequence is the file's most dangerous invariant; it lives here once. */
static void pm_signal_workers(PeerManager *pm, PmWho who, unsigned long sig)
{
    int i;

    peer_manager_handle(pm);
    Forbid();
    pm_drain_locked(pm);
    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (!slot->proc)
            continue;
        if (who == PM_PAUSED  && !slot->cfg->paused)
            continue;
        if (who == PM_REMOVED && !slot->cfg->removed)
            continue;
        Signal(&slot->proc->pr_Task, sig);
    }
    Permit();
}

void peer_manager_shutdown(PeerManager *pm)
{
    int i, live;

    if (!pm)
        return;

    pm->shutting_down = 1;     /* peer_manager_handle stops respawning */
    pm_signal_workers(pm, PM_ALL, WORKER_SIG_STOP);

    /* Wait for all of them to reply. */
    do {
        peer_manager_handle(pm);            /* reaps any already-finished */
        live = 0;
        for (i = 0; i < pm->n; i++)
            if (pm->slots[i].proc)
                live++;
        if (live)
            WaitPort(pm->port);
    } while (live);

    DeleteMsgPort(pm->port);
    FreeVec(pm);
}

int peer_count(PeerManager *pm)
{
    return pm ? pm->n : 0;
}

void peer_manager_status(PeerManager *pm, char *out, int cap,
                         int *out_connected, int *out_pending)
{
    int i, connected = 0, pending = 0, live = 0, resyncing = 0, kept = 0;
    int reverted = 0;

    if (pm) {
        for (i = 0; i < pm->n; i++) {
            PeerSlot *s = &pm->slots[i];
            int       ip;
            if (s->cfg->removed)
                continue;
            live++;
            /* Live volatile reads from each worker's shared block; only this
             * (main) task frees them, so a read is always safe. */
            {   /* same shape as 'pending' below: two peers deleting the
                 * same file each make their worker keep it, and adding those
                 * up would report one kept file as two. */
                int ik = slot_kept(s, -1);
                if (ik > kept)
                    kept = ik;
            }
            /* SUMMED, unlike the two above, and for the reason they are not:
             * those count files that several peers can each name, so adding
             * them double-counts. A revert is an action performed once, by the
             * one worker that fetched the replacement, so every count belongs
             * to a different event and the total is their sum. */
            reverted += slot_reverted(s, -1);
            if (slot_connected(s, -1, &ip)) {
                connected++;
                /* The LARGEST peer backlog, not their sum. Each worker counts
                 * the files ITS peer has that we do not, and peers sharing a
                 * folder are mostly offering the same files - so adding them
                 * up counts every missing file once per peer. Measured on the
                 * three-node rig: "Syncing (387 files)" with 127 missing,
                 * because two peers each queued the same ~195.
                 *
                 * Neither answer is exact without knowing which names overlap,
                 * which lives in per-worker queues and on disk spills. The max
                 * is a lower bound and the sum an upper one, and the lower is
                 * the better guess: peers sharing a folder normally hold the
                 * same content, so it is usually right, while the sum is
                 * usually wrong by a factor of the peer count. Both preserve
                 * the property that actually matters - it is above zero if any
                 * peer has something we lack, so nothing is ever called
                 * "Up to Date" while a file is missing. */
                if (ip > pending)
                    pending = ip;
                if (ip == 0 && slot_resyncing(s))
                    resyncing++;               /* drained, but not finished */
            } else if (slot_resyncing(s)) {
                /* Counts as up, deliberately: the worker closed the session
                 * itself and is being re-dialled. Calling that "Offline" for
                 * the second it lasts is as wrong as calling it "Up to Date". */
                connected++;
                resyncing++;
            }
        }
    }
    if (out_connected) *out_connected = connected;
    if (out_pending)   *out_pending   = pending;

    /* 'live', not pm->n: the slot count includes tombstones (peer.h says so),
     * so after removing your only peer the headline, ENV:amisync/status and
     * the AppIcon label all read "Offline" forever - reporting a peer that is
     * down when in fact there is none. */
    if (!pm || live == 0)
        scopy(out, "No peers configured", cap);
    else if (connected == 0)
        scopy(out, "Offline", cap);
    else if (pending > 0) {
        char tmp[48];
        sprintf(tmp, "Syncing (%d file%s)", pending, pending == 1 ? "" : "s");
        scopy(out, tmp, cap);
    } else if (resyncing)
        /* No number: the count belongs to a session that has ended and the
         * next one has not said yet. Naming a stale figure would be worse
         * than saying only what is certain - that this is not finished. */
        scopy(out, "Syncing", cap);
    else if (reverted > 0) {
        /* Said BEFORE 'kept': that one reports a disagreement, this one
         * reports that something the user wrote here has been overwritten and
         * now exists only in .stversions. If both are true at once, the
         * overwrite is the thing they need to know about. */
        char tmp[64];
        sprintf(tmp, "Up to Date (%d local edit%s replaced)",
                reverted, reverted == 1 ? "" : "s");
        scopy(out, tmp, cap);
    } else if (kept > 0) {
        /* Nothing left to fetch, but the peer and we disagree about files it
         * deleted and we kept. It counts us out of sync for them for as long
         * as they exist, so "Up to Date" on its own would be this program's
         * word against the other end's, with the other end right. */
        char tmp[48];
        sprintf(tmp, "Up to Date (%d kept)", kept);
        scopy(out, tmp, cap);
    } else
        scopy(out, "Up to Date", cap);
}

int peer_folder_kept(PeerManager *pm, int fidx)
{
    int i, total = 0;

    if (!pm || fidx < 0 || fidx >= CONFIG_MAX_FOLDERS)
        return 0;
    for (i = 0; i < pm->n; i++) {
        int ik;
        if (pm->slots[i].cfg->removed)
            continue;
        ik = slot_kept(&pm->slots[i], fidx);
        if (ik > total)
            total = ik;         /* largest, not the sum - see
                                 * peer_manager_status for why */
    }
    return total;
}

int peer_folder_reverted(PeerManager *pm, int fidx)
{
    int i, total = 0;

    if (!pm || fidx < 0 || fidx >= CONFIG_MAX_FOLDERS)
        return 0;
    for (i = 0; i < pm->n; i++) {
        if (pm->slots[i].cfg->removed)
            continue;
        total += slot_reverted(&pm->slots[i], fidx);   /* summed: see peer.h */
    }
    return total;
}

int peer_folder_pending(PeerManager *pm, int fidx)
{
    int i, total = 0;

    if (!pm || fidx < 0 || fidx >= CONFIG_MAX_FOLDERS)
        return 0;
    for (i = 0; i < pm->n; i++) {
        PeerSlot *s = &pm->slots[i];
        if (s->cfg->removed)
            continue;
        {
            int ip;
            if (slot_connected(s, fidx, &ip) && ip > total)
                total = ip;     /* largest backlog, not the sum - see
                                 * peer_manager_status for why */
        }
    }
    return total;
}

int peer_pending(PeerManager *pm, int i)
{
    PeerSlot *s;
    int       ip;

    if (!pm || i < 0 || i >= pm->n)
        return 0;
    s = &pm->slots[i];
    if (s->cfg->removed)
        return 0;
    /* Volatile read of the worker's shared block; safe live for the same
     * reason as in peer_manager_status (only this task ever frees it). */
    slot_connected(s, -1, &ip);
    return ip;
}

const ConfigPeer *peer_info(PeerManager *pm, int i, int *running, int *connected,
                            int *paused, const char **host, unsigned short *port)
{
    PeerSlot *slot;

    if (!pm || i < 0 || i >= pm->n)
        return NULL;

    slot = &pm->slots[i];
    if (slot->cfg->removed)
        return NULL;
    if (running)
        *running = slot->proc != NULL;
    /* 'connected' is a volatile flag the worker sets in its own (shared-memory)
     * startup block once it reaches the BEP-connected state; safe to read live
     * because the manager only frees that block here in the main task. */
    if (connected)
        *connected = slot_connected(slot, -1, NULL);
    if (paused)
        *paused = slot->cfg->paused;
    if (host)
        *host = slot->have_addr ? slot->host : "";
    if (port)
        *port = slot->port;
    return slot->cfg;
}

void peer_xfer_info(PeerManager *pm, int i, unsigned long long *in_bytes,
                    unsigned long long *out_bytes, const char **rname,
                    const char **rclient)
{
    PeerSlot           *slot;
    WorkerStartup      *st;
    unsigned long long  in_extra = 0, out_extra = 0;   /* inbound sessions */

    if (in_bytes)  *in_bytes  = 0;
    if (out_bytes) *out_bytes = 0;
    if (rname)     *rname     = "";
    if (rclient)   *rclient   = "";
    if (!pm || i < 0 || i >= pm->n)
        return;

    slot = &pm->slots[i];
    st   = slot->startup;    /* live worker's counters, same contract as
                              * 'connected' in peer_info above */
    /* Inbound sessions never pass through this slot - the listener spawns and
     * reaps those workers - so harvest what they have moved before answering:
     * the finished ones from the shared ConfigPeer, plus the live one if there
     * is one. Unlike 'connected', these ARE addends and not a fallback: over a
     * peer's life we may have dialled it at one time and been dialled by it at
     * another, and both directions moved real bytes. The live load and
     * dereference sit inside Forbid() for the reason inbound_connected
     * documents - the worker clears the pointer and the listener frees the
     * block, both from other tasks. The identity is COPIED into the slot for
     * the same reason: a pointer into that block would dangle the moment the
     * session ends, and copying also keeps the name once it has. */
    if (slot->cfg) {
        Forbid();
        {
            WorkerStartup *ist = slot->cfg->inbound_st;
            if (ist) {
                in_extra  = ist->bytes_in;
                out_extra = ist->bytes_out;
                if (ist->peer_name[0])
                    scopy(slot->rname, ist->peer_name, sizeof(slot->rname));
                if (ist->peer_client[0])
                    scopy(slot->rclient, ist->peer_client, sizeof(slot->rclient));
            }
        }
        Permit();
        in_extra  += slot->cfg->in_bytes_in;
        out_extra += slot->cfg->in_bytes_out;
    }

    if (in_bytes)
        *in_bytes = slot->tot_in + (st ? st->bytes_in : 0) + in_extra;
    if (out_bytes)
        *out_bytes = slot->tot_out + (st ? st->bytes_out : 0) + out_extra;
    if (rname)
        *rname = (st && st->peer_name[0]) ? (const char *)st->peer_name
                                          : slot->rname;
    if (rclient)
        *rclient = (st && st->peer_client[0]) ? (const char *)st->peer_client
                                              : slot->rclient;
}

int peer_pause(PeerManager *pm, const char *id)
{
    int all = (!id || !id[0]);
    int i, count = 0;

    if (!pm)
        return 0;

    /* Mark the target peers paused first. */
    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (slot->cfg->removed)
            continue;
        if (!all && !device_id_equal(slot->cfg->id, id))
            continue;
        slot->cfg->paused = 1;
        count++;
        /* No early break on a targeted match: config duplicates are now
         * refused, but a tombstoned slot and its resurrection can both carry
         * the same id, and stopping at the first would leave the other live -
         * pausing "the" device while it kept syncing. */
    }

    /* Stop the workers of every paused peer. Signalling one that was already
     * paused is a no-op: its worker exited when it was paused, so its slot
     * holds no proc. */
    pm_signal_workers(pm, PM_PAUSED, WORKER_SIG_STOP);

    /* Wake every connected worker (both directions - the listener's inbound
     * workers too, which the STOP signals above cannot reach): each re-checks
     * its peer's pause flag at the top of its loop and a paused one closes
     * its connection promptly instead of on the next idle tick. */
    wreg_signal(WORKER_SIG_RESCAN);
    return count;
}

int peer_resume(PeerManager *pm, const char *id)
{
    int all = (!id || !id[0]);
    int i, count = 0;

    if (!pm || pm->shutting_down)
        return 0;

    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (slot->cfg->removed)
            continue;                       /* removed stays removed */
        if (!all && !device_id_equal(slot->cfg->id, id))
            continue;
        if (slot->cfg->paused) {
            slot->cfg->paused  = 0;
            slot->backoff = PEER_BACKOFF_MIN;
            if (dialable(pm, slot))               /* dial again now */
                spawn(pm, slot, 0);
        }
        count++;
        /* Every match, as in peer_pause. */
    }
    return count;
}

void peer_manager_discovered(PeerManager *pm, const char *id,
                             const char *host, unsigned short port)
{
    int i;

    if (!pm || pm->shutting_down || !host || !host[0] || port == 0)
        return;

    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (slot->cfg->removed || !device_id_equal(slot->cfg->id, id))
            continue;

        /* Update the dial address; if nothing changed and a worker is already
         * up, leave it. */
        if (slot->have_addr && slot->port == port &&
            strcmp(slot->host, host) == 0 && slot->proc)
            return;

        slot_set_addr(slot, host, port);

        if (dialable(pm, slot)) {          /* idle: dial the new address now */
            slot->backoff = PEER_BACKOFF_MIN;
            log_printf(LOG_INFO, "peer: discovered %.7s at %s:%u, dialing",
                       slot->cfg->id, host, (unsigned)port);
            spawn(pm, slot, 0);
        }
        return;
    }
}

int peer_manager_has(PeerManager *pm, const char *id)
{
    int i;

    if (!pm || !id)
        return 0;
    for (i = 0; i < pm->n; i++)
        if (!pm->slots[i].cfg->removed &&
            device_id_equal(pm->slots[i].cfg->id, id))
            return 1;
    return 0;
}

int peer_manager_remove(PeerManager *pm, const char *id)
{
    int i, found = 0;

    if (!pm || !id || !id[0])
        return 0;

    for (i = 0; i < pm->n; i++) {
        PeerSlot *slot = &pm->slots[i];
        if (slot->cfg->removed || !device_id_equal(slot->cfg->id, id))
            continue;
        /* Tombstone, never compact: workers hold pointers into cfg->peers[]
         * and into this slot. 'paused' rides along so every existing pause
         * check (don't dial, refuse inbound, close live connections) does
         * the enforcement without new machinery. */
        slot->cfg->removed = 1;
        slot->cfg->paused  = 1;
        found = 1;
        /* Every match, as in peer_pause: a slot left live here would keep
         * dialling a device the user just removed, and peer_manager_has
         * (which scans them all) would go on reporting it configured - so it
         * would never reappear under Discovered and could not be re-added. */
    }
    if (!found)
        return 0;

    pm_signal_workers(pm, PM_REMOVED, WORKER_SIG_STOP);
    wreg_signal(WORKER_SIG_RESCAN);    /* inbound workers re-check promptly */
    log_printf(LOG_INFO, "peer: %.7s removed", id);
    return 1;
}

int peer_manager_add(PeerManager *pm, const char *id, const char *host,
                     unsigned short port)
{
    Config     *cfg;
    ConfigPeer *p;
    PeerSlot   *slot;
    char        canon[DEVICE_ID_BUFSZ];
    int         i;

    if (!pm || !id || !device_id_normalize(id, canon))
        return 0;
    if (peer_manager_has(pm, canon))
        return -1;

    /* A tombstoned (removed) slot for this device is resurrected instead of
     * appending a duplicate entry. */
    for (i = 0; i < pm->n; i++) {
        slot = &pm->slots[i];
        if (!slot->cfg->removed || !device_id_equal(slot->cfg->id, canon))
            continue;
        slot->cfg->removed = 0;
        slot->cfg->paused  = 0;
        if (host && host[0]) {
            scopy(slot->cfg->host, host, sizeof(slot->cfg->host));
            slot->cfg->port = port ? port : CONFIG_DEFAULT_PORT;
            slot_set_addr(slot, slot->cfg->host, slot->cfg->port);
        }
        slot->backoff = PEER_BACKOFF_MIN;
        log_printf(LOG_INFO, "peer: %.7s re-added at runtime", canon);
        if (dialable(pm, slot))
            spawn(pm, slot, 0);
        return 1;
    }

    cfg = pm->cfg;
    if (cfg->num_peers >= CONFIG_MAX_PEERS)
        return -2;
    if (pm->n != cfg->num_peers) {
        /* Slots and config entries are appended together and never compacted,
         * so this cannot happen; if it does, appending would misalign every
         * slot's cfg pointer. Refuse, and say so - the caller's "table full"
         * message would send the user looking in the wrong place. */
        log_printf(LOG_ERROR, "peer: slot/config count mismatch (%d vs %d) - "
                   "refusing to add %.7s", pm->n, cfg->num_peers, canon);
        return -3;
    }

    /* Extend the config's peer table in place (the slot and the workers hold
     * pointers into it, so it must be THE table, not a copy). */
    p = &cfg->peers[cfg->num_peers];
    memset(p, 0, sizeof(*p));
    scopy(p->id, canon, sizeof(p->id));
    if (host && host[0]) {
        scopy(p->host, host, sizeof(p->host));
        p->port = port ? port : CONFIG_DEFAULT_PORT;
    }
    cfg->num_peers++;

    slot = &pm->slots[pm->n];
    memset(slot, 0, sizeof(*slot));
    slot->cfg     = p;
    slot->backoff = PEER_BACKOFF_MIN;
    slot_set_addr(slot, p->host, p->port);
    pm->n++;

    if (slot->have_addr) {
        log_printf(LOG_INFO, "peer: %.7s added at runtime (%s:%u), dialing",
                   p->id, p->host, (unsigned)p->port);
        if (dialable(pm, slot))
            spawn(pm, slot, 0);
    } else {
        log_printf(LOG_INFO,
                   "peer: %.7s added at runtime, awaiting local discovery",
                   p->id);
    }
    return 1;
}

void peer_rescan(PeerManager *pm)
{
    if (!pm)
        return;

    pm_signal_workers(pm, PM_ALL, WORKER_SIG_RESCAN);
}
