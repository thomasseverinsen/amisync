/* worker.c - per-peer connection worker (process) for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See worker.h. The worker runs in its own process: it opens AmiSSL/bsdsocket
 * for itself, dials or adopts a socket, completes the TLS 1.3 handshake with
 * Syncthing's trust model (accept any cert at the X.509 layer, then pin on the
 * peer's derived device ID), runs the BEP handshake, and sits connected.
 *
 * The worker is pure transport over the shared per-folder index
 * (FolderState, owned by main, scanned/hashed by the scanner process). It does
 * NOT scan or hash. It:
 *   - announces records to its peer via a per-peer sequence cursor: each pass
 *     streams the folder's records whose 'sequence' exceeds the cursor (the
 *     initial Index when the cursor is 0, IndexUpdates thereafter), copying the
 *     stored block hashes straight out - no file re-read;
 *   - on receive, writes results back into the shared index under its lock
 *     (upsert + foldstate_next_seq). That sequence bump is what relays a file to
 *     the OTHER peers' workers automatically (their cursors fall behind, so they
 *     re-announce it) - peer->peer propagation for free.
 */

#include <string.h>

#include <exec/ports.h>
#include <exec/memory.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <openssl/ssl.h>

#include "netbase.h"     /* pulls in <proto/bsdsocket.h> bound to this task's base */
#include "worker.h"
#include "foldstate.h"
#include "wreg.h"
#include "spill.h"
#include "offered.h"
#include "ssl.h"
#include "net.h"
#include "bep.h"
#include "folder.h"
#include "syncmodel.h"
#include "device_id.h"
#include "log.h"
#include "version.h"

/* bep.h states two cross-module invariants in prose, and this is the file that
 * has all three headers in scope to check them: a framed message must be able
 * to carry a whole block, and a version vector must hold one counter per peer
 * we support. Breaking either fails quietly at runtime - transfers capped below
 * the advertised block size, or truncated vectors that invent conflicts - so
 * fail the build instead. Negative array size = the C89 static assert. */
typedef char bep_msg_holds_a_block[BEP_MSG_MAX >= FOLDER_MAX_BLOCK_SIZE ? 1 : -1];
typedef char bep_counters_hold_peers[BEP_MAX_COUNTERS >= CONFIG_MAX_PEERS ? 1 : -1];

/* How often (seconds) we send a keepalive Ping while idle, and re-announce any
 * records the scanner has advanced since the last pass. Syncthing pings on a
 * similar cadence and treats a long silence as a dead connection. */
#define WORKER_PING_SECS  60

/* How long an ACCEPTED connection may stay silent before we hang up. This is
 * the only bound on an unauthenticated inbound peer: it holds one of the
 * LISTEN_MAX_INBOUND slots (and this worker's 128 KB stack) from the moment
 * the TCP connection is accepted until the TLS handshake finishes or fails.
 * Generous enough that a real peer on a slow link is never cut off - its
 * ClientHello is already in flight when we start waiting - and short enough
 * that the table cannot be pinned shut. */
#define WORKER_HELLO_SECS  20

/* Length-bounded copy that always NUL-terminates. */
static void scopy(char *dst, const char *src, int cap)
{
    int n = (int)strlen(src);
    if (n > cap - 1)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ---- BEP transport bound to an SSL session -------------------------- */

static int w_read(void *ctx, void *buf, int len)
{
    return ssl_read((SSL *)ctx, buf, len);
}

static int w_write(void *ctx, const void *buf, int len)
{
    return ssl_write((SSL *)ctx, buf, len);
}

/* True if 'id' matches any peer in the configured list. */
static int id_in_peer_list(const Config *cfg, const char *id)
{
    int i;
    for (i = 0; i < cfg->num_peers; i++)
        if (device_id_equal(id, cfg->peers[i].id))
            return 1;
    return 0;
}

/* Verify the peer is who we expect: ALPN must be bep/1.0, and the peer cert's
 * derived device ID must be trusted. For a dialer that means matching the ID
 * we dialed; for an inbound connection (no expected ID) it means appearing in
 * the configured peer list. Records the observed ID either way. Returns 1 if
 * trusted. */
static int verify_peer(SSL *ssl, WorkerStartup *st)
{
    unsigned char der[4096];
    char          id[DEVICE_ID_BUFSZ];
    char          alpn[16];
    int           dl;

    log_printf(LOG_INFO, "worker: TLS cipher %s", SSL_get_cipher_name(ssl));

    if (!ssl_get_alpn(ssl, alpn, sizeof(alpn)) || strcmp(alpn, "bep/1.0") != 0) {
        log_printf(LOG_WARN, "worker: peer did not negotiate bep/1.0 ALPN");
        return 0;
    }

    dl = ssl_get_peer_cert_der(ssl, der, sizeof(der));
    if (dl <= 0 || !device_id_from_cert_der(der, dl, id)) {
        log_printf(LOG_WARN, "worker: could not derive peer device ID");
        return 0;
    }

    scopy(st->peer_actual_id, id, sizeof(st->peer_actual_id));

    if (st->peer_id[0]) {                       /* dialer: must be who we dialed */
        if (!device_id_equal(id, st->peer_id)) {
            log_printf(LOG_WARN, "worker: peer is %s, expected %s (rejecting)",
                       id, st->peer_id);
            return 0;
        }
    } else if (!st->cfg || !id_in_peer_list(st->cfg, id)) {  /* inbound: must be listed */
        log_printf(LOG_WARN, "worker: inbound peer %s not in peer list (rejecting)", id);
        return 0;
    }

    log_printf(LOG_INFO, "worker: peer authenticated as %s", id);
    return 1;
}

/* Which folders may appear in our ClusterConfig: a folder joins once its
 * FIRST scan has completed, or its (persisted) index already holds
 * records. Announcing a freshly-added folder before the scanner has
 * hashed it loses the adopt race: the peer's Index arrives against an
 * EMPTY local index, so every file - identical or not - classifies as a
 * fetch (seen live on the A4000: a folder remove/re-add re-transferred
 * 6 unchanged files). Syncthing sequences it the same way: scan first,
 * share after. Bit i = config folder slot i; NULL 'folders' (no shared
 * index) leaves everything eligible. */
static unsigned long cc_eligible_mask(const Config *cfg, FolderState *folders)
{
    unsigned long m = 0;
    int i;

    if (!cfg)
        return 0;
    for (i = 0; i < cfg->num_folders && i < CONFIG_MAX_FOLDERS; i++) {
        int ok;
        if (cfg->folders[i].removed)
            continue;
        if (!folders) {
            m |= 1UL << i;
            continue;
        }
        foldstate_lock(&folders[i]);
        ok = folders[i].scan_day || folders[i].scan_min ||
             folders[i].num_files > 0;
        foldstate_unlock(&folders[i]);
        if (ok)
            m |= 1UL << i;
    }
    return m;
}

/* Build the ClusterConfig we announce to this peer: every configured folder
 * whose 'mask' bit is set (cc_eligible_mask), listing us and the peer as
 * its two devices (by raw 32-byte device key). 'peer_raw' may be NULL if
 * the peer's key is unavailable. */
static void build_cluster_config(const Config *cfg, FolderState *folders,
                                 const unsigned char our_raw[32],
                                 const unsigned char *peer_raw,
                                 const char *our_name,
                                 BepClusterConfig *cc,
                                 unsigned long mask)
{
    int i;

    memset(cc, 0, sizeof(*cc));
    for (i = 0; i < cfg->num_folders && cc->num_folders < BEP_MAX_FOLDERS; i++) {
        BepFolder          *f;
        const ConfigFolder *cf;
        if (cfg->folders[i].removed)
            continue;
        if (i >= CONFIG_MAX_FOLDERS)   /* 'mask' cannot describe it: skip */
            continue;
        if (!(mask & (1UL << i)))
            continue;                  /* unscanned fresh folder: not yet */
        f  = &cc->folders[cc->num_folders++];
        cf = &cfg->folders[i];

        scopy(f->id, cf->id, sizeof(f->id));
        scopy(f->label, cf->label, sizeof(f->label));
        f->type = (int)cf->mode;            /* FolderMode == FolderType wire values */

        memcpy(f->devices[0].id, our_raw, 32);
        scopy(f->devices[0].name, our_name, sizeof(f->devices[0].name));
        /* Our index metadata - see BepDevice: a repeated CC without it reads
         * as an index regression to Syncthing. BOTH fields are read under the
         * lock: they are 64-bit (not atomic on the 68k) and a runtime re-add
         * of this folder re-keys them together, so a CC must not carry the
         * new index_id beside the old sequence. */
        if (folders) {
            FolderState *fs = &folders[i];
            foldstate_lock(fs);
            f->devices[0].index_id     = fs->index_id;
            f->devices[0].max_sequence = fs->sequence;
            foldstate_unlock(fs);
        }
        f->num_devices = 1;
        if (peer_raw) {
            memcpy(f->devices[1].id, peer_raw, 32);
            f->num_devices = 2;
        }
    }
}

/* ---- sync engine (transport over the shared index) --------- */

#define WK_TMP_MAX         320   /* room for a joined folder/name/temp path     */
#define WK_MAX_RETRY         3   /* per-block re-requests before giving up      */
#define WK_MAX_DEFER        32   /* deletions held back within one Index msg    */
#define WK_DIR_DEL_TRIES     3   /* FRUITLESS flushes before a drawer is given up */
#define WK_MAX_KEPT         32   /* contested names tracked per folder          */
#define WK_MAX_GONE        256   /* names a peer deleted while we had them parked */
#define DEFER_DONE        0xFF   /* defer_tries marker: settled, drop the entry */
#define WK_WINDOW            4   /* block Requests kept in flight (pipelining)  */
/* FileInfo entries packed into one Index/IndexUpdate. The real limit is the
 * send buffer (a batch stops early when the next entry will not fit), so this
 * only bounds how large one message gets when the entries are small - which is
 * the common case, an index record being a couple of hundred bytes. 256 keeps
 * a message in the tens of KB: big enough that the per-message cost stops
 * mattering, small enough that a peer sees progress rather than one huge
 * blocking write. */
#define WK_INDEX_BATCH     256
#define WK_MAX_FETCH         3   /* attempts at one file before we stop trying  */
#define WK_MAX_STALLED       8   /* given-up files remembered for the backlog   */

/* One outstanding block Request of the in-flight download. */
typedef struct {
    int block;                   /* block index requested                    */
    int id;                      /* its request id                           */
    int retries;                 /* re-requests of this block so far         */
} Inflight;

/* The in-flight download. Up to WK_WINDOW block Requests are outstanding at
 * once, so the peer's serve latency overlaps our disk writes instead of adding
 * a full round trip per block. The peer may answer them in ANY order, but the
 * staged temp can only be written forward (see FolderWriteResult), so a block
 * that arrives ahead of its turn goes on the same small redo list as a block
 * that failed verify and is re-requested (WK_MAX_RETRY per block for a failure;
 * reordering is not charged) ahead of fresh ones. The struct carries the file's
 * lean metadata plus the expected per-block hashes captured from the peer's
 * FileInfo - the same hashes we store in the shared index on completion. */
typedef struct {
    int        active;
    int        folder_idx;
    SyncMeta   fi;
    int        attempts;         /* fetches of this file so far, incl. this  */
    int        num_blocks;
    int        next_block;       /* next fresh block to request              */
    int        resumed;          /* temp carried blocks from an earlier run  */
    Inflight   inflight[WK_WINDOW];
    int        num_inflight;
    Inflight   redo[WK_WINDOW];  /* failed blocks awaiting re-request        */
    int        num_redo;
    FolderFile fh;               /* open temp file                           */
    char       folder_id[BEP_FOLDER_ID_MAX];
    char       tmp[WK_TMP_MAX];  /* temp file path (for finish/abort)        */
    unsigned char hashes[FOLDER_MAX_BLOCKS][BEP_HASH_LEN];  /* expected */
} Download;

/* All per-connection state. The index/version/sequence live in the shared
 * FolderState (S->folders); the worker owns the transport, the want queue +
 * in-flight download, the per-folder announce cursor, and scratch buffers. One
 * big heap allocation per worker. */
typedef struct {
    /* 'st' and 'cfg' are copied from the startup message and never reassigned;
     * peer.c and listener.c always populate both, and nearly every function
     * here dereferences them without checking - so they are invariants of a
     * constructed Sync, not optional fields. */
    BepConn       *conn;
    SSL           *ssl;           /* the session under conn (for ssl_buffered) */
    WorkerStartup *st;            /* shared block: publish live 'pending' here */
    int            sock;
    const Config  *cfg;
    FolderState   *folders;       /* shared, [cfg->num_folders]                */
    int            next_req_id;
    SyncModel      model;         /* want queue only (index lives in FolderState) */
    Download       dl;
    int64_t        cursor[CONFIG_MAX_FOLDERS];   /* highest seq told this peer  */
    int            announced[CONFIG_MAX_FOLDERS];/* sent the folder's Index yet */
    /* Per-folder ignore sets, allocated only for folders whose .stignore
     * actually has patterns (the set is ~6 KB and most folders have none);
     * NULL means "nothing ignored". Gates what we fetch and serve. */
    IgnoreSet     *ignores[CONFIG_MAX_FOLDERS];
    /* Scratch block-hash list: filled by index_block_cb when decoding an inbound
     * FileInfo, or by foldstate_blocks when announcing one of ours. */
    unsigned char  bh[FOLDER_MAX_BLOCKS][BEP_HASH_LEN];
    /* Serve-side scratch for one outbound block. Heap-allocated on demand and
     * grown toward FOLDER_MAX_BLOCK_SIZE: a worker that only ever serves the
     * default 128 KiB block never allocates the full 1 MiB. NULL until the first
     * block is served (sync_ensure_blockbuf). Also reused by local_prefill to
     * copy blocks out of a local same-content file (rename detection). */
    unsigned char *blockbuf;
    int32_t        blockbuf_cap;
    /* Our device ID's 7-char prefix, tagging conflict copies Syncthing-style. */
    char           ctag[8];
    /* Deletions held back within/past the current Index message. Files: a
     * peer's rename arrives as delete(old) + add(new, same content); a file
     * tombstone whose file's content matches a queued/active fetch stays here -
     * old file untouched on disk and in the index - so local_prefill can copy
     * its blocks instead of pulling them over the network. Dirs: parked so
     * they apply after the file tombstones and find themselves empty.
     * flush_deferred() applies entries (re-classified/re-guarded at apply
     * time) once no pending fetch needs them. */
    int            num_defer;
    int            defer_fidx[WK_MAX_DEFER];
    unsigned char  defer_tries[WK_MAX_DEFER];  /* dir deletes: flushes attempted */
    SyncMeta       defer[WK_MAX_DEFER];
    /* Fingerprint of each folder's ignore set, so a .stignore edit mid-session
     * can be noticed and said out loud (see refresh_ignores). 'valid' keeps
     * the first load - which necessarily "changes" the fingerprint from
     * nothing - from announcing itself. */
    unsigned long  ign_fp[CONFIG_MAX_FOLDERS];
    unsigned char  ign_fp_seen[CONFIG_MAX_FOLDERS];
    /* Each folder's need generation as it stood when this session started.
     * A difference means something here now wants what this peer's already
     * delivered Index can no longer tell us about, and only a fresh Index
     * can - see need_gen in foldstate.h. */
    int64_t        need_gen[CONFIG_MAX_FOLDERS];
    /* Folder-set change detection: snapshots of Config.config_gen and each
     * ConfigFolder.gen, taken at connect. On a mismatch the worker re-sends
     * its ClusterConfig IN-BAND (modern BEP/Syncthing accepts an updated CC
     * mid-session) and resets the announce cursor of each changed folder so
     * its index streams from scratch. The raw device keys are kept from the
     * handshake for the rebuild. */
    int            cfg_gen;
    int            fgen[CONFIG_MAX_FOLDERS];
    unsigned char  our_raw[32], peer_raw[32];
    int            have_our_raw, have_peer_raw;
    /* Which of OUR folders the peer's ClusterConfig also lists. We may only
     * announce an Index for MUTUALLY shared folders: Syncthing answers an
     * Index for a folder it does not share with us by DROPPING the whole
     * connection (a reconnect kill-loop, since we would just do it again).
     * Zero until the peer's CC arrives - announcing waits for it, exactly
     * as Syncthing itself sequences the exchange. Updated on every CC the
     * peer sends (it re-sends in-band when its sharing changes - e.g. the
     * user accepts a folder we offered - which is what starts our announce
     * without any reconnect). */
    unsigned char  peer_shares[CONFIG_MAX_FOLDERS];
    /* An Index message held more fetches than the want queue/hash pool could
     * take, and the excess was dropped (there is no BEP "resend" - the peer
     * only re-sends its full Index on a fresh connection). Once every queued
     * fetch has drained, worker_sync closes the session cleanly so the
     * reconnect (quick: a connected session resets the dial backoff) brings
     * the next batch; files already fetched classify as SYNC_NONE, so each
     * cycle strictly shrinks the remainder and the loop terminates. */
    int            want_overflow;
    /* Files this session tried WK_MAX_FETCH times and gave up on. They stay
     * counted in the published backlog: dropping a failed fetch silently let
     * the daemon report "Up to Date" with the file still missing, and BEP has
     * no resend - only a fresh connection re-offers it. Names are kept rather
     * than a bare count so a file the peer re-offers mid-session is not
     * counted twice. The list is small on purpose: WK_MAX_STALLED failures in
     * one session is not a backlog to account for precisely, it is a folder
     * that needs looking at, so the overflow is logged and left uncounted. */
    /* Folder whose fetch claim we hold (-1 = none). A worker fetches one file
     * at a time, so one claim; it must be released on every path out of a
     * download, teardown included. */
    int            claim_fidx;
    /* The peer's deletions we have declined, BY NAME (a hash of it - the names
     * themselves would be 8 KB of Sync for a status line). Kept as a set, not
     * a counter, because the disagreement usually ends: the peer applies the
     * same data-beats-a-delete rule we do, takes our version, and sends the
     * file back as LIVE - at which point it must stop being counted. A counter
     * cannot do that; a set removes the name when the peer changes its mind.
     * Reset per folder when a full Index restates it. At most WK_MAX_KEPT are
     * tracked: past that the number is only a signal that something diverges,
     * which is all it ever needed to be. */
    uint32_t       kept_h[CONFIG_MAX_FOLDERS][WK_MAX_KEPT];
    int            kept_n[CONFIG_MAX_FOLDERS];
    /* Names the peer has deleted that we never had a record of - which is
     * exactly the shape of a file still sitting in the spill. Parking made
     * that possible: a record can now wait minutes (35 of them, on the A4000's
     * 2500-file first sync) between the peer offering a file and us fetching
     * it, and a deletion arriving in between leaves no trace anywhere else,
     * because there is no local record to tombstone. Without this the drain
     * would ask for a file the peer has thrown away, get "no such file" three
     * times, count it out of sync, and leave the partial it opened to hold its
     * drawer un-deletable for a week. */
    uint32_t       gone_h[CONFIG_MAX_FOLDERS][WK_MAX_GONE];
    int            gone_n[CONFIG_MAX_FOLDERS];
    /* Wanted files that did not fit in the want queue, parked on disk instead
     * of dropped (see spill.h). One per folder, created on the first overflow
     * and thrown away when a full Index restates the folder or the session
     * ends. While these hold anything, the queue refills from them rather than
     * from a reconnect. */
    SpillFile      spill[CONFIG_MAX_FOLDERS];
    /* Deletions held back past the in-memory defer list, for the same reason
     * that list exists: a peer's rename is delete(old) + add(new, same
     * content), and 'old' has to stay on disk until 'new' is fetched or
     * local_prefill has nothing to copy from and the bytes come over the wire
     * again. The list holds 32; a renamed drawer holds as many files as it
     * holds. These are applied once the fetch queue and the want spill are
     * both empty - by then nothing can still need a source. */
    SpillFile      spill_del[CONFIG_MAX_FOLDERS];
    int            num_stalled;
    int            stalled_fidx[WK_MAX_STALLED];
    char           stalled_name[WK_MAX_STALLED][BEP_PATH_MAX];
    /* Folders our LAST ClusterConfig listed (cc_eligible_mask at the time):
     * announce_folder streams Index only for these - sending an Index for a
     * folder our CC does not list makes Syncthing drop the connection. A
     * fresh folder finishing its first scan flips its bit, which is what
     * triggers the mid-session CC resend. */
    unsigned long  cc_mask;
} Sync;

/* Inflate a lean SyncMeta into a BepFileInfo (no blocks; carries content_hash). */
static void fileinfo_from_meta(BepFileInfo *fi, const SyncMeta *m)
{
    memset(fi, 0, sizeof(*fi));
    scopy(fi->name, m->name, sizeof(fi->name));
    fi->type             = m->type;
    fi->size             = m->size;
    fi->permissions      = m->permissions;
    fi->modified_s       = m->modified_s;
    fi->modified_ns      = m->modified_ns;
    fi->modified_by      = m->modified_by;
    fi->deleted          = m->deleted;
    fi->invalid          = m->invalid;
    fi->sequence         = m->sequence;
    fi->block_size       = m->block_size;
    fi->version          = m->version;
    fi->has_content_hash = m->has_content_hash;
    if (m->has_content_hash)
        memcpy(fi->content_hash, m->content_hash, BEP_HASH_LEN);
}

/* Lean SyncMeta from a fully-populated BepFileInfo (drops the block array; the
 * block hashes, when we keep them, are passed to foldstate_upsert separately). */
static void note_wanted(Sync *S, int fidx, const BepFileInfo *fi);

static void meta_from_fileinfo(SyncMeta *m, const BepFileInfo *fi)
{
    memset(m, 0, sizeof(*m));
    scopy(m->name, fi->name, sizeof(m->name));
    m->type             = fi->type;
    m->size             = fi->size;
    m->permissions      = fi->permissions;
    m->modified_s       = fi->modified_s;
    m->modified_ns      = fi->modified_ns;
    m->modified_by      = fi->modified_by;
    m->deleted          = fi->deleted;
    m->invalid          = fi->invalid;
    m->sequence         = fi->sequence;
    m->block_size       = fi->block_size;
    m->version          = fi->version;
    m->has_content_hash = fi->has_content_hash;
    if (fi->has_content_hash)
        memcpy(m->content_hash, fi->content_hash, BEP_HASH_LEN);
}

/* Are we already fetching this file (in flight or queued)? */
static int wk_pending(const Sync *S, int folder_idx, const char *name)
{
    if (S->dl.active && S->dl.folder_idx == folder_idx &&
        strcmp(S->dl.fi.name, name) == 0)
        return 1;
    return sync_want_has(&S->model, folder_idx, name);
}

/* ---- announce: stream records with sequence > cursor[folder] -------- */

/* Send one record (already copied out of FolderState) to the peer. 'first'
 * selects the folder's establishing Index vs an IndexUpdate. 'blocks'/'nb' are
 * the record's stored block hashes (0 for dirs and tombstones). Returns 1 on a
 * sent message, 0 on a transport error. */
static int send_record(Sync *S, int fidx, const SyncMeta *m, int first,
                       const unsigned char (*blocks)[BEP_HASH_LEN], int nb)
{
    const ConfigFolder *f    = &S->cfg->folders[fidx];
    int                 type = first ? BEP_INDEX : BEP_INDEX_UPDATE;
    BepFileInfo         fi;

    fileinfo_from_meta(&fi, m);
    if (m->type == BEP_FILE_FILE && !m->deleted)
        return bep_send_index_file(S->conn, type, f->id, &fi, blocks, nb);
    return bep_send_index(S->conn, type, f->id, &fi, 1);
}

/* Tell the peer we share this folder by sending an empty Index, once. That is
 * what makes it start sending; a folder we never announce is one it will not
 * offer us anything for. Returns the transport result (1 if already done). */
static int establish_folder(Sync *S, int fidx)
{
    if (S->announced[fidx])
        return 1;
    if (!bep_send_index(S->conn, BEP_INDEX, S->cfg->folders[fidx].id, NULL, 0))
        return 0;
    S->announced[fidx] = 1;
    return 1;
}

/* One announce pass over one folder: stream every record whose sequence is in
 * (cursor, snapshot], advancing the cursor to snapshot. Records are copied out
 * (with their block hashes) UNDER the lock and sent OUTSIDE it. Returns 0 on a
 * transport error. */
static int announce_folder(Sync *S, int fidx)
{
    FolderState *fs = &S->folders[fidx];
    int64_t      snapshot;
    int          num, i, first;
    int64_t      pgen;
    int          recvonly;
    uint64_t     short_id;
    BepIndexBatch batch;
    BepFileInfo   fi;
    int           batching = 0;

    /* Never announce a folder our own ClusterConfig has not (yet) listed -
     * Syncthing answers an Index for an unshared folder by dropping the
     * connection. A fresh folder's bit sets once its first scan completes
     * (see cc_eligible_mask), which also resends the CC. */
    if (fidx >= CONFIG_MAX_FOLDERS)        /* every array below is this size */
        return 1;
    if (!(S->cc_mask & (1UL << fidx)))
        return 1;

    /* A receive-only folder announces what it MIRRORS but never what it
     * originates. Announcing a record we hold exactly as the peer produced it
     * - the peer's own version vector, untouched - cannot overwrite anything:
     * the peer compares vectors, finds them equal, and does nothing. What must
     * never go out is a record carrying a counter of OURS, which is the claim
     * "this device changed the file" and is precisely what this mode forbids.
     *
     * Announcing nothing at all (what this did before) is not a safer version
     * of that rule, it is a wrong one: with no index from us the peer assumes
     * we hold none of the folder, and shows this device stuck short of 100%
     * for ever - the 67 bytes of a two-file test folder read as "99%". It also
     * silently defeated announce_unstorable, whose whole purpose is to tell
     * the peer "I knowingly cannot store this file".
     *
     * The scanner already keeps local state out of a receive-only index (it
     * FORGETS an edited record rather than updating it, and never tombstones),
     * so in practice nothing here carries our counter. The filter is applied
     * per record anyway rather than trusted as a global invariant: the conflict
     * path in preserve_conflict_copy does stamp our short_id, and a rule this
     * mode's promise rests on should be enforced where it is relied upon. */
    recvonly = (S->cfg->folders[fidx].mode == FOLDER_RECEIVEONLY);

    foldstate_lock(fs);
    snapshot = fs->sequence;
    num      = fs->num_files;
    pgen     = fs->prune_gen;
    short_id = fs->short_id;
    foldstate_unlock(fs);

    /* Fast path: folder established and nothing new since last pass. */
    if (S->announced[fidx] && snapshot <= S->cursor[fidx])
        return 1;

    first = !S->announced[fidx];

    for (i = 0; i < num; i++) {
        SyncMeta m;
        int      nb = 0, send_it = 0;

        foldstate_lock(fs);
        if (i < fs->num_files) {
            int64_t seq = fs->files[i].sequence;
            if (seq > S->cursor[fidx] && seq <= snapshot) {
                foldstate_meta(fs, &fs->files[i], &m);
                nb = foldstate_blocks(fs, m.name, S->bh, FOLDER_MAX_BLOCKS, NULL);
                send_it = 1;
            }
        }
        foldstate_unlock(fs);

        if (!send_it)
            continue;
        /* Mirror what the peer produced; never announce our own authorship. */
        if (recvonly && sync_version_has(&m.version, short_id)) {
            log_printf(LOG_DEBUG, "worker: not announcing locally-originated "
                       "'%s' from receive-only '%s'",
                       m.name, S->cfg->folders[fidx].id);
            continue;
        }
        /* Never announce a live, valid file with an empty block list -
         * Syncthing treats that as a protocol error and drops the whole
         * connection. Such a record (a pre-fix empty file loaded from the
         * persisted index, or a block array lost to an allocation failure)
         * is healed by the next scan pass (rec_changed re-hashes blockless
         * records), which bumps its sequence so it is announced then. */
        if (m.type == BEP_FILE_FILE && !m.deleted && !m.invalid && nb == 0) {
            log_printf(LOG_DEBUG, "worker: holding back blockless record '%s' "
                       "until the scanner re-hashes it", m.name);
            continue;
        }
        /* Pack into the running batch. A refused add leaves the batch exactly
         * as it was, so the entry that did not fit gets a second try once the
         * batch has been flushed. */
        if (!batching) {
            bep_index_batch_begin(S->conn, &batch, S->cfg->folders[fidx].id);
            batching = 1;
        }
        fileinfo_from_meta(&fi, &m);
        if (!bep_index_batch_add(&batch, &fi, S->bh, nb)) {
            /* Only a batch with entries is worth sending, and only a send
             * clears 'first': flushing an empty one and clearing it anyway
             * would make the folder's FIRST message an IndexUpdate for an
             * Index the peer never got, which Syncthing answers by dropping
             * the connection. */
            if (batch.num > 0) {
                if (!bep_send_index_batch(S->conn,
                                          first ? BEP_INDEX : BEP_INDEX_UPDATE,
                                          &batch))
                    return 0;
                first = 0;
                S->announced[fidx] = 1;
                bep_index_batch_begin(S->conn, &batch,
                                      S->cfg->folders[fidx].id);
            }
            if (!bep_index_batch_add(&batch, &fi, S->bh, nb)) {
                /* One entry too large for an EMPTY batch - already the limit
                 * before batching, so fall back to the single-record send
                 * rather than quietly dropping the record. That path encodes
                 * into the same send buffer the batch lives in, so the batch
                 * must be restarted afterwards, not resumed. */
                if (!send_record(S, fidx, &m, first, S->bh, nb))
                    return 0;
                first = 0;
                S->announced[fidx] = 1;
                batching = 0;
                continue;
            }
        }
        if (batch.num >= WK_INDEX_BATCH) {
            if (!bep_send_index_batch(S->conn,
                                      first ? BEP_INDEX : BEP_INDEX_UPDATE,
                                      &batch))
                return 0;
            first = 0;
            S->announced[fidx] = 1;
            batching = 0;
        }
    }

    /* Whatever is still accumulated goes out as the last message. */
    if (batching && batch.num > 0) {
        if (!bep_send_index_batch(S->conn, first ? BEP_INDEX : BEP_INDEX_UPDATE,
                                  &batch))
            return 0;
        first = 0;
        S->announced[fidx] = 1;
    }

    if (!establish_folder(S, fidx))        /* nothing to announce: just claim it */
        return 0;

    /* Advance the cursor only if no tombstone prune ran during the pass. The
     * scanner prunes with a swap-remove (tail record -> freed slot); a live,
     * not-yet-announced record relocated into a slot we already passed would be
     * missed. A num_files comparison alone misses a prune whose removal is
     * exactly offset by a concurrent add, so we compare the prune generation:
     * if it changed (or the table shrank), leave the cursor so the next pass
     * re-scans in full (record resends are idempotent) and catches the moved
     * record. */
    {
        int moved;
        foldstate_lock(fs);
        moved = (fs->prune_gen != pgen) || (fs->num_files < num);
        foldstate_unlock(fs);
        if (!moved && snapshot > S->cursor[fidx])
            S->cursor[fidx] = snapshot;
    }
    return 1;
}

static int announce_all(Sync *S)
{
    int i;
    for (i = 0; i < S->cfg->num_folders; i++) {
        if (S->cfg->folders[i].removed)
            continue;
        /* Mutually shared folders only: an Index for a folder the peer does
         * not (yet) share makes Syncthing drop the connection. Before its
         * first ClusterConfig arrives this skips everything - the exchange
         * simply starts a moment later, CC first, like Syncthing's own. */
        if (!S->peer_shares[i])
            continue;
        if (!announce_folder(S, i))
            return 0;
    }
    return 1;
}

/* ---- serve a peer's Request from disk (no index needed) ------------- */

/* Ensure S->blockbuf can hold 'need' bytes for one served block. Grows
 * monotonically (never shrinks) up to FOLDER_MAX_BLOCK_SIZE; the buffer is
 * refilled fresh on every serve, so old contents need not be preserved. Returns
 * 1, or 0 on OOM. */
static int sync_ensure_blockbuf(Sync *S, int need)
{
    unsigned char *nb;
    if (need <= S->blockbuf_cap)
        return 1;
    nb = AllocVec((ULONG)need, MEMF_ANY);
    if (!nb)
        return 0;
    if (S->blockbuf)
        FreeVec(S->blockbuf);
    S->blockbuf     = nb;
    S->blockbuf_cap = need;
    return 1;
}

static int serve_request(Sync *S, const unsigned char *body, int blen)
{
    BepRequest  rq;
    BepResponse rs;
    int         fidx, got;

    if (!bep_decode_request(body, blen, &rq))
        return 1;                              /* malformed: ignore */

    memset(&rs, 0, sizeof(rs));
    rs.id = rq.id;

    fidx = sync_folder_index(S->cfg, rq.folder);
    if (fidx < 0 || rq.size < 0 || rq.size > FOLDER_MAX_BLOCK_SIZE ||
        !folder_name_safe(rq.name) ||          /* no volume/parent escape */
        (S->ignores[fidx] && ignore_match(S->ignores[fidx], rq.name))) {
        rs.code = BEP_ERR_NO_SUCH_FILE;
        return bep_send_response(S->conn, &rs);
    }
    if (!sync_ensure_blockbuf(S, rq.size)) {
        log_printf(LOG_ERROR, "worker: out of memory serving '%s' (%ld bytes)",
                   rq.name, (long)rq.size);
        rs.code = BEP_ERR_GENERIC;
        return bep_send_response(S->conn, &rs);
    }

    got = folder_read_block(S->cfg->folders[fidx].path, rq.name,
                            rq.offset, rq.size, S->blockbuf);
    if (got != rq.size) {
        rs.code = BEP_ERR_NO_SUCH_FILE;
    } else {
        rs.data     = S->blockbuf;
        rs.data_len = got;
        rs.code     = BEP_ERR_NONE;
        S->st->bytes_out += got;               /* live upload total (STATUS) */
    }
    return bep_send_response(S->conn, &rs);
}

/* Byte span of block 'block' of the file being downloaded: returns its length
 * (the tail block is short) and writes its offset to *off. The (int64_t) cast
 * before the multiply is what keeps a large file's offsets from wrapping. */
static int32_t dl_block_span(const Sync *S, int block, int64_t *off)
{
    int32_t bsz  = S->dl.fi.block_size;
    int64_t rest;

    *off = (int64_t)block * bsz;
    rest = S->dl.fi.size - *off;
    return (int32_t)(rest > bsz ? bsz : rest);
}

/* ---- download FSM (apply Responses to the in-flight pull) ------------ */

/* Remember a file we have stopped fetching so the published backlog still
 * counts it (see num_stalled in Sync). */
static void stall_add(Sync *S, int fidx, const char *name)
{
    int i;

    /* A peer re-offers what we could not take on every connection. Counting a
     * name twice would inflate the backlog and crowd out real entries. */
    for (i = 0; i < S->num_stalled; i++)
        if (S->stalled_fidx[i] == fidx &&
            strcmp(S->stalled_name[i], name) == 0)
            return;

    if (S->num_stalled >= WK_MAX_STALLED) {
        log_printf(LOG_WARN, "worker: more than %d unfetchable file(s); '%s' "
                   "is left out of the reported backlog", WK_MAX_STALLED, name);
        return;
    }
    S->stalled_fidx[S->num_stalled] = fidx;
    scopy(S->stalled_name[S->num_stalled], name, BEP_PATH_MAX);
    S->num_stalled++;
}

/* Drop a file from that list - it is wanted again (the peer re-offered it) or
 * it finally landed, and either way the want queue now accounts for it. */
static void stall_clear(Sync *S, int fidx, const char *name)
{
    int i;
    for (i = 0; i < S->num_stalled; i++)
        if (S->stalled_fidx[i] == fidx &&
            strcmp(S->stalled_name[i], name) == 0) {
            S->num_stalled--;
            S->stalled_fidx[i] = S->stalled_fidx[S->num_stalled];
            scopy(S->stalled_name[i], S->stalled_name[S->num_stalled],
                  BEP_PATH_MAX);
            return;
        }
}

/* Drop the fetch claim, if we are holding one. */
static void release_claim(Sync *S)
{
    if (S->claim_fidx >= 0) {
        foldstate_unclaim(&S->folders[S->claim_fidx], S);
        S->claim_fidx = -1;
    }
}

/* A fetch went wrong part-way. Put the file back on the want queue so it is
 * tried again rather than quietly disappearing from the backlog, unless it has
 * used up its WK_MAX_FETCH attempts (or the failure is one that re-fetching
 * cannot mend) - then it is only remembered as stalled. Never re-queued as a
 * conflict: the local loser was already preserved on the first attempt, and
 * asking for that again would leave a second conflict copy behind. */
static void requeue_download(Sync *S, int retryable)
{
    BepFileInfo fi;

    if (retryable && S->dl.attempts < WK_MAX_FETCH) {
        fileinfo_from_meta(&fi, &S->dl.fi);
        note_wanted(S, S->dl.folder_idx, &fi);
        if (sync_want_push_again(&S->model, S->dl.folder_idx, &fi, S->dl.hashes,
                                 S->dl.num_blocks, 0, S->dl.attempts)) {
            log_printf(LOG_INFO, "worker: will retry '%s' (attempt %d of %d)",
                       S->dl.fi.name, S->dl.attempts + 1, WK_MAX_FETCH);
            return;
        }
        log_printf(LOG_WARN, "worker: no room on the want queue to retry '%s'",
                   S->dl.fi.name);
    } else if (retryable) {
        log_printf(LOG_ERROR, "worker: giving up on '%s' after %d attempt(s); "
                   "it stays counted as out of sync until the next connection",
                   S->dl.fi.name, S->dl.attempts);
    }
    stall_add(S, S->dl.folder_idx, S->dl.fi.name);
}

/* End the in-flight download without finishing it: keep the staged temp (a
 * later attempt resumes from its completed blocks) and re-queue the file. */
static void abort_download(Sync *S)
{
    folder_recv_abort(S->dl.fh, S->dl.tmp);
    S->dl.active = 0;
    release_claim(S);                      /* another peer's worker may finish it */
    requeue_download(S, 1);
}

static void handle_response(Sync *S, const unsigned char *body, int blen)
{
    BepResponse rs;
    Inflight    fl;
    int64_t     off;
    int32_t     want;
    int         i, slot = -1;

    if (!bep_decode_response(body, blen, &rs))
        return;
    if (rs.code == BEP_ERR_NONE)
        S->st->bytes_in += rs.data_len;        /* live download total (STATUS) */
    if (!S->dl.active)
        return;                                /* stale / unexpected */
    for (i = 0; i < S->dl.num_inflight; i++)
        if (S->dl.inflight[i].id == rs.id) { slot = i; break; }
    if (slot < 0)
        return;                                /* not one of ours */

    fl = S->dl.inflight[slot];                 /* take it out of the window */
    S->dl.num_inflight--;
    S->dl.inflight[slot] = S->dl.inflight[S->dl.num_inflight];

    if (rs.code != BEP_ERR_NONE) {
        log_printf(LOG_WARN, "worker: peer cannot serve '%s' (code %d), aborting",
                   S->dl.fi.name, rs.code);
        abort_download(S);
        return;
    }

    want = dl_block_span(S, fl.block, &off);

    /* Verify the block (size + SHA-256) against what the peer's index promised
     * before trusting it to disk. */
    if (rs.data_len == want) {
        unsigned char h[BEP_HASH_LEN];
        folder_sha256(rs.data, rs.data_len, h);
        if (memcmp(h, S->dl.hashes[fl.block], BEP_HASH_LEN) == 0) {
            switch (folder_recv_write(S->dl.fh, off, rs.data, rs.data_len)) {
            case FOLDER_WRITE_OK:
                return;                        /* progress() refills the window */
            case FOLDER_WRITE_AHEAD:
                /* The peer answered our pipelined Requests out of order and
                 * this block sits past the temp's end, which cannot be written
                 * over a hole. Ask for it again once the blocks before it have
                 * landed - and do not charge a retry, since nothing is wrong
                 * with the block. The lowest outstanding block always lands
                 * (its offset is at most the temp's end), so the file makes
                 * progress every round however the peer orders its answers. */
                log_printf(LOG_DEBUG, "worker: block %d of '%s' arrived ahead "
                           "of its turn; re-requesting", fl.block, S->dl.fi.name);
                S->dl.redo[S->dl.num_redo++] = fl;   /* fits: window-bounded */
                return;
            default:
                log_printf(LOG_WARN, "worker: write failed for '%s', aborting",
                           S->dl.fi.name);
                abort_download(S);
                return;
            }
        }
    }

    /* Bad/short/mismatched block: put it on the redo list, up to a small cap. */
    if (++fl.retries > WK_MAX_RETRY) {
        log_printf(LOG_WARN, "worker: block %d of '%s' failed verify %d times, aborting",
                   fl.block, S->dl.fi.name, fl.retries - 1);
        abort_download(S);
        return;
    }
    log_printf(LOG_WARN, "worker: block %d of '%s' failed verify, re-requesting",
               fl.block, S->dl.fi.name);
    S->dl.redo[S->dl.num_redo++] = fl;         /* fits: window-bounded */
}

/* ---- receive: write peer changes into the shared index -------------- */

/* Apply a peer's deletion of a file (reached only when classify returned
 * SYNC_DELETE). Remove it, then record a tombstone in the shared index carrying
 * the peer's version but our own new sequence - the bump relays it onward. */
static void apply_peer_delete(Sync *S, int fidx, const BepFileInfo *fi)
{
    FolderState        *fs = &S->folders[fidx];
    const ConfigFolder *f  = &S->cfg->folders[fidx];
    SyncMeta            tomb;

    /* Honours the versioning setting, deliberately: a peer's deletion is the
     * case the trash-can was built for, in every mode. Only the receive-only
     * OVERWRITE (see finish_download) archives unconditionally, because there
     * the copy being destroyed is the user's own edit rather than the peer's
     * file. */
    folder_archive(f->path, fi->name, 0);
    folder_delete_temp(f->path, fi->name);     /* the partial is junk either way */
    if (!folder_delete(f->path, fi->name)) {   /* I/O: outside the lock */
        /* Still on disk (in use, protected, ...). Do NOT record a tombstone
         * for a file we did not remove: the next scan would re-discover it,
         * see a deleted record, and announce it as a new local creation whose
         * version dominates the peer's tombstone - resurrecting it there. Leave
         * our live record alone; the peer re-offers the deletion and we retry. */
        log_printf(LOG_WARN, "worker: could not delete '%s' (still on disk); "
                   "will retry", fi->name);
        return;
    }
    log_printf(LOG_INFO, "worker: applied peer deletion of '%s'", fi->name);

    meta_from_fileinfo(&tomb, fi);             /* keep the peer's version */
    foldstate_lock(fs);
    tomb.sequence = foldstate_next_seq(fs);
    foldstate_upsert(fs, &tomb, NULL, 0);
    foldstate_unlock(fs);
}

static int snap_record(FolderState *fs, const char *name, SyncMeta *out);

/* Create a directory the peer announced and record it.
 *
 * A name we hold a TOMBSTONE for needs the same last-writer test the file path
 * applies. A peer that has not heard about the deletion - one whose index was
 * reset, or that was away while it happened - keeps listing the drawer in
 * every Index it sends, and BEP gives it no way to be told again. Making the
 * drawer unconditionally puts it back on disk while our record still says
 * deleted, and the next scan reads that as a local re-add: it announces the
 * drawer with a version that dominates the deletion and the whole subtree
 * comes back, on every device, from the one node that was behind. So a
 * tombstone only yields to a version that actually beats it, and when it does
 * the record is replaced rather than left deleted - a live drawer on disk with
 * a deleted record is the same resurrection one scan later. */
static void apply_peer_dir(Sync *S, int fidx, const BepFileInfo *fi)
{
    FolderState        *fs = &S->folders[fidx];
    const ConfigFolder *f  = &S->cfg->folders[fidx];
    SyncMeta            have, d;
    int                 had;

    had = snap_record(fs, fi->name, &have);
    if (had && have.deleted) {
        meta_from_fileinfo(&d, fi);
        if (have.version.num_counters > 0 && d.version.num_counters > 0) {
            if (sync_version_compare(&have.version, &d.version) != SYNC_V_THEIRS)
                return;                        /* stale re-offer: stay deleted */
        } else if (fi->modified_s < have.modified_s) {
            return;                            /* no vectors: last writer wins */
        }
    }

    if (!folder_mkdir(f->path, fi->name)) {    /* I/O: outside the lock */
        /* A path AmigaDOS will not carry. Recording it would claim a drawer we
         * cannot reach and report "Up to Date" over a subtree that never
         * arrived, so count it stalled instead.
         *
         * It may be on disk already - see folder_path_addressable - and
         * dropping it from the index would be worse than the stall:
         * mark-and-sweep would read the gap as a local deletion and send the
         * peer a tombstone for data it holds and we merely cannot reach. */
        log_printf(LOG_WARN, "worker: cannot use drawer '%s' - path too long "
                   "for AmigaOS; shorten the name", fi->name);
        stall_add(S, fidx, fi->name);
        return;
    }
    foldstate_lock(fs);
    {
        FolderRec *h = foldstate_find(fs, fi->name);
        if (!h || h->deleted) {
            meta_from_fileinfo(&d, fi);
            d.sequence = foldstate_next_seq(fs);
            foldstate_upsert(fs, &d, NULL, 0);
        }
    }
    foldstate_unlock(fs);
}

/* Queue a deletion to apply after this message's adds. Keeps the two parallel
 * arrays in step - the same invariant flush_deferred's swap-remove relies on.
 * Returns 0 when the queue is full and the caller must apply it now. */
static int defer_push(Sync *S, int fidx, const BepFileInfo *fi)
{
    if (S->num_defer >= WK_MAX_DEFER)
        return 0;
    S->defer_fidx[S->num_defer]  = fidx;
    S->defer_tries[S->num_defer] = 0;
    meta_from_fileinfo(&S->defer[S->num_defer], fi);
    S->num_defer++;
    return 1;
}

/* Copy the record for 'name' out of 'fs' under its lock, for the pure classify
 * decisions. Returns 1 if a record was there ('out' filled), 0 if not. Block
 * hashes are not copied - conflict_preserve_local needs those and takes its own
 * lock. Holding the snapshot rather than the pointer is the rule: the record
 * can move or be rewritten the moment the lock drops. */
static int snap_record(FolderState *fs, const char *name, SyncMeta *out)
{
    FolderRec *h;
    int       had;

    foldstate_lock(fs);
    h   = foldstate_find(fs, name);
    had = h != NULL;
    if (had)
        foldstate_meta(fs, h, out);
    foldstate_unlock(fs);
    return had;
}

/* Apply a peer's deletion of a directory. folder_delete removes it only if empty
 * (its files arrive as their own tombstones), so a non-empty dir is left until
 * it empties. Tombstone recorded + relayed.
 *
 * Guarded by version where both sides carry one, and only by mtime where they
 * do not. Mtime alone was wrong here for two reasons. A clock set ahead - an
 * Amiga with a flat RTC battery is the normal case, not the exotic one - made
 * every drawer look newer than any deletion, so the peer's removals were
 * refused for good. And a drawer's datestamp moves on AmigaOS whenever an entry
 * is added or removed, so applying the peer's file tombstones bumps it to now:
 * with a perfectly good clock, a scan landing between those files and their
 * parent left the drawer "newer" than the deletion that was removing it.
 *
 * Where the file path keeps the data on a CONCURRENT pair, this removes the
 * drawer: a drawer holds nothing itself, and anything inside it that won its
 * own comparison keeps it from being empty, which is the real protection. Only
 * a version of ours that strictly dominates refuses the deletion.
 *
 * Returns 1 when the name is settled (removed, or the deletion does not apply)
 * and 0 while the directory is still there, so the caller can come back. */
static int apply_peer_dir_delete(Sync *S, int fidx, const BepFileInfo *fi)
{
    FolderState        *fs = &S->folders[fidx];
    const ConfigFolder *f  = &S->cfg->folders[fidx];
    SyncMeta            have;
    int                 had;
    SyncMeta            tomb;

    had = snap_record(fs, fi->name, &have);

    if (had && have.deleted)
        return 1;                              /* already gone */
    if (had) {
        SyncMeta peer;

        meta_from_fileinfo(&peer, fi);
        if (have.version.num_counters > 0 && peer.version.num_counters > 0) {
            if (sync_version_compare(&have.version, &peer.version) == SYNC_V_OURS)
                return 1;                      /* ours dominates: stale delete */
        } else if (fi->modified_s < have.modified_s) {
            return 1;                          /* no vectors: last writer wins */
        }
    }

    /* Only succeeds once the directory is empty. If it is not - typically
     * because it still holds files we have not synced (a folder over the
     * entry cap) or files we failed to delete - we must NOT tombstone it:
     * the next scan would re-discover the directory, see a deleted record,
     * and announce it as a new local creation, resurrecting it on the peer.
     * Leave our live record; the peer re-offers the deletion and we retry
     * once its contents are gone. */
    if (!folder_delete(f->path, fi->name)) {
        /* The opposite call to apply_peer_dir's. With no record and no way to
         * name the path there is nothing here to remove - folder_walk would
         * have indexed it otherwise - so take the tombstone rather than stay
         * pending on a deletion that can never succeed. With a record the
         * drawer is on disk and out of reach, and tombstoning it would have the
         * next scan announce it straight back. */
        if (had || folder_path_addressable(f->path, fi->name)) {
            log_printf(LOG_DEBUG, "worker: directory '%s' not empty yet; will retry",
                       fi->name);
            return 0;
        }
        log_printf(LOG_DEBUG, "worker: nothing to remove for '%s' - the path is "
                   "too long for AmigaOS and we never had it", fi->name);
    } else {
        log_printf(LOG_INFO, "worker: applied peer deletion of directory '%s'",
                   fi->name);
    }

    meta_from_fileinfo(&tomb, fi);
    foldstate_lock(fs);
    tomb.sequence = foldstate_next_seq(fs);
    foldstate_upsert(fs, &tomb, NULL, 0);
    foldstate_unlock(fs);
    return 1;
}

/* Record a file we deliberately cannot store (unfittable filename, too many /
 * too large blocks) as an INVALID index entry carrying the peer's version.
 * The announce machinery then tells the peer "this device knowingly does not
 * have this file" - Syncthing excludes invalid-flagged entries from the
 * remote's completion, so the folder shows Up to Date (with the file under
 * "remote ignored") instead of hanging at "Syncing 0%" forever. When the peer
 * later modifies the file, its new version dominates this entry, we re-try
 * the fetch, and either store it (e.g. the name now fits) or refresh the
 * invalid entry at the new version. The scanner never tombstones invalid
 * records (no disk file backs them - see commit_deletions). */
static void announce_unstorable(Sync *S, int fidx, const SyncMeta *fi)
{
    FolderState *fs = &S->folders[fidx];
    SyncMeta     m  = *fi;

    m.invalid = 1;
    m.deleted = 0;
    foldstate_lock(fs);
    m.sequence = foldstate_next_seq(fs);
    if (!foldstate_upsert(fs, &m, NULL, 0))
        log_printf(LOG_WARN, "worker: index full recording invalid '%s'", m.name);
    foldstate_unlock(fs);
}

/* ---- deferred deletions (rename detection support) ------------------- */

/* Is there a queued or in-flight fetch whose expected content matches the file
 * this deferred tombstone would delete? While there is, the deletion stays
 * deferred so local_prefill can copy blocks from the still-present file. The
 * content fingerprint comes from OUR live record (the tombstone itself carries
 * none) - looked up fresh, since the record is only unchanged while the
 * deletion has not been applied. */
static int defer_matches_pending(Sync *S, int fidx, const SyncMeta *m)
{
    FolderState  *fs = &S->folders[fidx];
    unsigned char hash[BEP_HASH_LEN];
    int64_t       size;
    int           live = 0;

    foldstate_lock(fs);
    {
        FolderRec *h = foldstate_find(fs, m->name);
        if (h && !h->deleted && h->has_content_hash) {
            live = 1;
            size = h->size;
            memcpy(hash, h->content_hash, BEP_HASH_LEN);
        }
    }
    foldstate_unlock(fs);
    if (!live)
        return 0;

    /* Asked of the FOLDER, not of this worker. The file is on disk and every
     * worker can copy from it, so "is anyone still going to want this content"
     * is the only version of the question that protects it. Scoped to our own
     * queue, one worker's flush removed a rename's source three seconds before
     * another worker asked for it - measured, ten files of two hundred.
     *
     * This also covers our OWN spilled wants, which the queue scan it replaces
     * never did: a file parked on disk is just as much a reason to keep its
     * source as one in memory. */
    return foldstate_want_any(fs, hash, size);
}

/* Apply one deferred deletion - re-classified against the record as it stands
 * NOW, so a file the peer re-added (or that we changed) meanwhile survives. */
static void apply_deferred_delete(Sync *S, int fidx, const SyncMeta *m)
{
    FolderState *fs = &S->folders[fidx];
    BepFileInfo  fi;
    SyncMeta     have;
    int          had;

    fileinfo_from_meta(&fi, m);
    had = snap_record(fs, fi.name, &have);

    if (sync_classify_incoming(had ? &have : NULL,
                               S->cfg->folders[fidx].mode, &fi) == SYNC_DELETE)
        apply_peer_delete(S, fidx, &fi);
}

/* Is anything still outstanding that could empty a drawer? A deletion parked
 * on disk, a file still queued, a download in flight. While one of these is
 * true a drawer that cannot be removed yet is WAITING, not stuck, and the
 * retry budget must not run down on it - deletions are now parked for the
 * whole of a transfer, so "three fruitless flushes" would otherwise expire
 * during the very fetches that are going to empty it. The want queue and the
 * download are worker-wide rather than per-folder, which errs towards patience:
 * the budget still applies the moment the worker goes quiet. */
static int deletes_outstanding(const Sync *S, int fidx)
{
    return S->dl.active || S->model.num_want > 0 ||
           spill_pending(&S->spill[fidx]) || spill_pending(&S->spill_del[fidx]);
}

/* How deep a name sits in the tree, counted in separators: "a" is 0, "a/b" 1.
 * Only the ordering matters, not the absolute value. */
static int name_depth(const char *s)
{
    int d = 0;

    while (*s)
        if (*s++ == '/')
            d++;
    return d;
}

/* Apply every deferred deletion that no pending fetch still needs as a local
 * block source. Called at the end of each Index message (once its adds are all
 * queued) and after each progress() pass (fetch finished or dropped). Files go
 * first, then directories, so a directory tombstone finds its already-doomed
 * contents gone regardless of the order they arrived in.
 *
 * The directories then go DEEPEST FIRST. A directory is only removable once it
 * is empty, and the peer's entries arrive in no useful order: taking them as
 * they came, 'a/b' is attempted before 'a/b/c', fails as non-empty, and - since
 * a directory we did not remove keeps its live record - is left behind as a
 * ghost that the next scan re-announces, resurrecting the whole subtree on the
 * peer. Deepest-first empties children before their parent, so a deleted tree
 * converges in this one pass.
 *
 * 'done' seeds the progress count with removals made just before this call
 * (the parked deletions, which are files and so never appear in the list
 * below). Without it a flush that only drains parked files looks fruitless to
 * every drawer waiting on them, and the retry budget - which exists precisely
 * to distinguish "stuck" from "waiting its turn" - runs out on drawers that
 * were emptying all along. */
static void flush_deferred(Sync *S, int done)
{
    int i, progress = done;

    i = 0;
    while (i < S->num_defer) {                 /* files first */
        SyncMeta *m = &S->defer[i];
        if (m->type == BEP_FILE_DIRECTORY ||
            defer_matches_pending(S, S->defer_fidx[i], m)) {
            i++;
            continue;
        }
        apply_deferred_delete(S, S->defer_fidx[i], m);
        progress++;
        S->num_defer--;
        S->defer[i]      = S->defer[S->num_defer];      /* swap-remove */
        S->defer_fidx[i] = S->defer_fidx[S->num_defer];
    }

    {                                          /* then directories, deepest up */
        int order[WK_MAX_DEFER], n = 0, k, j, w;

        for (i = 0; i < S->num_defer; i++)
            if (S->defer[i].type == BEP_FILE_DIRECTORY)
                order[n++] = i;

        for (k = 0; k < n; k++) {              /* selection sort by depth */
            int best = k;
            for (j = k + 1; j < n; j++)
                if (name_depth(S->defer[order[j]].name) >
                    name_depth(S->defer[order[best]].name))
                    best = j;
            j = order[k]; order[k] = order[best]; order[best] = j;
        }

        for (k = 0; k < n; k++) {
            BepFileInfo fi;

            i = order[k];
            fileinfo_from_meta(&fi, &S->defer[i]);
            if (apply_peer_dir_delete(S, S->defer_fidx[i], &fi)) {  /* own guards */
                S->defer_tries[i] = DEFER_DONE;
                progress++;
            } else if (progress || deletes_outstanding(S, S->defer_fidx[i])) {
                /* Something is still being removed around it, or is still to
                 * come, so this drawer is not stuck - it is waiting its turn.
                 * Deleting 5000 files takes many flushes, and counting those
                 * against it dropped every drawer of the tree long before its
                 * contents were gone. Only a flush that removes nothing while
                 * nothing else is outstanding is evidence. */
                S->defer_tries[i] = 0;
            } else if (++S->defer_tries[i] >= WK_DIR_DEL_TRIES) {
                log_printf(LOG_WARN, "worker: gave up removing directory '%s' - "
                           "still not empty", S->defer[i].name);
                S->defer_tries[i] = DEFER_DONE;
            }
        }

        for (i = 0, w = 0; i < S->num_defer; i++) {          /* compact */
            if (S->defer[i].type == BEP_FILE_DIRECTORY &&
                S->defer_tries[i] == DEFER_DONE)
                continue;
            if (w != i) {
                S->defer[w]       = S->defer[i];
                S->defer_fidx[w]  = S->defer_fidx[i];
                S->defer_tries[w] = S->defer_tries[i];
            }
            w++;
        }
        S->num_defer = w;
    }
}

/* Block callback used while decoding an inbound FileInfo: collects the peer's
 * per-block hashes into the worker scratch (S->bh) so we can fold a content_hash
 * and, if we decide to fetch, enqueue them. */
static int index_block_cb(void *ctx, int index, const BepBlockInfo *blk)
{
    Sync *S = (Sync *)ctx;
    if (index < FOLDER_MAX_BLOCKS)
        memcpy(S->bh[index], blk->hash, BEP_HASH_LEN);
    return 1;
}

static int  hset_add(uint32_t *h, int *n, int cap, const char *name);
static void hset_drop(uint32_t *h, int *n, const char *name);
static int  hset_has(const uint32_t *h, int n, const char *name);

/* Record that we still want this content, so a deferred deletion elsewhere in
 * the daemon does not remove the only local copy of it. One call per way a
 * file can join our backlog: queued, parked on the spill, or requeued. */
static void note_wanted(Sync *S, int fidx, const BepFileInfo *fi)
{
    if (fi->has_content_hash)
        foldstate_want_add(&S->folders[fidx], S, fi->content_hash, fi->size);
}

/* Park one wanted file on this folder's spill, opening it on first use.
 * Returns 1 when the file is safely parked, 0 to fall back to a reconnect. */
static int spill_want(Sync *S, int fidx, const BepFileInfo *fi, int nb,
                      int conflict)
{
    SpillFile *sp = &S->spill[fidx];

    if (sp->failed)
        return 0;                          /* asked once per record: stay quiet */
    if (!sp->ok) {
        char path[256];

        if (!S->cfg->statedir[0] ||
            !spill_path(S->cfg->statedir, S->cfg->folders[fidx].id,
                        S->st->peer_actual_id, (uint32_t)(unsigned long)S,
                        ".spl", path, sizeof(path)))
            return 0;
        if (!spill_reset(sp, path))
            return 0;
        log_printf(LOG_INFO, "worker: index larger than the queue; parking the "
                   "remainder of '%s' on disk", S->cfg->folders[fidx].id);
    }
    return spill_append(sp, fi, S->bh, nb, conflict);
}

/* Hold one file deletion past the in-memory defer list. Returns 1 when it is
 * safely parked, 0 to fall back to applying it now (which costs a rename its
 * local source, not correctness). */
static int spill_delete(Sync *S, int fidx, const BepFileInfo *fi)
{
    SpillFile *sp = &S->spill_del[fidx];

    if (sp->failed)
        return 0;                          /* asked once per record: stay quiet */
    if (!sp->ok) {
        char path[256];

        if (!S->cfg->statedir[0] ||
            !spill_path(S->cfg->statedir, S->cfg->folders[fidx].id,
                        S->st->peer_actual_id, (uint32_t)(unsigned long)S,
                        ".spd", path, sizeof(path)))
            return 0;
        if (!spill_reset(sp, path))
            return 0;
        log_printf(LOG_INFO, "worker: more deletions at once than '%s' can hold "
                   "in memory; parking the rest so renames keep their source",
                   S->cfg->folders[fidx].id);
    }
    return spill_append(sp, fi, NULL, 0, 0);
}

/* Nothing left in our backlog: forget the content we were protecting.
 *
 * This is the ONLY removal from the shared want set, which is what makes the
 * set safe to maintain - there is no per-file drop to forget at one of the
 * dozen places a fetch can end. The cost is that a content stays "wanted"
 * until its worker goes quiet, so a deletion can wait a little longer than
 * strictly necessary; the benefit is that it can never be forgotten early,
 * which is the direction that costs bytes. */
static void forget_wants_when_idle(Sync *S)
{
    int fidx;

    if (S->dl.active || S->model.num_want > 0)
        return;
    for (fidx = 0; fidx < CONFIG_MAX_FOLDERS; fidx++)
        if (spill_pending(&S->spill[fidx]))
            return;                        /* parked wants are still wants */
    for (fidx = 0; fidx < CONFIG_MAX_FOLDERS; fidx++)
        foldstate_want_clear(&S->folders[fidx], S);
}

/* Apply the parked deletions. Only once the queue AND the want spill are empty:
 * until then some pending fetch may still want one of these files as its block
 * source, and telling the difference per file would mean searching a spill that
 * is a sequential file. Waiting costs a little disk for a little longer and
 * needs no bookkeeping at all - and by the time both are empty, nothing can
 * need a source. */
static int drain_parked_deletes(Sync *S)
{
    int fidx, total = 0;


    for (fidx = 0; fidx < CONFIG_MAX_FOLDERS; fidx++) {
        SpillFile  *sp = &S->spill_del[fidx];
        int         n  = 0;
        /* Drawers met while draining, applied after every file below. The
         * spill is in the order the peer spoke, so a drawer's tombstone can
         * come off it long before the tombstones of the files inside it. */
        BepFileInfo dirs[WK_MAX_DEFER];
        int         ndirs = 0, i, k;

        /* Wait until nothing in this folder is spoken for by ANY worker. The
         * spill is a sequential file: sifting it per record would mean
         * re-appending the ones still needed and rewriting it every pass, so
         * it is drained in one go at the moment that is safe. The flush keeps
         * the per-file precision - a deletion whose content nobody wants goes
         * through immediately, without waiting for this. */
        if (spill_pending(sp) && !foldstate_want_idle(&S->folders[fidx]))
            continue;

        while (spill_pending(sp)) {
            BepFileInfo fi;
            SyncMeta    m;
            long        next = 0;
            int         nb = 0, conflict = 0;

            if (spill_next(sp, &next, &fi, S->bh, FOLDER_MAX_BLOCKS,
                           &nb, &conflict) != 1) {
                log_printf(LOG_WARN, "worker: parked deletions for '%s' are "
                           "unreadable; the peer will be asked again",
                           S->cfg->folders[fidx].id);
                spill_close(sp);
                S->want_overflow = 1;
                break;
            }
            if (fi.type == BEP_FILE_DIRECTORY) {
                /* Held until this whole spill has been read. Handing it to
                 * the defer list instead looked equivalent and was not: when
                 * that list is full the drawer falls through to being applied
                 * on the spot, against a drawer whose files are still further
                 * down this very spill. It fails as non-empty, silently, and
                 * the empty drawer is left behind with a live record for the
                 * next scan to announce back. Measured: 'settled' survived a
                 * rename that was otherwise perfect. */
                if (ndirs < WK_MAX_DEFER)
                    dirs[ndirs++] = fi;
                else if (!defer_push(S, fidx, &fi))
                    apply_peer_dir_delete(S, fidx, &fi);   /* last resort */
            } else {
                meta_from_fileinfo(&m, &fi);
                apply_deferred_delete(S, fidx, &m);  /* re-classified inside */
            }
            spill_commit(sp, next);
            n++;
        }
        /* Every file in this spill is gone; now the drawers, deepest first,
         * so a parent finds its children already removed. */
        for (k = 0; k < ndirs; k++) {
            int best = k;
            for (i = k + 1; i < ndirs; i++)
                if (name_depth(dirs[i].name) > name_depth(dirs[best].name))
                    best = i;
            if (best != k) {
                BepFileInfo t = dirs[k];
                dirs[k]       = dirs[best];
                dirs[best]    = t;
            }
            if (!apply_peer_dir_delete(S, fidx, &dirs[k]) &&
                !defer_push(S, fidx, &dirs[k]))
                log_printf(LOG_WARN, "worker: could not remove directory "
                           "'%s' and have nowhere to keep it", dirs[k].name);
        }
        if (n)
            log_printf(LOG_INFO, "worker: %d parked deletion(s) came due in "
                       "'%s'", n, S->cfg->folders[fidx].id);
        if (sp->ok && !spill_pending(sp))
            spill_rewind(sp);
        total += n;
    }
    return total;
}

/* Refill the want queue from the spills. Called wherever the queue may have
 * drained: what a file's completion frees, the next parked file takes.
 *
 * Every record is classified AGAIN as it comes back, against the index as it
 * is now rather than as it was when the peer spoke. Minutes may have passed
 * and thousands of files landed; the file may have arrived from another peer,
 * or been deleted here. Re-deciding costs one lookup and keeps the spill a
 * queue of things the peer once offered, never a promise about what we still
 * want. */
static void refill_from_spill(Sync *S)
{
    int fidx;

    for (fidx = 0; fidx < CONFIG_MAX_FOLDERS; fidx++) {
        SpillFile *sp = &S->spill[fidx];

        while (spill_pending(sp)) {
            BepFileInfo fi;
            SyncMeta    have;
            SyncAction  act;
            long        next = 0;
            int         nb = 0, conflict = 0, had;

            if (S->model.num_want >= SYNC_MAX_WANT)
                break;                             /* full again: later */
            if (spill_next(sp, &next, &fi, S->bh, FOLDER_MAX_BLOCKS,
                           &nb, &conflict) != 1) {
                log_printf(LOG_WARN, "worker: parked index for '%s' is "
                           "unreadable; the peer will be asked again",
                           S->cfg->folders[fidx].id);
                spill_close(sp);
                S->want_overflow = 1;              /* fall back to a reconnect */
                break;
            }

            if (!fi.name[0]) {                     /* damaged record */
                log_printf(LOG_WARN, "worker: parked index for '%s' is "
                           "damaged; the peer will be asked again",
                           S->cfg->folders[fidx].id);
                spill_close(sp);
                S->want_overflow = 1;
                break;
            }
            if (S->ignores[fidx] && ignore_match(S->ignores[fidx], fi.name)) {
                spill_commit(sp, next);            /* hidden since it was parked */
                continue;
            }
            if (hset_has(S->gone_h[fidx], S->gone_n[fidx], fi.name)) {
                /* Deleted by the peer while it sat here. Asking for it would
                 * fail three times and leave a partial behind. */
                log_printf(LOG_DEBUG, "worker: '%s' was deleted while parked; "
                           "not fetching it", fi.name);
                spill_commit(sp, next);
                continue;
            }
            had = snap_record(&S->folders[fidx], fi.name, &have);
            act = sync_classify_incoming(had ? &have : NULL,
                                         S->cfg->folders[fidx].mode, &fi);
            if (act != SYNC_FETCH && act != SYNC_CONFLICT) {
                spill_commit(sp, next);            /* settled while it waited */
                continue;
            }
            note_wanted(S, fidx, &fi);
            if (!sync_want_push(&S->model, fidx, &fi, S->bh, nb,
                                act == SYNC_CONFLICT))
                break;                             /* keep it for the next pass */
            spill_commit(sp, next);
        }
        if (sp->ok && !spill_pending(sp))
            spill_rewind(sp);      /* keep the file; the next burst reuses it */
    }
}

/* FNV-1a over a name, for the contested-name set. */
static uint32_t name_hash(const char *s)
{
    uint32_t h = 2166136261u;

    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

/* Small sets of names, held as hashes: the names themselves would be kilobytes
 * of Sync for what are bookkeeping notes. A hash collision costs one file the
 * wrong answer in a way that self-corrects on the next index, which is a fair
 * trade for the memory on this hardware. */
static int hset_add(uint32_t *h, int *n, int cap, const char *name)
{
    uint32_t v = name_hash(name);
    int      i;

    for (i = 0; i < *n; i++)
        if (h[i] == v)
            return 1;                          /* already in */
    if (*n >= cap)
        return 0;                              /* full: caller degrades */
    h[(*n)++] = v;
    return 1;
}

static void hset_drop(uint32_t *h, int *n, const char *name)
{
    uint32_t v = name_hash(name);
    int      i;

    for (i = 0; i < *n; i++)
        if (h[i] == v) {
            (*n)--;
            h[i] = h[*n];
            return;
        }
}

static int hset_has(const uint32_t *h, int n, const char *name)
{
    uint32_t v = name_hash(name);
    int      i;

    for (i = 0; i < n; i++)
        if (h[i] == v)
            return 1;
    return 0;
}

/* Merge a peer Index/IndexUpdate: create/remove dirs, apply file deletions,
 * enqueue wanted files (skipping ignored ones), all against the shared index. */
static void handle_index(Sync *S, const unsigned char *body, int blen, int full)
{
    BepIndexIter it;
    BepFileInfo  fi;
    char         folder[BEP_FOLDER_ID_MAX];
    FolderMode   mode;
    FolderState *fs;
    int          fidx, added = 0;

    S->st->indexed = 1;                    /* the peer has now spoken */
    bep_index_iter_begin(&it, body, blen, folder);

    fidx = sync_folder_index(S->cfg, folder);
    if (fidx < 0) {
        log_printf(LOG_DEBUG, "worker: Index for unshared folder '%s'", folder);
        return;
    }
    mode = S->cfg->folders[fidx].mode;
    fs   = &S->folders[fidx];
    if (full)
        S->kept_n[fidx] = 0;       /* a full Index restates the whole folder */
    /* The spill is deliberately NOT discarded here. It is created per session
     * and deleted at teardown, so there is never a stale one to discard, and
     * every parked record is classified AGAIN when it comes back - which means
     * a restatement can only make one redundant, never wrong. (Measured: a
     * 2500-file index arrives in a single Index message, so this path is not
     * even reached mid-stream.) */

    while (bep_index_iter_next_cb(&it, &fi, index_block_cb, S)) {
        SyncAction act;
        SyncMeta   have;
        int        had = 0;
        int        nb  = fi.num_blocks;

        if (fi.invalid)
            continue;
        if (!folder_name_safe(fi.name)) {      /* reject volume/parent escape */
            log_printf(LOG_WARN, "worker: peer sent unsafe name '%s' - skipping",
                       fi.name);
            continue;
        }
        /* Any record at all supersedes a stall: the peer has just told us
         * what this name is now, so the verdict we gave up on is stale. A
         * fetch re-queues below and the queue counts it again; a deletion or
         * an already-satisfied record means we do not need it at all. */
        stall_clear(S, fidx, fi.name);
        if (fi.type == BEP_FILE_DIRECTORY) {   /* create or remove on receive */
            if (mode != FOLDER_SENDONLY &&
                !(S->ignores[fidx] && ignore_match(S->ignores[fidx], fi.name))) {
                /* A dir tombstone defers like the file ones (and is applied
                 * after them in flush_deferred), so the dir empties first
                 * regardless of arrival order within the message. */
                if (!fi.deleted) {
                    apply_peer_dir(S, fidx, &fi);
                } else if (!defer_push(S, fidx, &fi)) {
                    /* A full list is exactly where a drawer tombstone must
                     * NOT be applied on the spot: the files inside it are
                     * still queued behind it, so the removal fails as
                     * non-empty and the drawer is left behind - empty, but
                     * with a live record the next scan announces back to the
                     * peer, putting the whole tree there again.
                     *
                     * Draining first used to make room. It cannot any more:
                     * the entries filling the list are the deletions of the
                     * very files being fetched, and those are now held on
                     * purpose until their fetch is done. So the drawer goes on
                     * the spill with them and is applied in the same drain,
                     * after its contents. Measured on the A4000: without this
                     * a renamed 200-file drawer converged perfectly and left
                     * the old one standing empty behind it. */
                    flush_deferred(S, 0);
                    if (!defer_push(S, fidx, &fi) && !spill_delete(S, fidx, &fi))
                        apply_peer_dir_delete(S, fidx, &fi);
                }
            }
            continue;
        }
        if (fi.type != BEP_FILE_FILE)
            continue;                          /* symlinks etc: v1 skips */
        if (!fi.deleted && S->ignores[fidx] &&
            ignore_match(S->ignores[fidx], fi.name))
            continue;                          /* we never fetch ignored files */

        /* Fold the peer's authoritative content fingerprint from its block
         * hashes (now in S->bh) so classify can tell "already have it". */
        if (!fi.deleted && nb >= 0 && nb <= FOLDER_MAX_BLOCKS) {
            folder_content_hash(S->bh, nb, fi.content_hash);
            fi.has_content_hash = 1;
        }

        had = snap_record(fs, fi.name, &have);   /* for the pure classify */

        act = sync_classify_incoming(had ? &have : NULL, mode, &fi);
        if (!fi.deleted) {
            /* The peer is speaking about this name WITHOUT deleting it, so
             * both notes about it are stale: it is no longer contested, and
             * no longer gone (it may have been re-created since). */
            hset_drop(S->kept_h[fidx], &S->kept_n[fidx], fi.name);
            hset_drop(S->gone_h[fidx], &S->gone_n[fidx], fi.name);
        }
        if (fi.deleted && act == SYNC_IGNORE && had && !have.deleted) {
            /* We are keeping a file the peer has deleted, because our version
             * won. Nothing is queued for it, so nothing else would ever
             * mention it again - and the peer will count us out of sync for it
             * until somebody resolves it by hand. Say so rather than reporting
             * a clean folder. */
            if (S->kept_n[fidx] < WK_MAX_KEPT)   /* log only what we count */
                log_printf(LOG_INFO, "worker: keeping '%s' - the peer deleted "
                           "it, our copy is newer; it will show as out of sync "
                           "there", fi.name);
            hset_add(S->kept_h[fidx], &S->kept_n[fidx], WK_MAX_KEPT, fi.name);
        }
        if (fi.deleted && act != SYNC_DELETE) {
            /* Nothing in the index to remove - typically a file we never
             * finished fetching, so it has no record - but there may well be
             * a PARTIAL of it on disk, and the peer has just said the file is
             * gone. Nothing will ever complete it. Left alone it sits there
             * until the seven-day temp sweep, and for all that time its drawer
             * cannot be deleted: 148 of these across three drawers is what a
             * peer deleting 5000 files mid-fetch left on the A4000. If it is
             * the download in flight, drop that first - resuming a file the
             * peer has deleted is work for nobody. */
            if (S->dl.active && strcmp(S->dl.fi.name, fi.name) == 0)
                abort_download(S);
            folder_delete_temp(S->cfg->folders[fidx].path, fi.name);
            if (!hset_add(S->gone_h[fidx], &S->gone_n[fidx], WK_MAX_GONE,
                          fi.name) && S->spill[fidx].ok) {
                /* More deletions in flight than names we can hold. Tracking
                 * them one by one was never going to scale to "the user threw
                 * away half the folder", and the parked list is at its most
                 * stale exactly then - so throw it away and ask the peer for a
                 * fresh index instead. That is the one thing guaranteed to
                 * reflect the deletions, and it costs a single re-stream.
                 * Sized at 256 because a first sync interrupted by a handful
                 * of deletions is the common case and must not pay for this. */
                log_printf(LOG_INFO, "worker: more than %d deletions while "
                           "'%s' was still arriving; dropping what is parked "
                           "and asking for a fresh index", WK_MAX_GONE,
                           S->cfg->folders[fidx].id);
                spill_close(&S->spill[fidx]);
                S->gone_n[fidx]  = 0;
                S->want_overflow = 1;
                S->st->resync    = 1;
            }
        }
        if (act == SYNC_DELETE) {
            /* Hold file deletions until the message's adds are all queued: if
             * one of those adds carries this file's content (a rename), the
             * doomed file stays around as a local block source until the fetch
             * is done. No room to defer -> apply now (only the rename
             * optimisation is lost). */
            if (!defer_push(S, fidx, &fi) && !spill_delete(S, fidx, &fi))
                apply_peer_delete(S, fidx, &fi);   /* no room anywhere: now */
            continue;
        }
        if (act == SYNC_ADOPT) {
            /* Identical content, dominating peer version: take the peer's
             * record WHOLE - vector, mtime, permissions - and stamp the
             * disk file to match (I/O outside the lock), exactly as a
             * finished download would. Announcing its version with any
             * OTHER metadata is a protocol inconsistency: it left the
             * peer's DB and disk disagreeing about the file, and its next
             * delete tripped Syncthing's changed-on-disk safeguard into a
             * spurious sync-conflict copy (seen on the A4000). The bumped
             * sequence announces the record on the normal cursor. */
            int adopted = 0;
            foldstate_lock(fs);
            {
                FolderRec *h = foldstate_find(fs, fi.name);
                if (h && !h->deleted) {
                    foldstate_set_version(fs, h, &fi.version);
                    h->modified_s  = fi.modified_s;
                    h->modified_ns = fi.modified_ns;
                    h->modified_by = fi.modified_by;
                    h->permissions = fi.permissions;
                    h->sequence    = foldstate_next_seq(fs);
                    adopted = 1;
                }
            }
            foldstate_unlock(fs);
            if (adopted) {
                folder_touch(S->cfg->folders[fidx].path, fi.name,
                             fi.modified_s, fi.permissions);
                log_printf(LOG_INFO, "worker: adopted peer's version of "
                           "'%s' (identical content, no transfer)", fi.name);
            }
            continue;
        }
        if (act != SYNC_FETCH && act != SYNC_CONFLICT)
            continue;
        if (wk_pending(S, fidx, fi.name))
            continue;                          /* already in flight / queued */

        /* Can we actually address and buffer this file? We handle block sizes up
         * to FOLDER_MAX_BLOCK_SIZE and up to FOLDER_MAX_BLOCKS blocks. An empty
         * file has no blocks (and may omit block_size), so let it pass. */
        if (nb > 0 && (fi.block_size <= 0 || fi.block_size > FOLDER_MAX_BLOCK_SIZE ||
                       nb > FOLDER_MAX_BLOCKS)) {
            SyncMeta m;
            log_printf(LOG_WARN, "worker: skipping '%s' (too large to sync)",
                       fi.name);
            meta_from_fileinfo(&m, &fi);
            announce_unstorable(S, fidx, &m);  /* peer stops counting it needed */
            continue;
        }

        if (act == SYNC_CONFLICT)
            log_printf(LOG_INFO, "worker: concurrent edit of '%s' - peer's copy "
                       "wins, ours will be kept as a conflict copy", fi.name);

        note_wanted(S, fidx, &fi);
        if (!sync_want_push(&S->model, fidx, &fi, S->bh, nb,
                            act == SYNC_CONFLICT)) {
            /* Queue full: the rest of this Index message cannot be taken now
             * and the peer will not re-send it unasked. Note the overflow;
             * after this batch drains the session is recycled to fetch the
             * remainder (see want_overflow in Sync). */
            /* The queue is full. Park the rest on disk and keep reading:
             * the peer says everything once, and the queue refills from the
             * spill as files complete. Only when that cannot be done do we
             * fall back to the old answer - drop it and ask the peer to send
             * its whole Index again after this batch. */
            if (spill_want(S, fidx, &fi, nb, act == SYNC_CONFLICT))
                continue;
            log_printf(LOG_INFO, "worker: want queue full at '%s'; will "
                       "reconnect for the remainder after this batch",
                       fi.name);
            S->want_overflow = 1;
            S->st->resync   = 1;      /* the folder is behind from here on */
            break;
        }
        added++;
    }

    /* Now that every add in this message is queued, apply the deletions whose
     * content no queued fetch wants as a local source (the rest wait in
     * S->defer until their matching fetch completes). */
    flush_deferred(S, drain_parked_deletes(S));

    if (added)
        log_printf(LOG_INFO, "worker: %d file(s) to fetch from '%s'", added, folder);
}

/* Close out a finished download: re-verify + rename into place, record it in the
 * shared index (the peer's version, our new sequence, with its block hashes), and
 * let the next announce pass tell our peers. The content_hash check inside
 * folder_recv_finish guards the rename, so a verify failure leaves any existing
 * copy untouched. */
static void finalize_download(Sync *S)
{
    FolderState        *fs = &S->folders[S->dl.folder_idx];
    const ConfigFolder *f  = &S->cfg->folders[S->dl.folder_idx];
    FolderRecvInfo      vi;
    int                 rc;
    int                 retryable = 1;   /* re-queue on failure? (see below) */
    int                 revert;          /* receive-only: replacing a local edit */

    /* Every block was hash-verified as it was written UNLESS the temp resumed
     * an earlier run's partial (that prefix was never seen this session):
     * skip_verify spares the full re-read + re-hash of the staged file, which
     * would otherwise double the I/O and SHA cost of every receive. */
    /* In a receive-only folder a file that is already on disk here is one the
     * user edited: the scanner forgets such a record so the peer's copy is
     * fetched back, which is what keeps a mirror a mirror (see scanner.c). The
     * edit itself, though, exists on no peer and nowhere else, so it is
     * archived whatever the versioning setting says - a preference about
     * peer-driven overwrites is the wrong thing to gate destroying the only
     * copy of someone's own work. */
    revert = (f->mode == FOLDER_RECEIVEONLY) &&
             folder_exists(f->path, S->dl.fi.name);

    rc = folder_recv_finish(f->path, S->dl.fi.name, S->dl.tmp, S->dl.fh,
                            S->dl.fi.modified_s, S->dl.fi.permissions,
                            S->dl.fi.block_size, S->dl.fi.size, !S->dl.resumed,
                            revert,
                            S->dl.fi.has_content_hash ? S->dl.fi.content_hash : NULL,
                            S->dl.hashes, S->dl.num_blocks, &vi);
    if (rc == FOLDER_RECV_OK) {
        SyncMeta m = S->dl.fi;              /* peer version + content_hash kept */
        foldstate_lock(fs);
        m.sequence = foldstate_next_seq(fs);
        foldstate_upsert(fs, &m, S->dl.hashes, S->dl.num_blocks);
        foldstate_unlock(fs);
        stall_clear(S, S->dl.folder_idx, S->dl.fi.name);
        if (revert) {
            int fx = S->dl.folder_idx;
            if (fx >= 0 && fx < CONFIG_MAX_FOLDERS)
                S->st->reverted_f[fx]++;
            S->st->reverted++;
            log_printf(LOG_WARN, "worker: '%s' was edited here, but '%s' is "
                       "receive-only - the peer's copy has replaced it; your "
                       "version is in .stversions", S->dl.fi.name, f->id);
        }
        log_printf(LOG_INFO, "worker: completed '%s'", S->dl.fi.name);
    } else if (rc == FOLDER_RECV_CLOSE) {
        log_printf(LOG_WARN, "worker: discarded '%s' (could not flush staged file "
                   "- disk full or write error?)", S->dl.fi.name);
    } else if (rc == FOLDER_RECV_IO) {
        switch (vi.io_reason) {
        case FOLDER_IO_NOMEM:
            log_printf(LOG_WARN, "worker: discarded '%s' (out of memory for the "
                       "verify buffer)", S->dl.fi.name);
            break;
        case FOLDER_IO_OPEN:
            log_printf(LOG_WARN, "worker: discarded '%s' (could not re-open staged "
                       "file to verify, IoErr %ld)", S->dl.fi.name, vi.ioerr);
            break;
        case FOLDER_IO_READ:
            log_printf(LOG_WARN, "worker: discarded '%s' (read error verifying after "
                       "%d/%d block(s), IoErr %ld)", S->dl.fi.name,
                       vi.got_blocks, vi.exp_blocks, vi.ioerr);
            break;
        case FOLDER_IO_TOOBIG:
            log_printf(LOG_WARN, "worker: discarded '%s' (staged file has more than "
                       "%d block(s) - far larger than the expected %d)",
                       S->dl.fi.name, vi.got_blocks, vi.exp_blocks);
            break;
        case FOLDER_IO_PATH:
            log_printf(LOG_WARN, "worker: discarded '%s' (final path too long to "
                       "assemble)", S->dl.fi.name);
            retryable = 0;                     /* the name will not get shorter */
            break;
        case FOLDER_IO_RENAME:
            log_printf(LOG_WARN, "worker: discarded '%s' (verify OK but rename into "
                       "place failed, IoErr %ld - filename too long for the "
                       "filesystem?)", S->dl.fi.name, vi.ioerr);
            retryable = 0;                     /* likewise: re-fetching is waste */
            break;
        case FOLDER_IO_SIZE:
            log_printf(LOG_WARN, "worker: discarded '%s' (staged file's flushed "
                       "size differs from the expected %ld bytes - disk full?)",
                       S->dl.fi.name, (long)S->dl.fi.size);
            break;
        default:
            log_printf(LOG_WARN, "worker: discarded '%s' (could not re-read staged "
                       "file)", S->dl.fi.name);
            break;
        }
    } else if (vi.got_blocks >= 0 && vi.got_blocks != vi.exp_blocks) {
        log_printf(LOG_WARN, "worker: discarded '%s' (staged file is %d block(s), "
                   "expected %d - truncated?)", S->dl.fi.name,
                   vi.got_blocks, vi.exp_blocks);
    } else if (vi.bad_block >= 0) {
        log_printf(LOG_WARN, "worker: discarded '%s' (block %d at offset %ld differs "
                   "on disk from what was received)", S->dl.fi.name,
                   vi.bad_block, (long)vi.bad_off);
    } else {
        log_printf(LOG_WARN, "worker: discarded '%s' (final verify failed)",
                   S->dl.fi.name);
    }
    S->dl.active = 0;
    release_claim(S);
    if (rc != FOLDER_RECV_OK)
        requeue_download(S, retryable);
}

/* Preserve the local loser of a concurrent edit before its slot is fetched
 * over: rename it to a Syncthing-style conflict name (a compact one if the
 * filesystem can't fit that) and register the copy in the shared index as a
 * local change - the sequence bump announces it, so the conflict copy
 * propagates to the peer exactly as Syncthing's do. Best-effort: if no name
 * fits or the rename fails, the fetch simply overwrites (the old behaviour). */
static void conflict_preserve_local(Sync *S, int fidx, const char *name)
{
    FolderState        *fs = &S->folders[fidx];
    const ConfigFolder *f  = &S->cfg->folders[fidx];
    SyncMeta            have;
    char                cn[BEP_PATH_MAX];
    int                 had = 0, nb = 0, ok;

    foldstate_lock(fs);
    {
        FolderRec *h = foldstate_find(fs, name);
        if (h && !h->deleted) {
            had = 1;
            foldstate_meta(fs, h, &have);
            nb = foldstate_blocks(fs, name, S->bh, FOLDER_MAX_BLOCKS, NULL);
        }
    }
    foldstate_unlock(fs);
    if (!had)
        return;                                /* nothing on our side to keep */

    ok = sync_make_conflict_name(cn, sizeof(cn), name, folder_now(),
                                 S->ctag, 0) &&
         folder_name_fits(f->path, cn);
    if (!ok)                                   /* tight filesystem: short form */
        ok = sync_make_conflict_name(cn, sizeof(cn), name, folder_now(),
                                     S->ctag, 1) &&
             folder_name_fits(f->path, cn);
    if (!ok) {
        log_printf(LOG_WARN, "worker: no conflict name fits for '%s'; peer's "
                   "copy will replace ours", name);
        return;
    }
    if (!folder_rename(f->path, name, cn)) {
        log_printf(LOG_WARN, "worker: could not rename '%s' to '%s'; peer's "
                   "copy will replace ours", name, cn);
        return;
    }

    /* Register the copy as a brand-new local file carrying the loser's version
     * history forward (so it dominates nothing but conflicts with nothing). */
    scopy(have.name, cn, sizeof(have.name));
    foldstate_lock(fs);
    sync_bump_version(&have.version, &have.version, fs->short_id,
                      folder_version_stamp(have.modified_s));
    have.modified_by = fs->short_id;      /* the rename is our change */
    have.sequence = foldstate_next_seq(fs);
    if (!foldstate_upsert(fs, &have, S->bh, nb))
        log_printf(LOG_WARN, "worker: index full registering conflict copy '%s'",
                   cn);
    foldstate_unlock(fs);
    log_printf(LOG_INFO, "worker: preserved our '%s' as '%s'", name, cn);
}

/* Rename/copy detection: before requesting blocks over the network, look for a
 * local live file with the same size and content_hash as the fetch target and
 * copy as many blocks as verify (SHA-256 against the peer's expected hashes)
 * out of it into the staged temp. Whatever this fills, the network FSM no
 * longer requests; a mismatch (stale index, changed file) just falls back to
 * the network from that block on. */
static void local_prefill(Sync *S)
{
    FolderState        *fs = &S->folders[S->dl.folder_idx];
    const ConfigFolder *f  = &S->cfg->folders[S->dl.folder_idx];
    char                src[BEP_PATH_MAX];
    int                 found = 0, i, filled = 0;
    int32_t             bsz = S->dl.fi.block_size;

    if (S->dl.num_blocks <= 0 || S->dl.next_block >= S->dl.num_blocks ||
        !S->dl.fi.has_content_hash || bsz <= 0)
        return;

    foldstate_lock(fs);
    for (i = 0; i < fs->num_files; i++) {
        const FolderRec *r = &fs->files[i];
        if (!r->deleted && r->type == BEP_FILE_FILE &&
            r->has_content_hash && r->size == S->dl.fi.size &&
            strcmp(foldstate_name(fs, r), S->dl.fi.name) != 0 &&
            memcmp(r->content_hash, S->dl.fi.content_hash, BEP_HASH_LEN) == 0) {
            scopy(src, foldstate_name(fs, r), sizeof(src));
            found = 1;
            break;
        }
    }
    foldstate_unlock(fs);
    if (!found)
        return;
    if (!sync_ensure_blockbuf(S, bsz))
        return;                                /* no scratch: plain download */

    while (S->dl.next_block < S->dl.num_blocks) {
        int           b = S->dl.next_block;
        int64_t       off;
        int32_t       want = dl_block_span(S, b, &off);
        unsigned char h[BEP_HASH_LEN];

        if (folder_read_block(f->path, src, off, want, S->blockbuf) != want)
            break;
        folder_sha256(S->blockbuf, want, h);
        if (memcmp(h, S->dl.hashes[b], BEP_HASH_LEN) != 0)
            break;                             /* source differs: use network */
        if (folder_recv_write(S->dl.fh, off, S->blockbuf, want) != FOLDER_WRITE_OK)
            break;
        S->dl.next_block++;
        filled++;
    }
    if (filled)
        log_printf(LOG_INFO, "worker: copied %d/%d block(s) of '%s' from local "
                   "'%s'", filled, S->dl.num_blocks, S->dl.fi.name, src);
}

/* Did the file we queued arrive by another route while we waited our turn? In a
 * folder shared with more than one peer every worker queues the same files, so
 * by the time the claim frees up the other worker has usually written it
 * already. Compared on content, not version: an identical file is identical
 * whoever wrote it, and our index is only marked from disk (scanner) or from a
 * rename that has landed (finalize_download), so a match means it is really
 * there. */
static int already_have(Sync *S, int fidx, const SyncMeta *fi)
{
    FolderState *fs = &S->folders[fidx];
    int          have;

    if (!fi->has_content_hash)
        return 0;                              /* nothing to compare against */
    foldstate_lock(fs);
    {
        const FolderRec *h = foldstate_find(fs, fi->name);
        have = h && !h->deleted && h->has_content_hash &&
               h->size == fi->size &&
               memcmp(h->content_hash, fi->content_hash, BEP_HASH_LEN) == 0;
    }
    foldstate_unlock(fs);
    return have;
}

/* Begin the next queued download (pop its expected block hashes, open or resume a
 * temp). A surviving partial temp resumes from its completed blocks, so only the
 * remaining blocks are fetched; the final whole-file verify guards the prefix. */
static void start_download(Sync *S)
{
    WantFile            t;
    const ConfigFolder *f;
    int                 resume_from = 0;

    if (S->dl.active)
        return;

    /* Every peer sharing this folder offers the same files, and each peer's
     * worker queues them independently. Take the fetch claim before committing
     * to the pop: denied means another worker is already on this file, so leave
     * it queued (peek does not remove it) and come back next pass rather than
     * have two workers write one staged temp. Waiting costs nothing real here -
     * the machine, not the source, is the bottleneck - and if the worker
     * holding the claim loses its peer, the claim goes with it and this one
     * picks the file up, resuming from the temp already on disk.
     *
     * Then skip whatever landed while we waited: our turn often comes after the
     * other worker has already written the very file we queued, and fetching it
     * again would move the same megabytes twice. Loop rather than return, so a
     * run of such entries drains in one pass instead of one per network wake. */
    for (;;) {
        int  pf = -1;
        char pn[BEP_PATH_MAX];

        if (!sync_want_peek(&S->model, &pf, pn, sizeof(pn)))
            return;                            /* queue empty */
        if (pf < 0 || pf >= CONFIG_MAX_FOLDERS)
            return;
        if (!foldstate_claim(&S->folders[pf], pn, S))
            return;                            /* another worker has it */
        S->claim_fidx = pf;

        if (!sync_want_pop(&S->model, &t, S->dl.hashes, FOLDER_MAX_BLOCKS)) {
            release_claim(S);
            return;
        }
        if (!already_have(S, t.folder_idx, &t.fi)) {
            /* Queued files go stale the same way parked ones do, and for
             * longer than it looks: the queue holds 256, and the peer can
             * delete any of them between offering it and our getting to it.
             * Asking anyway costs three round trips, an "out of sync" count
             * that clears only on the next connection, and a partial left to
             * hold its drawer un-deletable for a week. The queue cannot drop
             * a middle entry - its block hashes are a LIFO stack - but it does
             * not need to: this is the same "never mind" the already-have
             * check above performs, one line later. */
            if (!hset_has(S->gone_h[t.folder_idx], S->gone_n[t.folder_idx],
                          t.fi.name))
                break;
            log_printf(LOG_DEBUG, "worker: '%s' was deleted while queued; "
                       "not fetching it", t.fi.name);
            release_claim(S);
            continue;
        }
        log_printf(LOG_DEBUG, "worker: '%s' already here (another peer's worker "
                   "fetched it); nothing to do", t.fi.name);
        release_claim(S);
    }

    f = &S->cfg->folders[t.folder_idx];

    /* Skip up front if this folder's filesystem can't store the file's name
     * intact (e.g. an over-30-char name on FFS). Otherwise we would fetch the
     * whole file - megabytes - only to fail the final rename, every scan. The
     * want was already popped, so it just re-checks (cheaply) next pass. */
    if (!folder_name_fits(f->path, t.fi.name)) {
        log_printf(LOG_WARN, "worker: skipping '%s' (filename too long for this "
                   "folder's filesystem - use PFS3/SFS or a shorter name)",
                   t.fi.name);
        announce_unstorable(S, t.folder_idx, &t.fi);  /* peer stops counting it */
        release_claim(S);
        return;
    }

    /* A concurrent-edit loser is preserved under a conflict name before the
     * winner is fetched into its place. */
    if (t.conflict)
        conflict_preserve_local(S, t.folder_idx, t.fi.name);

    S->dl.folder_idx   = t.folder_idx;
    S->dl.fi           = t.fi;
    S->dl.attempts     = t.attempts + 1;       /* counting the one starting now */
    S->dl.num_blocks   = t.num_blocks;
    S->dl.num_inflight = 0;
    S->dl.num_redo     = 0;
    S->dl.tmp[0]       = '\0';
    scopy(S->dl.folder_id, f->id, sizeof(S->dl.folder_id));

    S->dl.fh = folder_recv_open(f->path, t.fi.name, S->dl.tmp, sizeof(S->dl.tmp),
                                t.fi.block_size, t.num_blocks, &resume_from);
    if (!S->dl.fh) {
        log_printf(LOG_WARN, "worker: cannot create temp file for '%s'", t.fi.name);
        release_claim(S);
        requeue_download(S, 1);            /* the want was popped: do not lose it */
        return;
    }
    S->dl.next_block = resume_from;
    S->dl.resumed    = resume_from > 0;
    S->dl.active     = 1;
    if (resume_from > 0)
        log_printf(LOG_INFO, "worker: resuming '%s' from block %d/%d",
                   t.fi.name, resume_from, t.num_blocks);
    else
        log_printf(LOG_INFO, "worker: fetching '%s' (%d block(s))",
                   t.fi.name, t.num_blocks);

    /* Satisfy as much as possible from a local same-content file (a rename or
     * copy on the peer's side) before touching the network. */
    local_prefill(S);
}

/* Send one block Request and add it to the in-flight window. 'retries' carries
 * a redo entry's count across the re-request. Returns 0 on a send failure. */
static int send_block_request(Sync *S, int block, int retries)
{
    BepRequest rq;
    int64_t    off;
    int32_t    want = dl_block_span(S, block, &off);
    Inflight  *fl;

    memset(&rq, 0, sizeof(rq));
    rq.id = ++S->next_req_id;
    scopy(rq.folder, S->dl.folder_id, sizeof(rq.folder));
    scopy(rq.name, S->dl.fi.name, sizeof(rq.name));
    rq.offset = off;
    rq.size   = want;
    memcpy(rq.hash, S->dl.hashes[block], BEP_HASH_LEN);
    rq.has_hash = 1;

    if (!bep_send_request(S->conn, &rq))
        return 0;
    fl = &S->dl.inflight[S->dl.num_inflight++];
    fl->block   = block;
    fl->id      = rq.id;
    fl->retries = retries;
    return 1;
}

/* Drive outbound progress: start a download if idle, finalize a finished one,
 * or keep the request window full - redo blocks first, then fresh ones. Block
 * offset/size are derived from the file's own block size (S->dl.fi.block_size).
 * Returns 0 on a transport send failure. */
static void publish_pending(Sync *S);

static int progress(Sync *S)
{
    for (;;) {
        if (!S->dl.active)
            start_download(S);
        if (!S->dl.active)
            return 1;                          /* nothing left to fetch */

        if (S->dl.next_block >= S->dl.num_blocks &&
            S->dl.num_inflight == 0 && S->dl.num_redo == 0) {
            finalize_download(S);              /* all blocks in (or empty file) */
            /* Publish from INSIDE the loop, not only where the caller does it.
             * A file whose blocks all came from a local copy needs no network
             * at all, so this loop runs to the end of the queue without ever
             * returning - and a whole renamed drawer was fetched, written and
             * finished between two counts of an empty queue. The status said
             * "Up to Date" for the minute and a half the A4000 spent copying
             * 200 files. */
            publish_pending(S);
            continue;                          /* try the next queued file */
        }

        while (S->dl.num_inflight < WK_WINDOW) {
            if (S->dl.num_redo > 0) {
                Inflight r = S->dl.redo[--S->dl.num_redo];
                if (!send_block_request(S, r.block, r.retries))
                    return 0;
            } else if (S->dl.next_block < S->dl.num_blocks) {
                if (!send_block_request(S, S->dl.next_block, 0))
                    return 0;
                S->dl.next_block++;
            } else {
                break;                         /* tail: window drains */
            }
        }
        return 1;                              /* window full/drained; go wait */
    }
}

/* (Re)load per-folder ignores (cheap; picks up .stignore edits mid-connection,
 * matching the pre-4a behaviour where the rescan reloaded them). A folder's
 * set is heap-allocated the first time its .stignore actually has patterns;
 * on an allocation failure the slot just stays NULL - receive stays correct,
 * only the filtering is lost until the next refresh. */
/* FNV-1a over what actually decides matching, so an edit that changes nothing
 * (a comment, whitespace, reordering into the same rules) stays quiet. */
static unsigned long ignore_fingerprint(const IgnoreSet *set)
{
    unsigned long h = 2166136261UL;
    int           i;
    const char   *p;

    for (i = 0; i < set->n; i++) {
        for (p = set->pats[i].glob; *p; p++)
            h = (h ^ (unsigned long)(unsigned char)*p) * 16777619UL;
        h = (h ^ (unsigned long)set->pats[i].negate)    * 16777619UL;
        h = (h ^ (unsigned long)set->pats[i].has_slash) * 16777619UL;
    }
    return (h ^ (unsigned long)set->n) * 16777619UL;
}

static void refresh_ignores(Sync *S)
{
    IgnoreSet tmp;                      /* ~6 KB; the worker stack is 128 KB */
    int       i;

    for (i = 0; i < S->cfg->num_folders; i++) {
        unsigned long fp;

        if (S->cfg->folders[i].removed)
            continue;
        /* -1 is "there but unreadable": keep the rules we already have rather
         * than read a blip as the user deleting every one of them, which would
         * both un-hide files and bounce the need generation below. */
        if (folder_load_ignores(S->cfg->folders[i].path, &tmp) < 0)
            continue;

        /* Relaxing a rule does not pull in what it was hiding on its own: the
         * peer's Index was turned into wants when it arrived and then dropped,
         * and BEP has no resend. Note that what we need has changed and let
         * the session recycle below fetch it. */
        fp = ignore_fingerprint(&tmp);
        if (S->ign_fp_seen[i] && fp != S->ign_fp[i]) {
            log_printf(LOG_INFO, "worker: ignore rules changed for '%s'; "
                       "re-asking the peer for what they now allow",
                       S->cfg->folders[i].id);
            foldstate_need_changed(&S->folders[i]);
        }
        S->ign_fp[i]      = fp;
        S->ign_fp_seen[i] = 1;

        if (tmp.n > 0) {
            if (!S->ignores[i])
                S->ignores[i] = AllocVec(sizeof(IgnoreSet), MEMF_ANY);
            if (S->ignores[i])
                *S->ignores[i] = tmp;
        } else if (S->ignores[i]) {
            S->ignores[i]->n = 0;       /* .stignore removed or emptied */
        }
    }
}

/* The peer's ClusterConfig: rebuild the mutual-share map and refresh what it
 * is offering us. A folder TRANSITIONING to shared restarts its announce from
 * zero - the peer just (re)accepted it and expects the full index. The message
 * is the peer's COMPLETE offer set, so the sweep between offered_begin/end
 * makes a withdrawn offer vanish with the very message that withdrew it.
 *
 * Kept out of worker_sync's switch so the ~30 KB BepClusterConfig lives in a
 * leaf frame rather than the event loop's. */
static void handle_cluster_config(Sync *S, const unsigned char *body, int blen)
{
    BepClusterConfig cc;
    unsigned char    now[CONFIG_MAX_FOLDERS];
    int              i;

    if (!bep_decode_cluster_config(body, blen, &cc))
        return;

    log_printf(LOG_INFO, "worker: peer ClusterConfig, %d folder(s)",
               cc.num_folders);

    memset(now, 0, sizeof(now));
    offered_begin(S->st->peer_actual_id);
    for (i = 0; i < cc.num_folders; i++) {
        int fx = sync_folder_index(S->cfg, cc.folders[i].id);
        if (fx >= 0 && fx < CONFIG_MAX_FOLDERS)
            now[fx] = 1;
        else if (fx < 0)
            /* a folder we have no config for: the peer is offering it
             * (Syncthing's "wants to share") */
            offered_note(S->st->peer_actual_id, S->st->peer_name,
                         cc.folders[i].id, cc.folders[i].label);
    }
    offered_end(S->st->peer_actual_id);

    for (i = 0; i < CONFIG_MAX_FOLDERS; i++) {
        if (now[i] && !S->peer_shares[i]) {
            S->cursor[i]    = 0;
            S->announced[i] = 0;
        }
        S->peer_shares[i] = now[i];
    }
}

/* Re-send our ClusterConfig when the folder set changed underneath us (runtime
 * ADDFOLDER/REMOVEFOLDER) or a fresh folder finished its first scan and became
 * eligible - Syncthing accepts an updated CC mid-session. Each changed folder's
 * announce cursor resets so its index streams from scratch; a removed folder
 * simply vanishes from the CC and the peer unshares it. Returns 0 on a send
 * failure. Holds the ~30 KB BepClusterConfig in this leaf frame rather than the
 * event loop's. */
static int sync_folder_set(Sync *S)
{
    unsigned long em          = cc_eligible_mask(S->cfg, S->folders);
    int           gen_changed = S->cfg_gen != S->cfg->config_gen;
    int           i;

    if (gen_changed) {
        S->cfg_gen = S->cfg->config_gen;
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++) {
            if (S->fgen[i] != S->cfg->folders[i].gen) {
                S->fgen[i]      = S->cfg->folders[i].gen;
                S->cursor[i]    = 0;
                S->announced[i] = 0;
            }
        }
        /* A folder we just un-configured that the peer's last CC still lists
         * reverts to being an OFFER from that peer. Re-note it: the CC decode
         * swept the original entry the moment the folder became configured,
         * and a connected Syncthing has no reason to re-send its unchanged CC
         * after our unshare - without this the offer only reappears on a
         * reconnect. The tombstoned slot keeps its id and label. */
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++)
            if (S->peer_shares[i] && S->cfg->folders[i].removed)
                offered_note(S->st->peer_actual_id, S->st->peer_name,
                             S->cfg->folders[i].id, S->cfg->folders[i].label);
    }

    if (!gen_changed && em == S->cc_mask)
        return 1;

    S->cc_mask = em;
    if (S->have_our_raw) {
        BepClusterConfig cc;
        build_cluster_config(S->cfg, S->folders, S->our_raw,
                             S->have_peer_raw ? S->peer_raw : NULL,
                             S->st->device_name, &cc, em);
        if (!bep_send_cluster_config(S->conn, &cc))
            return 0;
        log_printf(LOG_INFO, "worker: folder set changed; sent updated "
                   "ClusterConfig (%d folder(s))", cc.num_folders);
    }
    return 1;
}

/* Publish the live fetch backlog for the daemon's status aggregation: files
 * queued to pull plus the one in flight. 0 while connected = this peer is up
 * to date. The per-folder split feeds the Folders list's State column. */
static void publish_pending(Sync *S)
{
    int pf[CONFIG_MAX_FOLDERS];
    int k;

    memset(pf, 0, sizeof(pf));
    for (k = 0; k < S->model.num_want; k++) {
        int fx = S->model.want[k].folder_idx;
        if (fx >= 0 && fx < CONFIG_MAX_FOLDERS)
            pf[fx]++;
    }
    if (S->dl.active && S->dl.folder_idx >= 0 &&
        S->dl.folder_idx < CONFIG_MAX_FOLDERS)
        pf[S->dl.folder_idx]++;
    /* Files we have stopped fetching are still missing, so they still count:
     * reporting "Up to Date" over a file the peer has and we do not is the one
     * answer a sync status must never give. */
    for (k = 0; k < S->num_stalled; k++) {
        int fx = S->stalled_fidx[k];
        if (fx >= 0 && fx < CONFIG_MAX_FOLDERS)
            pf[fx]++;
    }

    /* Files parked on disk because the queue was full are still wanted, and
     * counting only the queue would report a 2500-file transfer as 256 files
     * forever - the same lie the old drop-and-reconnect told by another
     * route. */
    for (k = 0; k < CONFIG_MAX_FOLDERS; k++)
        pf[k] += spill_count(&S->spill[k]);

    for (k = 0; k < CONFIG_MAX_FOLDERS; k++)
        S->st->pending_f[k] = pf[k];
    S->st->pending = S->model.num_want + (S->dl.active ? 1 : 0) + S->num_stalled;
    for (k = 0; k < CONFIG_MAX_FOLDERS; k++)
        S->st->pending += spill_count(&S->spill[k]);

    {
        int kept = 0;
        for (k = 0; k < CONFIG_MAX_FOLDERS; k++) {
            S->st->kept_f[k] = S->kept_n[k];
            kept += S->kept_n[k];
        }
        S->st->kept = kept;
    }
}

/* The connected event loop: each pass drives our downloads, announces any
 * records the scanner (or our own receives) have advanced past the cursor, then
 * waits - serving the peer's Requests/Index, answering Pings, honouring the stop
 * signal. Returns 0 on a clean close/stop, non-zero on error. */
static int worker_sync(Sync *S)
{
    for (;;) {
        unsigned long got = 0;
        int           w;

        /* Pause closes the connection - inbound ones too. peer_pause wakes
         * every worker (wreg RESCAN) after setting the flag, so this is
         * seen promptly rather than on the next idle tick. */
        if (S->st->peer_cfg &&
            (S->st->peer_cfg->paused || S->st->peer_cfg->removed)) {
            log_printf(LOG_INFO, "worker: peer paused; closing connection");
            bep_send_close(S->conn, "paused");
            return 0;
        }

        if (!sync_folder_set(S))
            return 1;

        if (!progress(S))
            return 1;
        /* Parked file deletions FIRST: a drawer tombstone in the defer list
         * cannot be applied until the files inside it are gone, and it is the
         * flush that has the retry budget. */
        forget_wants_when_idle(S);   /* before the flush: it reads the set */
        /* Order matters, and it is the opposite of what one statement made it.
         *
         * The flush goes FIRST so the in-memory backlog is empty before the
         * drain runs. Those entries are the deletions that did not fit the
         * list when the peer spoke, and some of them are files inside the very
         * drawer the drain is about to try to remove - so draining first left
         * the drawer standing, non-empty, exactly as if it had never been
         * parked. Written as one nested call the argument evaluated first,
         * which put the drain before the flush and hid this behind an
         * evaluation-order detail.
         *
         * Then the drain applies the parked files and its drawers, and a
         * second flush takes any drawer it had to hand back, told what the
         * drain removed so it is not counted as a fruitless pass. */
        flush_deferred(S, 0);
        {
            int done = drain_parked_deletes(S);
            if (done)
                flush_deferred(S, done);
        }
        refill_from_spill(S);  /* what a finished fetch frees, a parked one takes */
        if (!announce_all(S))                  /* stream new records to the peer */
            return 1;

        /* Two reasons to recycle a healthy session, both the same shape: we
         * want something this peer has already told us about once, and its
         * Index is gone. Either an oversized Index overflowed the want queue
         * and the excess was dropped, or our own side changed what we need
         * (a rule relaxed, a mirror's record forgotten). Wait until everything
         * we did queue has drained and our announces are streamed, then close
         * cleanly: the peer re-sends its complete Index on the reconnect.
         *
         * Both terminate. The overflow case shrinks the remainder every cycle
         * (see want_overflow). The need-generation case is edge-triggered by a
         * change that has already happened - a rule edit, a file removed from
         * a mirror - and the reconnect re-snapshots, so a steady state stops
         * asking. Nothing that can fail repeatedly bumps it: a file we give up
         * on is left counted rather than re-asked, precisely so a peer that
         * cannot serve it does not become a reconnect loop. */
        if (!S->dl.active && S->model.num_want == 0 && S->num_defer == 0) {
            int stale = 0, k;

            for (k = 0; k < CONFIG_MAX_FOLDERS; k++)
                if (foldstate_need_gen(&S->folders[k]) != S->need_gen[k]) {
                    stale = 1;
                    break;
                }
            if (S->want_overflow) {
                log_printf(LOG_INFO, "worker: batch of an oversized index done; "
                           "reconnecting for the remainder");
                bep_send_close(S->conn, "index batch done; reconnecting for more");
                return 0;
            }
            if (stale) {
                log_printf(LOG_INFO, "worker: what we need has changed; "
                           "reconnecting for a fresh index");
                S->st->resync = 1;             /* still syncing, not finished */
                bep_send_close(S->conn, "need changed; reconnecting");
                return 0;
            }
        }

        publish_pending(S);

        /* The TLS layer may already hold received data that WaitSelect cannot
         * see (a record's tail carrying the next message - routine now that
         * pipelined Responses stream back-to-back). If so skip the wait, but
         * still take any pending stop/rescan signals the way net_wait would. */
        if (ssl_buffered(S->ssl)) {
            got = SetSignal(0L, WORKER_SIG_STOP | WORKER_SIG_RESCAN) &
                  (WORKER_SIG_STOP | WORKER_SIG_RESCAN);
            w = 1;
        } else {
            w = net_wait(S->sock, WORKER_PING_SECS,
                         WORKER_SIG_STOP | WORKER_SIG_RESCAN, &got);
        }

        if (got & WORKER_SIG_STOP) {
            bep_send_close(S->conn, "shutting down");
            return 0;
        }
        if (got & WORKER_SIG_RESCAN) {         /* on-demand: re-announce now */
            refresh_ignores(S);
            continue;
        }
        if (w < 0) {
            log_printf(LOG_WARN, "worker: net_wait error, ending");
            return 1;
        }
        if (w == 0) {                          /* idle timeout: keepalive */
            if (!bep_send_ping(S->conn))
                return 1;
            refresh_ignores(S);
            continue;                          /* loop top re-announces */
        }

        {
            BepHeader            hdr;
            const unsigned char *body;
            int                  blen;
            int                  r = bep_read_message(S->conn, &hdr, &body, &blen);

            if (r <= 0) {
                log_printf(r == 0 ? LOG_INFO : LOG_WARN,
                           "worker: bep_read_message r=%d (%s)", r,
                           r == 0 ? "peer closed" : "read/framing error");
                return r == 0 ? 0 : 1;         /* peer closed / error */
            }

            switch (hdr.type) {
            case BEP_REQUEST:
                if (!serve_request(S, body, blen))
                    return 1;
                break;
            case BEP_RESPONSE:
                handle_response(S, body, blen);
                break;
            case BEP_INDEX:
            case BEP_INDEX_UPDATE:
                handle_index(S, body, blen, hdr.type == BEP_INDEX);
                break;
            case BEP_CLUSTER_CONFIG:
                handle_cluster_config(S, body, blen);
                break;
            case BEP_CLOSE:
                log_printf(LOG_INFO, "worker: peer sent Close");
                return 0;
            case BEP_PING:
            default:
                break;
            }
        }
    }
}

/* Close a socket the listener handed us that we will never use. ObtainSocket
 * needs a socket base, and the failure that brings us here may be the very
 * thing that stopped us getting one - so open a bare one for the length of the
 * close. Best-effort by nature: if even that fails the machine is out of
 * resources and the descriptor is the smaller problem. */
static void discard_handoff(LONG socket_id)
{
    int s;

    if (!netbase_open())
        return;
    s = ObtainSocket(socket_id, AF_INET, SOCK_STREAM, 0);
    if (s != NET_INVALID_SOCKET)
        net_close(s);
    netbase_close();
}

/* The whole connection lifecycle, run from worker_entry once the startup
 * message has arrived. Returns 0 on success, non-zero on failure. */
static int worker_run(WorkerStartup *st)
{
    SSL_CTX *ctx      = NULL;
    SSL     *ssl      = NULL;
    BepConn *conn     = NULL;
    Sync    *S        = NULL;
    int      sock     = NET_INVALID_SOCKET;
    int      ssl_up   = 0;
    int      rc       = 1;
    unsigned long cc_mask0 = 0;    /* folders our handshake CC listed */
    /* Our identity, derived ONCE from the cert: parsing it means opening the
     * PEM, DERing the X.509 and SHA-256ing it, and both the handshake's
     * ClusterConfig and the Sync block need the result. */
    char          ourid[DEVICE_ID_BUFSZ];
    unsigned char our_raw[32];
    int           have_ourid = 0, have_our_raw = 0;

    /* Retry backoff, waited out one second at a time so a stop can end it.
     * A single Delay() of the whole span is what made shutdown appear to
     * hang: the manager spawns the worker immediately and lets it sleep, the
     * backoff climbs to PEER_BACKOFF_MAX, and Delay() answers no signal - so
     * Quit sat behind up to a minute of sleep on one unreachable peer, with
     * the UI already gone. One-second granularity is plenty for a retry timer
     * and keeps timer.device out of it, exactly as the scanner's nap() does. */
    {
        int i;
        for (i = 0; i < st->initial_delay; i++) {
            if (SetSignal(0L, 0L) & WORKER_SIG_STOP)
                return 0;
            Delay(TICKS_PER_SECOND);
        }
    }

    /* Stand down instead of dialing a peer that is paused or already
     * connected INBOUND (it dialed us first). Dialing anyway just makes the
     * peer reject the duplicate - the "BEP handshake failed" loop - while
     * the working connection is right there. Exiting rc=0 lets the manager's
     * normal backoff pace the re-check. */
    if (st->mode == WORKER_DIAL && st->peer_cfg &&
        (st->peer_cfg->paused || st->peer_cfg->removed ||
         st->peer_cfg->inbound_st)) {
        log_printf(LOG_DEBUG, "worker: standing down (%s)",
                   st->peer_cfg->paused ? "peer paused"
                                        : "inbound connection active");
        return 0;
    }

    if (!ssl_subtask_init()) {
        log_printf(LOG_ERROR, "worker: ssl_subtask_init() failed");
        /* An inbound socket is already OURS: the listener ReleaseSocket()d it
         * and relies on us to adopt and close it. The acquisition below is
         * deliberately the first thing that can fail after this point - but
         * this failure comes BEFORE it, so without reclaiming the socket here
         * the descriptor stays in bsdsocket's released table for the life of
         * the daemon and the peer sits in ESTABLISHED with no FIN. */
        if (st->mode != WORKER_DIAL)
            discard_handoff(st->socket_id);
        goto done;   /* init self-cleans on failure; must NOT call cleanup */
    }
    ssl_up = 1;

    /* Acquire the socket BEFORE the SSL_CTX setup. For an inbound worker the
     * listener has ReleaseSocket()d the accepted socket and relies on us to
     * reclaim and eventually close it; obtaining it first means any later
     * failure (ctx/identity/ALPN, OOM) falls through to `done`, which closes
     * 'sock' - otherwise the released socket would leak permanently. */
    if (st->mode == WORKER_DIAL) {
        log_printf(LOG_INFO, "worker: dialing %s:%u", st->host, st->port);
        sock = net_connect(st->host, st->port, st->connect_timeout);
    } else {
        sock = ObtainSocket(st->socket_id, AF_INET, SOCK_STREAM, 0);
    }
    if (sock == NET_INVALID_SOCKET) {
        /* Distinct subjects: a dial that did not connect, versus the listener's
         * handed-off socket failing to adopt - the latter has no host:port and
         * points at a different bug entirely. */
        if (st->mode == WORKER_DIAL)
            log_printf(LOG_WARN, "worker: connection to %s:%u failed",
                       st->host, st->port);
        else
            log_printf(LOG_WARN, "worker: could not obtain the handed-off "
                       "socket (id %ld)", (long)st->socket_id);
        goto done;
    }
    net_set_nodelay(sock);   /* latency over throughput for our request/response */
    net_set_buffers(sock, 256 * 1024);   /* room for the pipelined block window */

    /* Inbound only: do not enter the TLS handshake until the peer has actually
     * said something. SSL_accept blocks with no timeout of its own, so a host
     * that completes the TCP connection and then sends nothing parks this
     * worker - and its inbound slot - forever. Eight such connections is the
     * whole LISTEN_MAX_INBOUND table, and no authentication has happened yet,
     * so ANY host that can reach the port can shut inbound sync down until the
     * daemon is restarted. Waiting for readability first costs a legitimate
     * peer nothing (its ClientHello is already in flight) and bounds a silent
     * one to WORKER_HELLO_SECS. The wait takes WORKER_SIG_STOP too, so a
     * shutdown no longer has to outlast a stalled handshake either. */
    if (st->mode != WORKER_DIAL) {
        unsigned long got = 0;
        int           w   = net_wait(sock, WORKER_HELLO_SECS,
                                     WORKER_SIG_STOP, &got);
        if (got & WORKER_SIG_STOP)
            goto done;
        if (w <= 0) {
            log_printf(LOG_INFO, "worker: inbound peer sent nothing in %ds; "
                       "dropping it", WORKER_HELLO_SECS);
            goto done;
        }
    }

    ctx = ssl_ctx_new();
    if (!ctx ||
        !ssl_ctx_use_identity(ctx, st->cert_path, st->key_path) ||
        !ssl_ctx_set_alpn_bep(ctx)) {
        log_printf(LOG_ERROR, "worker: SSL_CTX setup failed");
        goto done;
    }

    ssl = (st->mode == WORKER_DIAL) ? ssl_client(ctx, sock) : ssl_server(ctx, sock);
    if (!ssl) {
        log_printf(LOG_WARN, "worker: TLS handshake failed");
        goto done;
    }

    if (!verify_peer(ssl, st))
        goto done;

    /* Resolve the peer's config slot: dialers got it from the manager, an
     * inbound peer is looked up now that it has authenticated. It carries
     * the shared runtime pause/inbound state (config.h). */
    if (!st->peer_cfg && st->cfg) {
        int i;
        for (i = 0; i < st->cfg->num_peers; i++)
            if (device_id_equal(st->peer_actual_id, st->cfg->peers[i].id)) {
                st->peer_cfg = (ConfigPeer *)&st->cfg->peers[i];
                break;
            }
    }
    /* A paused peer is refused in BOTH directions - without this, the peer
     * simply dials us moments after pause "disconnected" it, and syncing
     * carries on behind a status that says Offline. */
    if (st->peer_cfg && (st->peer_cfg->paused || st->peer_cfg->removed)) {
        log_printf(LOG_INFO, "worker: peer %.7s is %s; refusing connection",
                   st->peer_actual_id,
                   st->peer_cfg->removed ? "removed" : "paused");
        goto done;
    }

    conn = AllocVec(sizeof(BepConn), MEMF_ANY | MEMF_CLEAR);
    if (!conn) {
        log_printf(LOG_ERROR, "worker: out of memory for BepConn");
        goto done;
    }
    if (!bep_conn_init(conn)) {
        log_printf(LOG_ERROR, "worker: out of memory for BepConn buffers");
        goto done;
    }
    conn->t.ctx   = ssl;
    conn->t.read  = w_read;
    conn->t.write = w_write;

    have_ourid   = device_id_from_cert_file(st->cert_path, ourid);
    have_our_raw = have_ourid && device_id_to_raw(ourid, our_raw);

    {
        BepHello         local, remote;
        BepClusterConfig cc;
        unsigned char    peer_raw[32];
        int              have_peer_raw;

        memset(&local, 0, sizeof(local));
        scopy(local.device_name, st->device_name, sizeof(local.device_name));
        scopy(local.client_name, AMISYNC_CLIENT, sizeof(local.client_name));
        scopy(local.client_version, AMISYNC_VERSION,
              sizeof(local.client_version));

        /* Announce our configured folders, listing us + this peer as devices. */
        have_peer_raw = device_id_to_raw(st->peer_actual_id, peer_raw);
        cc_mask0 = cc_eligible_mask(st->cfg, st->folders);
        if (st->cfg && have_our_raw) {
            build_cluster_config(st->cfg, st->folders, our_raw,
                                 have_peer_raw ? peer_raw : NULL,
                                 st->device_name, &cc, cc_mask0);
        } else {
            memset(&cc, 0, sizeof(cc));   /* fall back to an empty config */
        }

        if (!bep_handshake(conn, &local, &remote, &cc)) {
            log_printf(LOG_WARN, "worker: BEP handshake failed");
            goto done;
        }
        log_printf(LOG_INFO, "worker: connected; peer is \"%s\" (%s %s), %d folder(s) shared",
                   remote.device_name, remote.client_name, remote.client_version,
                   cc.num_folders);

        /* Publish the peer's identity for STATUS, before raising 'connected'.
         * Both remote fields are NUL-terminated BEP_NAME_MAX buffers, so the
         * pair always fits peer_client (2 * BEP_NAME_MAX). */
        scopy(st->peer_name, remote.device_name, sizeof(st->peer_name));
        sprintf(st->peer_client, "%s %s",
                remote.client_name, remote.client_version);
    }

    st->connected = 1;

    /* An inbound connection publishes itself in the peer's config slot: the
     * peer's dialer stands down while we live here, and STATUS counts this
     * connection. Cleared (under Forbid, matching every reader) in 'done'
     * BEFORE the startup is replied - the listener frees it in its task. */
    if (st->mode != WORKER_DIAL && st->peer_cfg) {
        Forbid();
        st->peer_cfg->inbound_st = st;
        Permit();
    }

    /* Set up the transport state and run the serve/fetch loop. The Sync block is
     * large (fixed buffers), so it lives on the heap, not the worker stack. The
     * shared index it reads/writes is owned by main (st->folders). */
    S = AllocVec(sizeof(Sync), MEMF_ANY | MEMF_CLEAR);
    if (!S) {
        log_printf(LOG_ERROR, "worker: out of memory for sync state");
        goto done;
    }
    S->conn          = conn;
    S->ssl           = ssl;
    S->st            = st;
    S->sock          = sock;
    S->cfg           = st->cfg;
    S->folders       = st->folders;
    S->cc_mask       = cc_mask0;   /* what the handshake CC actually listed */
    S->claim_fidx    = -1;         /* MEMF_CLEAR would read as folder 0 */
    sync_init(&S->model);

    /* Folder-set change detection baseline + the raw keys a mid-session
     * ClusterConfig rebuild needs (cheap re-derivations, done once). */
    if (S->cfg) {
        int i;
        S->cfg_gen = S->cfg->config_gen;
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++)
            S->fgen[i] = S->cfg->folders[i].gen;
    }
    {
        int i;
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++)
            S->need_gen[i] = foldstate_need_gen(&S->folders[i]);
    }
    S->have_peer_raw = device_id_to_raw(st->peer_actual_id, S->peer_raw);

    /* Both users of our identity, from the single derivation above: the raw
     * key a mid-session ClusterConfig rebuild needs, and the conflict-copy tag
     * - our device ID's first 7 chars (the canonical form's first dash-group),
     * matching Syncthing's naming. */
    S->have_our_raw = have_our_raw;
    if (have_our_raw)
        memcpy(S->our_raw, our_raw, 32);
    memcpy(S->ctag, have_ourid ? ourid : "AMIGA00", 7);
    S->ctag[7] = '\0';

    /* Load each folder's ignores up front: they gate what we accept on receive
     * and what we serve. The cursors start at 0, so the first announce pass sends
     * the full current index (whatever the scanner has populated so far). */
    refresh_ignores(S);

    /* Register for scanner wake-ups while we are in the connected loop, so a
     * scan that advances a folder's sequence makes us announce promptly instead
     * of waiting for the idle tick. */
    wreg_add();
    rc = worker_sync(S);
    wreg_remove();

done:
    if (st->peer_cfg)                  /* what this session leaves owing */
        st->peer_cfg->resyncing = st->connected ? st->resync : 0;
    if (st->peer_cfg && st->peer_cfg->inbound_st == (void *)st) {
        Forbid();
        st->peer_cfg->inbound_st = NULL;
        Permit();
    }
    if (S) {
        int i;
        if (S->dl.active)                       /* abandon a partial download */
            folder_recv_abort(S->dl.fh, S->dl.tmp);
        /* Unconditionally, and before the Sync block is freed: a claim left
         * behind outlives this process and would pin the file - no other
         * worker could ever fetch it - until the daemon restarts. */
        release_claim(S);
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++) {
            spill_close(&S->spill[i]);   /* session-scoped, see spill.h */
            spill_close(&S->spill_del[i]);
            /* Same reasoning as the claim: a want set left behind outlives
             * this worker and would hold another one's deletions for the life
             * of the daemon, which is how a deleted drawer comes back. */
            foldstate_want_release(&S->folders[i], S);
        }
        if (S->blockbuf)                        /* serve-side scratch, if grown */
            FreeVec(S->blockbuf);
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++)
            if (S->ignores[i])
                FreeVec(S->ignores[i]);
        FreeVec(S);
    }
    if (conn)                      { bep_conn_free(conn); FreeVec(conn); }
    if (ssl)                       ssl_free(ssl);
    if (ctx)                       ssl_ctx_free(ctx);
    if (sock != NET_INVALID_SOCKET) net_close(sock);
    if (ssl_up)                    ssl_subtask_cleanup();
    return rc;
}

void worker_entry(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    WorkerStartup  *st;

    /* Block until main delivers our parameters. */
    WaitPort(&me->pr_MsgPort);
    st = (WorkerStartup *)GetMsg(&me->pr_MsgPort);
    if (!st)
        return;

    st->result = worker_run(st);

    /* Final act: hand the message back so main knows we are done. After this
     * we must not touch st (main owns it again) - just fall off and exit. */
    ReplyMsg((struct Message *)st);
}
