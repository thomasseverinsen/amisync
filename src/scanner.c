/* scanner.c - the dedicated folder scan/hash process for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See scanner.h. The scanner runs in its own process: it opens AmiSSL for
 * SHA-256, then on each idle tick walks every folder and re-hashes only files
 * whose size/mtime changed, recording the block hashes and bumping the sequence
 * in the shared FolderState. It is the main writer but NOT the only one - a
 * worker also writes on receive (a pulled or peer-deleted file) - so every
 * access takes the folder semaphore. The locking discipline is the one rule that
 * matters: hold the lock only across the pure memory update, never across
 * folder_hash() or any disk I/O. Because the scanner re-derives a file's version
 * from whatever record it finds under the lock, a value a worker wrote between
 * the scanner's "is it changed?" check and its commit is carried forward, not
 * lost.
 */

#include <string.h>

#include <exec/memory.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <dos/dos.h>
#include <dos/dostags.h>
#include <dos/notify.h>

#include "scanner.h"
#include "foldstate.h"
#include "index_store.h"
#include "syncmodel.h"     /* sync_bump_version */
#include "folder.h"
#include "ignore.h"
#include "ssl.h"
#include "worker.h"        /* WORKER_SIG_STOP, WORKER_SIG_RESCAN */
#include "wreg.h"
#include "log.h"

#define SCANNER_INTERVAL   60       /* seconds between rescans            */
#define SCANNER_STACK   131072      /* deep dir recursion + AmiSSL SHA256 */
#define SCANNER_PATH_MAX   256      /* a full native path, everywhere here */
#define SCANNER_GC_EVERY   30       /* sweep orphaned temps every N passes (~30 min) */
#define SCANNER_TEMP_AGE  (7*86400) /* a *.amitmp idle this long (s) is abandoned    */

/* Directories watched across all folders (roots + subdirectories). A Watch is
 * ~300 bytes, so even the full budget costs under 80 KB; the real cost is the
 * filesystem handler checking its notify list on every directory change, which
 * stays cheap at this scale. Trees with more subdirectories than this simply
 * fall back to the periodic scan for the excess (best-effort as ever). 256 was
 * raised from 64 when the per-folder entry cap went away and deep trees became
 * routine. */
#define NOTIFY_MAX_WATCH  256
#define NOTIFY_QUIET_SECS   2       /* settle time after a change burst       */

struct ScannerHandle {
    struct MsgPort *port;
    struct Process *proc;      /* NULL once the scanner has replied and exited */
    ScannerStartup *startup;
    int             exited;    /* the startup message has been taken off port */
};

/* Null h->proc if the scanner already replied; caller MUST hold Forbid().
 * scanner_entry's Process is freed just after ReplyMsg, and scanner_run does
 * return on its own (ssl_subtask_init or the scratch AllocVec failing), so a
 * reply waiting on the port means signalling h->proc would hit freed memory.
 * The message is h->startup, freed by scanner_stop; only taken off here. */
static void drain_scanner_locked(ScannerHandle *h)
{
    if (!h->exited && GetMsg(h->port)) {
        h->exited = 1;
        h->proc   = NULL;
    }
}

/* Length-bounded copy that always NUL-terminates (mirrors worker.c's helper;
 * avoids strncpy's truncation warning on the fixed-size index fields). */
static void scopy(char *dst, const char *src, int cap)
{
    int n = (int)strlen(src);
    if (n > cap - 1)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Heap scratch for one scan pass (too big for the process stack): the ignore
 * set, the block-hash buffer folder_hash() fills, and the subdirectory names
 * collected for the change-notification watch set. There is no directory
 * listing: the walk drives a callback per entry and the deletion sweep works
 * off the index's per-record 'seen' marks, so a folder of any size scans in
 * constant scratch. Both the content_hash and the per-block hashes are kept in
 * the index (the latter so a worker can announce the file without re-reading
 * it); foldstate_upsert copies bh into the record's own owned array, so this
 * scratch is reused freely next file. */
typedef struct {
    IgnoreSet     ignores;
    unsigned char bh[FOLDER_MAX_BLOCKS][BEP_HASH_LEN];
    int           ndirs;         /* subdirs collected this pass (for notify)  */
    char          dirs[NOTIFY_MAX_WATCH][BEP_PATH_MAX];
} ScanScratch;

/* ---- instant change detection (dos.library file notification) --------
 *
 * The scanner watches each folder root and every known subdirectory with
 * StartNotify(NRF_SEND_MESSAGE): the filesystem posts a message when a
 * watched directory's entries change (create/delete/rename - which covers
 * most saves, since editors typically write via temp-and-rename). The nap
 * loop drains the port each second and, after a short quiet period, scans
 * right away instead of waiting out the rest of the 60 s interval. In-place
 * rewrites of existing files may not touch any watched directory, so the
 * periodic scan remains the backstop, not a casualty.
 *
 * Everything is best-effort: no port, no memory, or a handler without
 * notification support (StartNotify fails) just leaves that folder on the
 * periodic scan. NRF_WAIT_REPLY caps each watch at one outstanding message,
 * so a burst of changes cannot flood the port while a scan is running. */

typedef struct Watch {
    struct Watch        *next;
    struct NotifyRequest nr;
    int                  folder_idx;
    int                  seen;       /* liveness mark for the reconcile sweep */
    char                 path[SCANNER_PATH_MAX];  /* nr_Name points at this               */
} Watch;

typedef struct {
    struct MsgPort *port;                     /* NULL = feature off        */
    Watch          *watches;
    int             count;
    unsigned char   off[CONFIG_MAX_FOLDERS];  /* root watch failed: give up */
    unsigned char   on [CONFIG_MAX_FOLDERS];  /* "active" logged once       */
} NotifyState;

static void notify_open(NotifyState *ns)
{
    memset(ns, 0, sizeof(*ns));
    ns->port = CreateMsgPort();    /* NULL tolerated: periodic scan only */
}

/* Reply every queued change notification; returns 1 if any arrived. */
static int notify_drain(NotifyState *ns)
{
    struct Message *m;
    int any = 0;
    if (!ns->port)
        return 0;
    while ((m = GetMsg(ns->port)) != NULL) {
        ReplyMsg(m);
        any = 1;
    }
    return any;
}

static Watch *notify_find(NotifyState *ns, int fidx, const char *path)
{
    Watch *w;
    for (w = ns->watches; w; w = w->next)
        if (w->folder_idx == fidx && strcmp(w->path, path) == 0)
            return w;
    return NULL;
}

/* Watch directory 'path' for entry changes. Returns 1 on success, 0 when the
 * filesystem handler does not support notification (a permanent condition for
 * this folder), or -1 when the global watch budget is full (transient - slots
 * may free up as other folders shrink). */
static int notify_add(NotifyState *ns, int fidx, const char *path)
{
    Watch *w;

    if (ns->count >= NOTIFY_MAX_WATCH)
        return -1;
    w = AllocVec(sizeof(*w), MEMF_PUBLIC | MEMF_CLEAR);
    if (!w)
        return -1;                         /* transient (out of memory) */
    w->folder_idx = fidx;
    scopy(w->path, path, sizeof(w->path));
    w->nr.nr_Name  = w->path;
    w->nr.nr_Flags = NRF_SEND_MESSAGE | NRF_WAIT_REPLY;
    w->nr.nr_stuff.nr_Msg.nr_Port = ns->port;
    if (!StartNotify(&w->nr)) {
        FreeVec(w);
        return 0;
    }
    w->seen = 1;
    w->next = ns->watches;
    ns->watches = w;
    ns->count++;
    return 1;
}

static void notify_remove(NotifyState *ns, Watch *dead)
{
    Watch **pp;
    for (pp = &ns->watches; *pp; pp = &(*pp)->next)
        if (*pp == dead) {
            *pp = dead->next;
            break;
        }
    EndNotify(&dead->nr);   /* also removes its queued messages (V37+) */
    FreeVec(dead);
    ns->count--;
}

/* Bring folder 'fidx's watch set in line with what the scan just walked:
 * the root plus every subdirectory ('dirs': relative names collected during
 * the walk, capped at NOTIFY_MAX_WATCH - the global watch budget, so the cap
 * never costs a watch we could otherwise afford). Quiet on failure (the
 * periodic scan still covers everything); a failing ROOT watch marks the
 * folder as notification-unsupported so we stop retrying every pass. */
static void notify_reconcile(NotifyState *ns, int fidx, const ConfigFolder *cf,
                             const char (*dirs)[BEP_PATH_MAX], int ndirs)
{
    Watch *w, *next;
    char   path[SCANNER_PATH_MAX];
    int    i;

    if (!ns->port || ns->off[fidx])
        return;

    for (w = ns->watches; w; w = w->next)
        if (w->folder_idx == fidx)
            w->seen = 0;

    if ((w = notify_find(ns, fidx, cf->path)) != NULL) {
        w->seen = 1;
    } else {
        int rc = notify_add(ns, fidx, cf->path);
        if (rc < 0)
            return;                    /* watch budget full: retry a later pass */
        if (rc == 0) {                 /* handler has no notification: give up */
            ns->off[fidx] = 1;
            log_printf(LOG_INFO, "scanner: no change notification for '%s'; "
                       "relying on the periodic scan", cf->id);
            for (w = ns->watches; w; w = next) {
                next = w->next;
                if (w->folder_idx == fidx)
                    notify_remove(ns, w);
            }
            return;
        }
    }

    for (i = 0; i < ndirs; i++) {
        scopy(path, cf->path, sizeof(path));
        if (!AddPart(path, (STRPTR)dirs[i], sizeof(path)))
            continue;
        if ((w = notify_find(ns, fidx, path)) != NULL)
            w->seen = 1;
        else
            notify_add(ns, fidx, path);    /* best-effort; cap or handler */
    }

    for (w = ns->watches; w; w = next) {   /* dirs deleted since last pass */
        next = w->next;
        if (w->folder_idx == fidx && !w->seen)
            notify_remove(ns, w);
    }

    if (!ns->on[fidx]) {
        ns->on[fidx] = 1;
        log_printf(LOG_INFO, "scanner: change notification active for '%s' "
                   "(%d watch(es) total)", cf->id, ns->count);
    }
}

/* Drop every watch belonging to folder 'fidx'. Only notify_reconcile prunes
 * watches, and it runs from a scan pass - which a removed folder never gets -
 * so without this its root and subdirectory watches outlive the folder: the
 * filesystem keeps posting changes from a drawer we no longer sync, and each
 * one wakes the scanner for a full pass over everything that IS synced (edit a
 * file in an un-synced drawer and it rescans every few seconds, forever). The
 * watches also stay charged against the global budget. Clearing the two
 * latches leaves a later re-add to start over cleanly. */
static void notify_drop_folder(NotifyState *ns, int fidx)
{
    Watch *w, *next;

    for (w = ns->watches; w; w = next) {
        next = w->next;
        if (w->folder_idx == fidx)
            notify_remove(ns, w);
    }
    ns->off[fidx] = 0;
    ns->on[fidx]  = 0;
}

static void notify_close(NotifyState *ns)
{
    Watch *w, *next;
    struct Message *m;

    for (w = ns->watches; w; w = next) {
        next = w->next;
        EndNotify(&w->nr);
        FreeVec(w);
    }
    ns->watches = NULL;
    if (ns->port) {
        while ((m = GetMsg(ns->port)) != NULL)
            ReplyMsg(m);
        DeleteMsgPort(ns->port);
        ns->port = NULL;
    }
}

/* True if 'name' (size/mtime) differs from our stored live record, i.e. it needs
 * (re)hashing. A missing or tombstoned record counts as changed - and so does a
 * record with no stored block hashes: a live file must always announce at least
 * one block (Syncthing drops the connection over an empty block list), so a
 * blockless record (a pre-fix empty file, or a block array lost to an
 * allocation failure) is re-hashed to heal it. */
static int rec_changed(FolderState *fs, const char *name,
                       int64_t size, int64_t modified_s)
{
    FolderRec *have = foldstate_find(fs, name);
    int       total = 0;
    if (!have || have->deleted)
        return 1;
    /* An INVALID record is one we told peers we are not offering - an ignored
     * file, or one we cannot store. Seeing the file in the walk again means
     * that reason is gone (the rule was relaxed), so it must be rebuilt and
     * announced live; without this the file would stay hidden from every peer
     * for as long as its size and mtime happened not to change. */
    if (have->invalid)
        return 1;
    if (have->size != size || have->modified_s != modified_s)
        return 1;
    foldstate_blocks(fs, name, NULL, 0, &total);
    return total == 0;
}

/* Build the index record for a changed file and commit it under the lock,
 * carrying the prior version forward so a re-add dominates a peer's tombstone
 * (mirrors the worker's rescan path). 'content_hash' and the 'nblocks' block
 * hashes come from a folder_hash() done OUTSIDE the lock by the caller; upsert
 * copies the block hashes into the record's own owned array. */
static void commit_file(FolderState *fs, const FolderEntry *e,
                        const unsigned char content_hash[BEP_HASH_LEN],
                        const unsigned char (*hashes)[BEP_HASH_LEN], int nblocks)
{
    SyncMeta  m;
    FolderRec *have;
    BepVector  prev;

    memset(&m, 0, sizeof(m));
    scopy(m.name, e->name, sizeof(m.name));
    m.type             = BEP_FILE_FILE;
    m.size             = e->size;
    m.permissions      = 0644;
    m.modified_s       = e->modified_s;
    m.modified_by      = fs->short_id;    /* a local change: ours */
    m.block_size       = folder_block_size(e->size);
    memcpy(m.content_hash, content_hash, BEP_HASH_LEN);
    m.has_content_hash = 1;

    foldstate_lock(fs);
    have = foldstate_find(fs, e->name);
    sync_bump_version(&m.version, foldstate_version(fs, have, &prev),
                      fs->short_id, folder_version_stamp(e->modified_s));
    m.sequence = foldstate_next_seq(fs);
    if (!foldstate_upsert(fs, &m, hashes, nblocks))
        log_printf(LOG_WARN, "scanner: index full for '%s' in folder '%s'",
                   e->name, fs->folder_id);
    foldstate_mark_seen(fs, e->name);
    foldstate_unlock(fs);
}

/* Record a directory we found (idempotent: skip if already live). */
static void commit_dir(FolderState *fs, const FolderEntry *e)
{
    SyncMeta  m;
    FolderRec *have;
    BepVector  prev;

    foldstate_lock(fs);
    have = foldstate_find(fs, e->name);
    if (have && !have->deleted) {
        foldstate_mark_seen(fs, e->name);
        foldstate_unlock(fs);
        return;
    }
    memset(&m, 0, sizeof(m));
    scopy(m.name, e->name, sizeof(m.name));
    m.type        = BEP_FILE_DIRECTORY;
    m.permissions = 0755;
    m.modified_s  = e->modified_s;
    m.modified_by = fs->short_id;         /* a local change: ours */
    sync_bump_version(&m.version, foldstate_version(fs, have, &prev),
                      fs->short_id, folder_version_stamp(e->modified_s));
    m.sequence = foldstate_next_seq(fs);
    foldstate_upsert(fs, &m, NULL, 0);
    foldstate_mark_seen(fs, e->name);
    foldstate_unlock(fs);
}

/* Tombstone live records whose files have vanished from disk: the mark-and-
 * sweep counterpart of the walk, run only after a COMPLETE walk has set the
 * 'seen' mark on every record with a file (or directory) behind it - a live,
 * valid record still unmarked has nothing on disk. Tombstoning goes through
 * foldstate_upsert(NULL,0) so the file's stored block hashes are freed. The
 * whole pass is pure memory, so the lock is held throughout (folder_now() is
 * read once up front, outside any I/O). Tombstones replace records in place, so
 * num_files and slot order stay stable across the loop. */
static void sweep_deletions(FolderState *fs, int64_t before,
                            const IgnoreSet *ign)
{
    int64_t when = folder_now();
    int     i, tombstoned = 0, spared = 0, hidden = 0;

    /* Pure-memory pass under the lock - NO logging here: log_printf does file
     * I/O (fputs/fflush), and holding the folder semaphore across it would
     * serialize every worker and the scanner on the log during a large delete
     * sweep. Tally under the lock, report once after releasing it. */
    foldstate_lock(fs);
    for (i = 0; i < fs->num_files; i++) {
        FolderRec *t = &fs->files[i];
        SyncMeta  tomb;
        BepVector prev;
        const char *tname = foldstate_name(fs, t);

        /* Invalid records are deliberate "we knowingly don't store this"
         * announcements (unfittable name, too large - see worker.c
         * announce_unstorable); no disk file backs them, so the missing-file
         * sweep must never turn them into deletions - that would propagate a
         * DELETE of the peer's perfectly good file. */
        if (t->deleted || t->invalid || fs->seen[i])
            continue;

        /* An IGNORED name is unmarked for a completely different reason: the
         * walk was told to skip it, not told it was gone. Tombstoning it
         * announces a deletion of a file that is sitting right there on disk -
         * so adding a rule to STOP syncing some files instead deletes them
         * from every peer, silently, while the local copies stay put. Measured
         * before this check existed: one rule covering ~100 files took the
         * peer from 101 files to 1, with all 102 still on the Amiga.
         *
         * The record is left exactly as it is. Whether an ignored file should
         * go on being announced at all is a separate question; quietly
         * destroying the peer's copy is not the way to raise it. */
        if (ign && ignore_match(ign, tname)) {
            /* A file we have stopped syncing. Leaving the record LIVE would go
             * on telling peers we hold this version - a claim the walk no
             * longer checks, so it rots: edit the file locally and nobody
             * hears, and the stale record still gets a vote in a version
             * comparison it can win. Silence does not fix that either, because
             * nothing in BEP retracts what was already said; the peer simply
             * keeps believing the last thing it heard.
             *
             * So say the true thing instead: INVALID, the same flag used for a
             * file we knowingly cannot store. It means "I have a record for
             * this name and I am not offering it", and the sweep above skips
             * invalid records from then on, so it is said once rather than
             * every pass.
             *
             * MEASURED, and not what was expected: Syncthing 2.1.3 does not
             * act on a remote's invalid flag. It still lists this device as a
             * source for the file and still reports us 100% complete, with or
             * without a version bump to make the record look new. So the value
             * here is local and honest rather than remote: the record stops
             * claiming to offer something the walk no longer checks, and its
             * block hashes are freed (21 KB for an 85 MB file). Peers keep
             * believing what they last heard, because BEP has no way to
             * retract it.
             *
             * Directories are left alone: they carry no content, so a live
             * record for one claims nothing that can rot.
             *
             * The way back is rec_changed(), which treats an invalid record as
             * changed - relax the rule and the walk rebuilds it live. */
            if (t->type == BEP_FILE_FILE && !t->invalid) {
                SyncMeta inv;

                foldstate_meta(fs, t, &inv);
                inv.invalid  = 1;
                inv.sequence = foldstate_next_seq(fs);
                foldstate_upsert(fs, &inv, NULL, 0);   /* drops block hashes */
                hidden++;
            } else {
                spared++;
            }
            continue;
        }

        /* Never tombstone a record that appeared AFTER this pass started its
         * walk ('before' is the sequence high-water captured before it). A
         * worker receiving a file mid-scan writes it to disk and upserts it
         * into the index; the walk may already have passed that directory, so
         * the record is unmarked and would look vanished - we would announce a
         * DELETE of the file the peer just sent us, and re-add it on the next
         * pass. During the initial sync of a large folder that fires
         * constantly. */
        if (t->sequence > before)
            continue;

        memset(&tomb, 0, sizeof(tomb));
        scopy(tomb.name, tname, sizeof(tomb.name));
        tomb.type        = t->type;
        tomb.deleted     = 1;
        tomb.permissions = t->permissions;
        tomb.modified_s  = when;
        tomb.modified_by = fs->short_id;  /* the deletion is our change */
        sync_bump_version(&tomb.version, foldstate_version(fs, t, &prev),
                          fs->short_id,
                          (uint64_t)when);
        tomb.sequence = foldstate_next_seq(fs);
        foldstate_upsert(fs, &tomb, NULL, 0);   /* replace in place; frees blocks */
        tombstoned++;
    }
    foldstate_unlock(fs);

    if (tombstoned)
        log_printf(LOG_INFO, "scanner: tombstoned %d vanished file(s) in "
                   "folder '%s'", tombstoned, fs->folder_id);
    if (hidden)
        log_printf(LOG_INFO, "scanner: %d newly ignored file(s) in '%s'; peers "
                   "told we no longer offer them (nothing deleted)",
                   hidden, fs->folder_id);
    if (spared)
        log_printf(LOG_DEBUG, "scanner: %d ignored record(s) in '%s' left "
                   "alone", spared, fs->folder_id);
}

/* Once-per-run latch for per-file scan warnings: a persistently unreadable
 * file would otherwise warn every pass, sixty seconds apart, forever (same
 * shape as folder.c's warn_once; only the scanner process calls this). */
#define SCAN_WARN_SLOTS 16
static ULONG scan_warned[SCAN_WARN_SLOTS];
static int   scan_warned_n;

static int scan_warn_once(const char *folder, const char *name)
{
    ULONG       h = 5381;
    const char *p;
    int         i;

    for (p = folder; *p; p++)
        h = h * 33 + (unsigned char)*p;
    for (p = name; *p; p++)
        h = h * 33 + (unsigned char)*p;
    if (h == 0)
        h = 1;
    for (i = 0; i < scan_warned_n && i < SCAN_WARN_SLOTS; i++)
        if (scan_warned[i] == h)
            return 0;
    if (scan_warned_n < SCAN_WARN_SLOTS)
        scan_warned[scan_warned_n++] = h;
    return 1;
}

/* Context threaded through folder_walk to scan_entry, one folder at a time. */
typedef struct {
    const ConfigFolder *cf;
    FolderState        *fs;
    ScanScratch        *sc;
} ScanCtx;

/* Per-entry walk callback: what the old per-listing loop did, plus marking the
 * entry's record 'seen' so the sweep afterwards knows its file is still on
 * disk. Returns 0 (abort the walk) only on a stop signal. */
static int scan_entry(void *vctx, const FolderEntry *e)
{
    ScanCtx      *c  = (ScanCtx *)vctx;
    FolderState  *fs = c->fs;
    unsigned char content_hash[BEP_HASH_LEN];
    int           nb, rc, changed;

    /* Stay responsive to shutdown: a big folder is many slow hashes, and the
     * daemon's QUIT/CTRL-C blocks until we return, so bail between files.
     * Aborting mid-walk also suppresses the deletion sweep (scan_folder). */
    if (SetSignal(0, 0) & WORKER_SIG_STOP)
        return 0;

    /* The folder can be un-configured (ARexx REMOVEFOLDER, the window's
     * Remove...) while this pass runs - 'removed' is only checked when the
     * pass PICKS a folder up, and a big tree is many slow hashes after that.
     * Bail here so a re-add of the same id, which re-keys the shared index,
     * waits at most one file rather than racing the walk. Aborting also
     * suppresses the deletion sweep (scan_folder), which is what we want:
     * nothing about this folder should be concluded now. */
    if (c->cf->removed)
        return 0;

    if (e->is_dir) {
        commit_dir(fs, e);                 /* also marks the record seen */
        if (c->sc->ndirs < NOTIFY_MAX_WATCH) {
            scopy(c->sc->dirs[c->sc->ndirs], e->name, sizeof(c->sc->dirs[0]));
            c->sc->ndirs++;
        }
        return 1;
    }

    /* A receive-only folder is a MIRROR: what the peer holds is the truth and
     * our local copy is not. Recording a local edit here would bump our
     * version over the peer's and classify would then answer "ours is newer,
     * nothing to do" for ever - the file silently and permanently different,
     * with the folder reporting itself up to date. Worse, that record would
     * carry our own counter, and announcing it would push our edit onto the
     * peer, which is the one thing this mode exists to prevent.
     *
     * So local state never enters the index here. An edited file has its
     * record FORGOTTEN rather than updated, which makes the peer's next Index
     * classify it as one we lack, and the peer's copy replaces the edit - the
     * mirror repairs itself. A file with no record at all is left entirely
     * alone: purely local additions stay local, exactly as this mode promises.
     *
     * This is what keeps announcing safe (see announce_folder): everything
     * left in the index is a record we hold exactly as a peer produced it, so
     * it can be announced without ever claiming we changed anything. */
    if (c->cf->mode == FOLDER_RECEIVEONLY) {
        int forgot = 0;

        foldstate_lock(fs);
        if (!foldstate_find(fs, e->name)) {
            /* not ours to track */
        } else if (rec_changed(fs, e->name, e->size, e->modified_s)) {
            forgot = foldstate_forget(fs, e->name);
        } else {
            foldstate_mark_seen(fs, e->name);
        }
        foldstate_unlock(fs);
        if (forgot) {
            /* We now want a file we can no longer ask for: this peer's Index
             * was consumed when it arrived. Tell the workers so one of them
             * fetches the peer's copy back. */
            foldstate_need_changed(fs);
            log_printf(LOG_WARN, "scanner: '%s' was edited in receive-only "
                       "'%s'; the peer's copy will replace it and your version "
                       "will be kept in .stversions", e->name, c->cf->id);
        }
        return 1;
    }

    foldstate_lock(fs);                    /* cheap read to decide if we hash */
    changed = rec_changed(fs, e->name, e->size, e->modified_s);
    if (!changed)
        foldstate_mark_seen(fs, e->name);
    foldstate_unlock(fs);
    if (!changed)
        return 1;

    rc = folder_hash(c->cf->path, e->name, e->size, c->sc->bh,
                     FOLDER_MAX_BLOCKS, &nb,
                     content_hash);              /* the slow part, OUTSIDE lock */
    if (rc != 1) {
        /* A hash that failed to READ has two very different causes, and the
         * walk cannot tell them apart on its own: the file is held open by
         * something else (keep it - tombstoning a file that is still there
         * announces its deletion to every peer), or it was deleted between the
         * directory listing and our attempt to open it. The second used to be
         * swallowed: the record was marked seen, the sweep spared it, and the
         * deletion went unannounced until some later scan happened to catch
         * the file already gone - which is exactly what a peer waiting on that
         * tombstone never hears. Ask the filesystem which case this is. */
        if (rc == 0 && !folder_exists(c->cf->path, e->name)) {
            log_printf(LOG_INFO, "scanner: '%s' vanished during the scan of "
                       "'%s'; recording the deletion", e->name, c->cf->id);
            return 1;                      /* NOT marked seen: the sweep gets it */
        }
        if (rc < 0)
            log_printf(LOG_WARN, "scanner: skipping '%s' (too large to sync)",
                       e->name);
        else if (scan_warn_once(c->cf->path, e->name))
            /* A read failure used to be SILENT - and a file that never
             * hashes never syncs (a new one is never indexed; a changed one
             * keeps announcing its old content; a blockless record is never
             * healed and so never announced at all). Say it, once. */
            log_printf(LOG_WARN, "scanner: cannot read '%s' in '%s'; it "
                       "will not sync until it is readable",
                       e->name, c->cf->id);
        /* Still on disk even though we could not (re)hash it; keep any record
         * it has out of the deletion sweep. */
        foldstate_lock(fs);
        foldstate_mark_seen(fs, e->name);
        foldstate_unlock(fs);
        return 1;
    }
    commit_file(fs, e, content_hash, c->sc->bh, nb);   /* also marks seen */
    return 1;
}

/* One scan pass over one folder: clear the index's 'seen' marks, walk the tree
 * (each entry committed - and marked seen - by scan_entry, with hashing OUTSIDE
 * the lock), then tombstone the live records the walk never saw. Returns 1 if
 * it advanced the folder's sequence (i.e. there is something new for workers to
 * announce), else 0. Also reconciles the folder's change-notification watches
 * against the subdirectories the walk collected ('fidx' indexes ns). */
static int scan_folder(const ConfigFolder *cf, FolderState *fs, ScanScratch *sc,
                       NotifyState *ns, int fidx)
{
    ScanCtx ctx;
    int64_t before;
    int     rc, advanced;

    foldstate_lock(fs);
    before = fs->sequence;
    foldstate_clear_seen(fs);
    foldstate_unlock(fs);

    folder_load_ignores(cf->path, &sc->ignores);

    sc->ndirs = 0;
    ctx.cf = cf;
    ctx.fs = fs;
    ctx.sc = sc;
    rc = folder_walk(cf->path, &sc->ignores, scan_entry, &ctx);
    if (rc < 0)
        return 0;                          /* folder vanished: leave it alone */

    /* Reconcile nothing from a PARTIAL walk (a stop signal, or the folder
     * being un-configured mid-pass): the subdirectories it never reached are
     * missing from sc->dirs, so the watch sweep would drop live watches only
     * to re-add them next pass - and the deletion sweep would tombstone files
     * that are still on disk, announcing spurious DELETEs to peers. */
    if (rc > 0) {
        notify_reconcile(ns, fidx, cf, sc->dirs, sc->ndirs);
        if (cf->mode == FOLDER_RECEIVEONLY) {
            /* A mirror does not get to delete: a file missing here is one to
             * fetch again, not a deletion to record. A tombstone would carry
             * our own counter, so announcing it would propagate a local
             * deletion to the peer - and even unannounced it would mask the
             * peer's copy here permanently. Forget the record instead and the
             * next Index brings the file back. */
            int gone;
            foldstate_lock(fs);
            gone = foldstate_forget_unseen(fs, before);
            foldstate_unlock(fs);
            if (gone) {
                foldstate_need_changed(fs);      /* same as above: re-ask */
                log_printf(LOG_INFO, "scanner: %d file(s) missing from "
                           "receive-only '%s'; fetching them back",
                           gone, cf->id);
            }
        } else {
            sweep_deletions(fs, before, &sc->ignores);
        }
    }
    /* Persistence happens once per pass in scanner_run via save_all(). */

    foldstate_lock(fs);
    advanced = fs->sequence != before;
    foldstate_unlock(fs);
    return advanced;
}

/* Persist one folder's index if it has unsaved changes. Prunes aged
 * tombstones, then snapshots+encodes under the lock and writes the file outside
 * it (atomic temp+Rename). Save is debounced naturally - it runs once per scan
 * tick and skips clean folders. */
static void save_folder(const Config *cfg, FolderState *fs)
{
    char           path[SCANNER_PATH_MAX];
    unsigned char *buf;
    size_t         cap;
    int            len = 0;
    int64_t        cutoff = folder_now() - (int64_t)cfg->keep_deletes * 86400;

    foldstate_lock(fs);
    if (!fs->dirty) {
        foldstate_unlock(fs);
        return;
    }
    if (cfg->keep_deletes > 0)
        foldstate_prune_tombstones(fs, cutoff);
    cap = index_store_size(fs);
    buf = AllocVec((ULONG)cap, MEMF_ANY);
    if (buf) {
        len = index_store_encode(fs, buf, cap);
        if (len > 0)
            fs->dirty = 0;                 /* consistent snapshot taken */
    }
    foldstate_unlock(fs);

    if (!buf) {
        log_printf(LOG_WARN, "scanner: no memory to save index for '%s'",
                   fs->folder_id);
        return;
    }
    if (len == 0) {
        /* index_store_size under-estimated and the encode overflowed. The
         * folder stays dirty, so this is not data loss - but it IS permanent
         * and, until this branch existed, completely silent: nothing was
         * written, nothing was logged, and every tick from then on re-ran the
         * prune, the multi-megabyte AllocVec and the full encode with the
         * folder lock HELD, stalling every worker. Say it once per folder so
         * the estimate can be fixed rather than guessed at. */
        FreeVec(buf);
        if (scan_warn_once(fs->folder_id, "\1index-encode"))
            log_printf(LOG_ERROR, "scanner: cannot encode the index for '%s' "
                       "(size estimate too small) - it will not be saved; "
                       "please report this", fs->folder_id);
        return;
    }
    if (len > 0) {
        if (!folder_state_path(cfg->statedir, fs->folder_id, path, sizeof(path)) ||
            !folder_state_write(path, buf, len)) {
            log_printf(LOG_WARN, "scanner: failed to save index for '%s'",
                       fs->folder_id);
            foldstate_lock(fs);
            fs->dirty = 1;                 /* leave dirty so we retry next tick */
            foldstate_unlock(fs);
        }
    }
    FreeVec(buf);
}

static void save_all(const Config *cfg, FolderState *folders, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (!cfg->folders[i].removed)
            save_folder(cfg, &folders[i]);
}

/* Reclaim download temps abandoned by an interrupted transfer whose file/peer
 * never returned (a resumed temp stays fresh, so only truly idle ones go). */
static void gc_temps(const Config *cfg, int num_folders)
{
    int64_t cutoff = folder_now() - (int64_t)SCANNER_TEMP_AGE;
    int     i, n = 0;
    for (i = 0; i < num_folders; i++)
        if (!cfg->folders[i].removed)
            n += folder_gc_temps(cfg->folders[i].path, cutoff);
    if (n)
        log_printf(LOG_INFO, "scanner: reclaimed %d orphaned temp file(s)", n);
}

/* Sleep up to 'secs', waking early to stop (WORKER_SIG_STOP), to scan now
 * (WORKER_SIG_RESCAN, from an ARexx RESCAN), or when watched directories
 * changed and the burst has settled (NOTIFY_QUIET_SECS with no further
 * notifications). Returns 1 to keep running (scan again), 0 if a stop was
 * seen. A 1s poll granularity is plenty for a background scanner and avoids
 * pulling in timer.device. */
static int nap(NotifyState *ns, int secs)
{
    int i, dirty = 0, quiet = 0;

    for (i = 0; i < secs; i++) {
        ULONG sigs = SetSignal(0, 0);
        if (sigs & WORKER_SIG_STOP)
            return 0;
        if (sigs & WORKER_SIG_RESCAN) {
            SetSignal(0, WORKER_SIG_RESCAN);   /* consume; scan immediately */
            return 1;
        }
        if (notify_drain(ns)) {
            dirty = 1;                         /* changes landing: wait for */
            quiet = 0;                         /* the burst to settle       */
        } else if (dirty && ++quiet >= NOTIFY_QUIET_SECS) {
            return 1;                          /* settled: scan now         */
        }
        Delay(TICKS_PER_SECOND);
    }
    {
        ULONG sigs = SetSignal(0, WORKER_SIG_RESCAN);  /* clear pending rescan */
        return !(sigs & WORKER_SIG_STOP);
    }
}

static int scanner_run(ScannerStartup *st)
{
    ScanScratch *sc;
    NotifyState  ns;

    if (!ssl_subtask_init()) {                 /* per-process AmiSSL for SHA-256 */
        log_printf(LOG_ERROR, "scanner: ssl_subtask_init() failed");
        return 1;   /* init self-cleans on failure; must NOT call cleanup */
    }

    sc = AllocVec(sizeof(*sc), MEMF_ANY | MEMF_CLEAR);
    if (!sc) {
        log_printf(LOG_ERROR, "scanner: out of memory for scan scratch");
        ssl_subtask_cleanup();
        return 1;
    }

    notify_open(&ns);          /* best-effort; port may be NULL */

    /* The persisted index is loaded by the daemon (main) BEFORE workers start,
     * so the first scan below re-uses stored {size, mtime, content_hash, blocks}
     * and re-hashes only files that actually changed - the durable "hash once". */

    log_printf(LOG_INFO, "scanner: started (%d folder(s), every %ds)",
               st->num_folders, st->interval);

    gc_temps(st->cfg, st->num_folders);        /* clear last run's leftovers */

    {
        int pass = 0;
        for (;;) {
            /* Folder count and tombstones are read LIVE: folders added or
             * removed at runtime (ARexx ADDFOLDER/REMOVEFOLDER) join or
             * leave the rotation on the next pass - the slot array is
             * allocated at CONFIG_MAX_FOLDERS capacity by the daemon. */
            int i, advanced = 0, nf = st->cfg->num_folders;
            unsigned long mask;

            /* A pending targeted request turns THIS pass into one over just
             * the flagged folders (per-folder Rescan in the status window);
             * the skipped folders keep their notify/interval schedule - the
             * next tick pass is a full one again. */
            Forbid();
            mask = st->rescan_all ? 0 : st->rescan_mask;   /* all beats some */
            st->rescan_mask = 0;
            st->rescan_all  = 0;
            Permit();

            for (i = 0; i < nf; i++) {
                struct DateStamp ds;
                FolderState     *fs = &st->folders[i];
                int              gen0;
                if (st->cfg->folders[i].removed) {
                    notify_drop_folder(&ns, i);   /* un-configured: stop watching */
                    continue;
                }
                if (mask && !(mask & (1UL << i)))
                    continue;                     /* skipped, not gone: keep them */
                gen0 = st->cfg->folders[i].gen;
                advanced |= scan_folder(&st->cfg->folders[i], fs, sc, &ns, i);
                /* The folder may have gone - or gone and come back under a
                 * fresh, empty index ('gen' moves on every add) - while the
                 * pass ran. Stamping then would report an index this walk
                 * never covered as scanned, and mark a brand new folder
                 * eligible to announce before it holds anything. */
                if (st->cfg->folders[i].removed ||
                    st->cfg->folders[i].gen != gen0)
                    continue;
                DateStamp(&ds);              /* stamp "last scan" for STATUS */
                foldstate_lock(fs);
                fs->scan_day = ds.ds_Days;
                fs->scan_min = ds.ds_Minute;
                foldstate_unlock(fs);
            }

            /* Wake the connected workers so they announce the new records now,
             * rather than on their next idle tick. They each re-check their own
             * per-peer cursor, so a worker with nothing new just fast-paths. */
            if (advanced)
                wreg_signal(WORKER_SIG_RESCAN);

            save_all(st->cfg, st->folders, nf);               /* persist dirty */

            if (++pass % SCANNER_GC_EVERY == 0)   /* periodic orphaned-temp sweep */
                gc_temps(st->cfg, nf);

            if (!nap(&ns, st->interval))
                break;
        }
    }

    notify_close(&ns);
    /* Live count, like the pass loop: a folder added at runtime sits past
     * st->num_folders (the count at startup) and would miss this flush. */
    save_all(st->cfg, st->folders, st->cfg->num_folders);   /* final flush on stop */
    FreeVec(sc);
    ssl_subtask_cleanup();
    return 0;
}

void scanner_entry(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    ScannerStartup *st;

    WaitPort(&me->pr_MsgPort);
    st = (ScannerStartup *)GetMsg(&me->pr_MsgPort);
    if (!st)
        return;

    scanner_run(st);
    ReplyMsg((struct Message *)st);
}

ScannerHandle *scanner_start(const Config *cfg, FolderState *folders,
                             int num_folders)
{
    ScannerHandle  *h;
    ScannerStartup *st;
    struct Process *proc;

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
    st->folders             = folders;
    st->num_folders         = num_folders;
    st->interval            = SCANNER_INTERVAL;

    proc = CreateNewProcTags(NP_Entry,     (ULONG)scanner_entry,
                             NP_Name,      (ULONG)"amisync-scanner",
                             NP_StackSize,  SCANNER_STACK,
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

void scanner_rescan(ScannerHandle *h)
{
    if (!h)
        return;

    Forbid();
    drain_scanner_locked(h);
    if (h->proc) {
        h->startup->rescan_all = 1;   /* not narrowable by a targeted request */
        Signal(&h->proc->pr_Task, WORKER_SIG_RESCAN);
    }
    Permit();
}

void scanner_rescan_folder(ScannerHandle *h, int idx)
{
    if (!h || idx < 0 || idx >= CONFIG_MAX_FOLDERS)
        return;

    Forbid();
    drain_scanner_locked(h);
    if (h->proc) {
        h->startup->rescan_mask |= 1UL << idx;
        Signal(&h->proc->pr_Task, WORKER_SIG_RESCAN);
    }
    Permit();
}

void scanner_stop(ScannerHandle *h)
{
    if (!h)
        return;

    Forbid();
    drain_scanner_locked(h);
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
