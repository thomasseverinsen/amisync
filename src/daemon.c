/* daemon.c - main daemon lifecycle for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#include <string.h>

#include <dos/dos.h>
#include <dos/var.h>
#include <exec/ports.h>
#include <exec/memory.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/locale.h>
#include <libraries/locale.h>

#include "daemon.h"
#include "arexx.h"
#include "appicon.h"
#include "statuswin.h"
#include "ssl.h"
#include "peer.h"
#include "listener.h"
#include "disco.h"
#include "scanner.h"
#include "worker.h"        /* WORKER_SIG_RESCAN (wake workers on changes) */
#include "wreg.h"
#include "foldstate.h"
#include "index_store.h"
#include "folder.h"
#include "pathsafe.h"      /* text_field_safe (untrusted ids/labels/paths) */
#include "syncmodel.h"     /* sync_short_id_from_raw */
#include "device_id.h"
#include "version.h"      /* AMISYNC_DATE (the clock sanity floor) */
#include "log.h"

struct LocaleBase *LocaleBase;   /* proto/locale.h inlines resolve here */

/* What locale.library believes this machine's offset from UTC is, in seconds
 * east, or 'found' = 0 when it cannot say. loc_GMTOffset is documented in the
 * NDK as no more than "minutes from GMT" and is MINUTES WEST - the value the
 * Time Zone list in Locale prefs stores, where a zone behind GMT is positive.
 * Hence the negation.
 *
 * A machine whose Locale prefs were never saved reports 0, which is not a
 * claim that it sits on the meridian - it is the absence of an answer, and it
 * behaves exactly as every version before this did. 'tzoffset' in the config
 * overrides whatever is found here, which is also the escape hatch if a
 * machine's Locale is set to a zone its clock does not actually keep. */
static int locale_utc_offset_s(int *found)
{
    struct Locale *loc;
    int            secs = 0;

    *found = 0;
    LocaleBase = (struct LocaleBase *)OpenLibrary("locale.library", 38);
    if (!LocaleBase)
        return 0;
    loc = OpenLocale(NULL);
    if (loc) {
        secs   = -(int)loc->loc_GMTOffset * 60;   /* west-positive -> east */
        *found = 1;
        CloseLocale(loc);
    }
    CloseLibrary((struct Library *)LocaleBase);
    LocaleBase = NULL;
    return secs;
}

/* Fast RAM free, for the startup memory trace below. AvailMem is a walk of the
 * free list, so this is not free itself - it runs a handful of times at startup
 * and never in the event loop. */
static ULONG mem_free_fast(void)
{
    return AvailMem(MEMF_FAST);
}

/* Where the footprint actually goes. amisync measured 6.3 MB on an A4000 with
 * two folders and two peers, and apportioning that by subtraction produced a
 * TLS figure six times too large - which nearly retired the idea of shrinking
 * anything. So the daemon says it directly: one DEBUG line per startup stage,
 * each reporting what that stage cost and what is left.
 *
 * DEBUG rather than INFO because it is diagnostic, not news, and a running
 * daemon should not narrate its own allocator.
 *
 * READ THESE WITH CARE. Only the stages that allocate INLINE are attributable:
 * ssl_open and the folder indexes. The scanner and the peer workers are
 * subprocesses, so what they allocate lands in whichever stage happens to be
 * measuring when they are scheduled - a 366 KB "statuswin" reading here was
 * mostly the scanner, since StatusWin itself is two 32-entry lists, about
 * 40 KB. For a total figure, take Avail with the daemon stopped and running. */
static void mem_stage(const char *what, ULONG *prev)
{
    ULONG now  = mem_free_fast();
    long  used = (long)*prev - (long)now;

    log_printf(LOG_DEBUG, "mem: %-22s %+7ld bytes, %lu free",
               what, used, (unsigned long)now);
    *prev = now;
}

/* Days from 1970-01-01 to a civil date, for AMISYNC_DATE. (log.c carries the
 * inverse, days -> civil, for its timestamps.) */
static int64_t days_from_civil(int y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y  -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;                          /* [0, 399] */
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* Two digits, or -1. */
static int two_digits(const char *p)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
        return -1;
    return (p[0] - '0') * 10 + (p[1] - '0');
}

/* Say so when the clock cannot be right, because everything downstream quietly
 * believes it: file datestamps we announce to peers, the mtime tiebreak that
 * decides a real conflict, and - where a peer sends no version - which side of
 * a deletion wins. An Amiga with a flat RTC battery is the ordinary case, and
 * the failure it causes is silent and confusing. The build date is the floor:
 * this daemon cannot be running before it existed. No formatting of what the
 * clock says is needed - the log line stamps itself, which is exactly the
 * value in question. */
static void check_clock(void)
{
    const char *d = AMISYNC_DATE;                 /* "dd.mm.yyyy" */
    int         day, mon, year, hi, lo;
    int64_t     built, now;

    day = two_digits(d);
    mon = two_digits(d + 3);
    hi  = two_digits(d + 6);
    lo  = two_digits(d + 8);
    if (day < 1 || mon < 1 || hi < 0 || lo < 0 || d[2] != '.' || d[5] != '.')
        return;                                   /* unparsable: say nothing */
    year = hi * 100 + lo;

    built = days_from_civil(year, mon, day) * 86400;
    now   = folder_now();

    if (now < built)
        log_printf(LOG_WARN, "daemon: the clock is set earlier than this build "
                   "(%s) - the stamp on this line is what this machine "
                   "believes. File times and conflict resolution follow it, so "
                   "set the clock or this machine loses conflicts silently",
                   AMISYNC_DATE);
    else if (now > built + (int64_t)20 * 365 * 86400)
        log_printf(LOG_WARN, "daemon: the clock is set more than 20 years past "
                   "this build (%s) - the stamp on this line is what this "
                   "machine believes. File times and conflict resolution "
                   "follow it, so set the clock or this machine wins conflicts "
                   "it should lose", AMISYNC_DATE);
}

/* Our device's short ID (the version-counter key), derived from our identity
 * cert. The scanner stamps it into each folder's versions. 0 if the cert is
 * unreadable - the scanner still tracks files, just keyed to 0 until identity
 * is available (matches the worker's own best-effort derivation). */
static uint64_t our_short_id(const Config *cfg)
{
    char          ourid[DEVICE_ID_BUFSZ];
    unsigned char raw[32];

    if (device_id_from_cert_file(cfg->cert_path, ourid) &&
        device_id_to_raw(ourid, raw))
        return sync_short_id_from_raw(raw);
    return 0;
}

/* Load a folder's persisted index into 'fs' (already foldstate_init'd).
 * Done here in main, BEFORE any worker can write to the shared index, so a load
 * can never wipe a file a worker has already received. Missing / corrupt / wrong
 * index is not fatal - the scanner just rebuilds it by hashing. */
static void load_folder_index(const Config *cfg, FolderState *fs)
{
    char  path[256];
    long  sz;
    void *buf;

    if (!folder_state_path(cfg->statedir, fs->folder_id, path, sizeof(path)))
        return;
    sz = folder_state_size(path);
    if (sz <= 0)
        return;                                  /* absent / empty: full rescan */

    buf = AllocVec((ULONG)sz, MEMF_ANY);
    if (!buf)
        return;
    if (folder_state_read(path, buf, (int)sz) == (int)sz &&
        index_store_decode(fs, buf, (size_t)sz))
        log_printf(LOG_INFO, "daemon: loaded index for '%s' (%d file(s), seq %ld)",
                   fs->folder_id, fs->num_files, (long)fs->sequence);
    FreeVec(buf);

    /* Decoding replays records through foldstate_upsert, which notes each as
     * the folder's "latest change" - but a loaded record is history, not a
     * change. No lock needed: workers/scanner have not started yet. */
    fs->chg_verb = 0;
    fs->chg_name[0] = '\0';
}

/* ---- clock-offset migration --------------------------------------------
 * The offset the persisted indexes were written under, kept beside them as
 * 'clock.tz'. Absent means 0, which is what every version before the offset
 * existed used. Text, because it is one number a human may want to read. */
static int tz_state_load(const Config *cfg, int *out)
{
    char path[256], buf[32];
    long sz;
    int  i = 0, neg = 0, v = 0;

    if (!folder_aux_path(cfg->statedir, "clock.tz", path, sizeof(path)))
        return 0;
    sz = folder_state_size(path);
    if (sz <= 0 || sz >= (long)sizeof(buf))
        return 0;
    if (folder_state_read(path, buf, (int)sz) != (int)sz)
        return 0;
    buf[sz] = '\0';
    if (buf[i] == '-') { neg = 1; i++; }
    else if (buf[i] == '+') i++;
    if (buf[i] < '0' || buf[i] > '9')
        return 0;
    for (; buf[i] >= '0' && buf[i] <= '9'; i++)
        v = v * 10 + (buf[i] - '0');
    *out = neg ? -v : v;
    return 1;
}

static void tz_state_save(const Config *cfg, int secs)
{
    char path[256], buf[32];

    if (!folder_aux_path(cfg->statedir, "clock.tz", path, sizeof(path)))
        return;
    sprintf(buf, "%d\n", secs);
    folder_state_write(path, buf, (int)strlen(buf));
}

/* Reconcile one folder with a changed clock offset, so that changing it does
 * not re-date a folder that is already in sync.
 *
 * Every datestamp on disk was written under the OLD offset, and the new one
 * reads them all differently - which the scanner would report as every file
 * having been modified at once, and announce. Two cases, told apart by whether
 * anyone else's counter appears in the record's version vector:
 *
 *   A peer's file: our index holds the sender's UTC, which is right, and the
 *   disk stamp is the one we derived wrongly. Re-stamp the file from the
 *   record. Nothing to announce - the record does not change.
 *
 *   Our own file: the disk stamp is the true local time the user sees, and the
 *   RECORD is the one computed wrongly. Leave both alone; the next scan reads
 *   the disk under the new rule, corrects the record and announces it once,
 *   which is exactly right.
 *
 * modified_by looks like the obvious test and is the wrong one: it means "who
 * wrote this record last", and a full rescan - which the index-format bump
 * already forced on everyone once - rewrites it to us for every file in the
 * folder. Tried here first, and it misfiled all seven files of a folder whose
 * every byte came from a peer. A foreign counter in the vector survives that,
 * because the scanner carries the prior version forward when it re-hashes.
 *
 * Runs before the scanner and any worker, so nothing else touches the index;
 * the lock is taken per record anyway, to keep file I/O outside it. */
static int retime_folder(const ConfigFolder *cf, FolderState *fs)
{
    int i, n = 0, ours = 0, failed = 0;

    for (i = 0; ; i++) {
        SyncMeta m;

        foldstate_lock(fs);
        if (i >= fs->num_files) {
            foldstate_unlock(fs);
            break;
        }
        foldstate_meta(fs, &fs->files[i], &m);
        foldstate_unlock(fs);

        if (m.deleted || m.invalid || m.type != BEP_FILE_FILE)
            continue;
        {
            int k, foreign = 0;
            for (k = 0; k < m.version.num_counters; k++)
                if (m.version.counters[k].id != fs->short_id)
                    foreign = 1;
            if (!foreign) {
                ours++;                        /* ours: the scan corrects it */
                continue;
            }
        }
        if (folder_touch(cf->path, m.name, m.modified_s, 0))
            n++;
        else
            failed++;
    }
    if (n || ours)
        log_printf(LOG_INFO, "daemon: '%s': re-stamped %d file(s) from the "
                   "index, left %d of our own for the scan to correct",
                   fs->folder_id, n, ours);
    if (failed)
        log_printf(LOG_WARN, "daemon: '%s': %d file(s) could not be re-stamped "
                   "- their dates stay as they were", fs->folder_id, failed);
    return n;
}

/* Drain the discovery port: DISCO_FOUND events (a configured peer's address)
 * go to the peer manager to dial; DISCO_SEEN events (an unconfigured device on
 * the LAN) are recorded for the ARexx DISCOVERED verb and logged once each. */
static void drain_discovered(PeerManager *pm, DiscoSeenList *seen,
                             struct MsgPort *port)
{
    struct Message *m;
    while ((m = GetMsg(port)) != NULL) {
        DiscoEvent *df = (DiscoEvent *)m;
        if (df->kind == DISCO_SEEN) {
            if (seen && disco_seen_add(seen, df->id, df->host, df->port))
                log_printf(LOG_INFO, "discovered new device %s at %s:%u "
                           "(not configured - add a peer line to sync with it)",
                           df->id, df->host, (unsigned)df->port);
        } else {
            peer_manager_discovered(pm, df->id, df->host, df->port);
        }
        FreeVec(df);                 /* fire-and-forget: we own it now */
    }
}

/* ---- status publishing --------------------------------------------------
 * The daemon exports a one-line sync status to ENV:amisync/status so the user
 * can see at a glance (Workbench tool, a script, an AppIcon later) whether the
 * folder is up to date. A small repeating timer refreshes it; connect/complete
 * events refresh it immediately too. */
#define STATUS_POLL_SECS  2

typedef struct {
    struct MsgPort     *port;
    struct timerequest *req;
    int                 armed;
    char                last[64];       /* debounce: only write ENV on change */
} StatusTimer;

/* Best-effort: the FIELDS are the contract, not a return value - a NULL port
 * or req makes status_timer_sig/_arm/_close no-ops, so the caller needs no
 * check. Failure only means ENV:amisync/status stops refreshing on the tick,
 * so say so once rather than leaving the user to wonder. */
static void status_timer_open(StatusTimer *t)
{
    t->port  = NULL;
    t->req   = NULL;
    t->armed = 0;
    t->last[0] = '\0';

    t->port = CreateMsgPort();
    if (!t->port)
        goto failed;
    t->req = (struct timerequest *)CreateIORequest(t->port, sizeof(*t->req));
    if (!t->req) {
        DeleteMsgPort(t->port); t->port = NULL;
        goto failed;
    }
    if (OpenDevice("timer.device", UNIT_VBLANK, (struct IORequest *)t->req, 0)) {
        DeleteIORequest((struct IORequest *)t->req); t->req = NULL;
        DeleteMsgPort(t->port); t->port = NULL;
        goto failed;
    }
    return;

failed:
    log_printf(LOG_WARN, "daemon: no status timer; ENV:amisync/status will "
               "only update on connect/complete events");
}

static unsigned long status_timer_sig(StatusTimer *t)
{
    return t->port ? (1UL << t->port->mp_SigBit) : 0;
}

static void status_timer_arm(StatusTimer *t)
{
    if (!t->req || t->armed)
        return;
    t->req->tr_node.io_Command = TR_ADDREQUEST;
    t->req->tr_time.tv_secs    = STATUS_POLL_SECS;
    t->req->tr_time.tv_micro   = 0;
    SendIO((struct IORequest *)t->req);
    t->armed = 1;
}

static void status_timer_close(StatusTimer *t)
{
    if (t->req) {
        if (t->armed) {
            AbortIO((struct IORequest *)t->req);
            WaitIO((struct IORequest *)t->req);
            t->armed = 0;
        }
        CloseDevice((struct IORequest *)t->req);
        DeleteIORequest((struct IORequest *)t->req);
        t->req = NULL;
    }
    if (t->port) {
        DeleteMsgPort(t->port);
        t->port = NULL;
    }
}

/* Length-bounded copy that always NUL-terminates. */
static void scopy(char *dst, const char *src, int cap)
{
    int n = (int)strlen(src);
    if (n > cap - 1)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Publish one status string to ENV:amisync/status (global env only - it is
 * volatile, never saved to ENVARC:). Returns 1 when the file now holds
 * exactly 'now', 0 when it could not be written and the caller should try
 * again on the next tick.
 *
 * Written directly rather than through SetVar. SetVar normally replaces the
 * file, but not while someone else has it open: publishing a 10-byte
 * "Up to Date" over a 17-byte "Syncing (5 files)" left the last seven bytes
 * of the old value behind, and ENV:amisync/status - which is the AppIcon's
 * label on the Workbench backdrop - read "Up to Date files)" from then on.
 * Reading the variable is the whole point of publishing it, so the reader
 * must not be able to corrupt it.
 *
 * MODE_NEWFILE has no such middle ground: it either takes the file
 * exclusively and truncates it, or it fails and leaves the previous value
 * intact and coherent. A failure costs a status that is one tick stale
 * (STATUS_POLL_SECS), which is the right thing to be wrong about. */
static int status_write(const char *now)
{
    BPTR fh = Open((STRPTR)"ENV:amisync/status", MODE_NEWFILE);
    long n  = (long)strlen(now);

    if (!fh)
        return 0;                      /* someone is reading it; try again */
    if (Write(fh, (APTR)now, (LONG)n) != (LONG)n) {
        Close(fh);
        return 0;
    }
    Close(fh);
    return 1;
}

/* Recompute the aggregate status and, if it changed, publish it.
 * Cheap; safe to call on every wake. 'last' is only advanced once the file
 * really holds the new text, so a write that lost the file to a reader is
 * retried rather than silently skipped. */
static void status_publish(StatusTimer *t, PeerManager *pm)
{
    char now[64];

    peer_manager_status(pm, now, sizeof(now), NULL, NULL);
    if (strcmp(now, t->last) == 0)
        return;
    if (!status_write(now))
        return;
    scopy(t->last, now, sizeof(t->last));
    log_printf(LOG_INFO, "status: %s", now);
}

/* A per-run index id for one folder slot: current DateStamp mixed with our
 * short id and the slot number. Not cryptographic - just distinct across
 * runs and folders (see FolderState.index_id). */
static uint64_t make_index_id(uint64_t sid, int slot)
{
    struct DateStamp ds = {0};
    uint64_t h;

    DateStamp(&ds);
    h  = sid ^ 0x9E3779B97F4A7C15ULL;
    h ^= (uint64_t)(ULONG)ds.ds_Days   << 40;
    h ^= (uint64_t)(ULONG)ds.ds_Minute << 20;
    h ^= (uint64_t)(ULONG)ds.ds_Tick   << 4;
    h ^= (uint64_t)(slot + 1);
    h *= 0x2545F4914F6CDD1DULL;
    return h ? h : 1;
}

/* ---- runtime folder add/remove (ARexx ADDFOLDER / REMOVEFOLDER) --------
 *
 * The folder set follows the peer table's runtime pattern: fixed-capacity
 * arrays, a live count, tombstones instead of compaction (workers index
 * folders by position), and a generation bump that makes connected workers
 * re-send their ClusterConfig in-band and reset the announce cursors of
 * changed folders. Main task only (called from the ARexx dispatch), reaching
 * the live daemon state through ArexxContext (see arexx.h). */

/* Canonical volume-rooted form of 'path' via Lock+NameFromLock: resolves
 * assigns, relative components and letter case, so any two spellings of
 * the same drawer compare equal. Returns 0 when the path cannot be
 * locked. */
static int canon_dir(const char *path, char *out, int cap)
{
    BPTR lk = Lock((STRPTR)path, ACCESS_READ);
    int  ok;

    if (!lk)
        return 0;
    ok = NameFromLock(lk, (STRPTR)out, cap) ? 1 : 0;
    UnLock(lk);
    return ok;
}

/* Is canonical path 'inner' the same drawer as - or nested inside -
 * canonical path 'outer'? (ASCII-case-insensitive; both come from
 * NameFromLock, so a prefix match on a component boundary decides.) */
static int path_within(const char *inner, const char *outer)
{
    int n = (int)strlen(outer);
    int i;

    for (i = 0; i < n; i++) {
        int a = inner[i], b = outer[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b)
            return 0;
    }
    return inner[n] == '\0' || inner[n] == '/' ||
           (n > 0 && outer[n - 1] == ':');
}

int daemon_folder_add(const ArexxContext *ctx, const char *id,
                      const char *path, FolderMode mode, const char *label)
{
    Config      *cfg;
    FolderState *fs = NULL;
    int          i, idx = -1;

    if (!ctx || !ctx->cfg_rw || !ctx->folders || !id || !path ||
        !id[0] || !path[0])
        return 0;
    cfg = ctx->cfg_rw;
    if (strlen(id) >= CONFIG_FOLDER_ID_MAX || strlen(path) >= CONFIG_PATH_MAX)
        return 0;
    /* Accepting a peer's offer brings ITS folder id and label here unaltered
     * (they must match the peer's exactly), and this ends up as a line of
     * amisync.conf. A control character in one of them would write a whole
     * extra setting - a folder rooted at SYS:, say - that the next start
     * obeys. Refuse the add outright; config.c's writer refuses again. */
    if (!text_field_safe(id) || !text_field_safe(path) ||
        (label && !text_field_safe(label))) {
        log_printf(LOG_WARN, "daemon: ADDFOLDER: refusing '%.64s' - the id, "
                   "path or label holds control characters or quotes", id);
        return 0;
    }

    for (i = 0; i < cfg->num_folders; i++) {
        if (strcmp(cfg->folders[i].id, id) != 0)
            continue;
        if (!cfg->folders[i].removed)
            return -1;                     /* already configured */
        idx = i;                           /* tombstone: resurrect this slot */
        break;
    }
    if (idx < 0) {
        if (cfg->num_folders >= CONFIG_MAX_FOLDERS)
            return -2;                     /* table full (restart reclaims) */
        idx = cfg->num_folders;
    }

    if (!folder_ensure_dir(path)) {
        log_printf(LOG_WARN, "daemon: ADDFOLDER: cannot create '%s'", path);
        return 0;
    }

    /* Refuse a path that IS - or nests inside/around - an already-synced
     * drawer, whatever it is spelled like (assigns, case): two indexes
     * over the same files would each announce them under their own folder
     * id and process every change twice. Syncthing refuses overlapping
     * folder paths for the same reason. Checked after ensure_dir so the
     * canonical form exists to lock; a drawer created just now and then
     * refused is left behind, empty and harmless. */
    {
        char cnew[2 * CONFIG_PATH_MAX], cold[2 * CONFIG_PATH_MAX];
        /* Fail closed: folder_ensure_dir just succeeded, so a path we cannot
         * lock and name means something is wrong with it, and an unresolved
         * path cannot be shown NOT to overlap. */
        if (!canon_dir(path, cnew, sizeof(cnew))) {
            log_printf(LOG_WARN, "daemon: ADDFOLDER '%s': cannot resolve '%s'",
                       id, path);
            return 0;
        }
        for (i = 0; i < cfg->num_folders; i++) {
            const ConfigFolder *f = &cfg->folders[i];
            if (f->removed)
                continue;
            if (!canon_dir(f->path, cold, sizeof(cold)))
                continue;              /* its volume is gone: cannot overlap
                                        * a drawer that exists right now */
            if (path_within(cnew, cold) || path_within(cold, cnew)) {
                log_printf(LOG_WARN, "daemon: ADDFOLDER '%s': path '%s' "
                           "overlaps folder '%s' (%s)",
                           id, path, f->id, f->path);
                return -3;
            }
        }
    }

    /* Fresh shared index for the slot. No stale persisted index is loaded -
     * a resurrected id may point at a different path, and sweeping a stale
     * index against a fresh directory would announce spurious deletions; the
     * scanner builds the truth from disk. Any old state file goes with it.
     *
     * foldstate_reset, NOT free+init: a tombstoned slot is not a quiet one.
     * The scanner checks 'removed' when it picks a folder up, then walks it
     * for as long as hashing that tree takes, and a worker announces from the
     * same records - so a remove followed by a re-add of the same id lands
     * here while another task is inside the slot. reset re-keys it under the
     * slot's own semaphore and leaves that semaphore alone. */
    {
        uint64_t sid = our_short_id(cfg);      /* re-reads the cert: once */
        fs = &ctx->folders[idx];
        foldstate_reset(fs, id, sid, make_index_id(sid, idx));
    }
    {
        char sp[256];
        if (folder_state_path(cfg->statedir, id, sp, sizeof(sp)))
            DeleteFile((STRPTR)sp);
    }

    {
        ConfigFolder *f = &cfg->folders[idx];
        scopy(f->id, id, sizeof(f->id));
        scopy(f->label, label && label[0] ? label : id, sizeof(f->label));
        scopy(f->path, path, sizeof(f->path));
        f->mode = mode;
        Forbid();                          /* slot complete before visible */
        f->gen++;
        f->removed = 0;
        if (idx == cfg->num_folders)
            cfg->num_folders++;
        cfg->config_gen++;
        Permit();
    }

    if (!config_append_folder(CONFIG_PATH_DEFAULT, id, path, mode,
                              label && label[0] ? label : NULL))
        log_printf(LOG_WARN, "daemon: added folder '%s' but could not write "
                   CONFIG_PATH_DEFAULT, id);

    scanner_rescan(ctx->scanner);          /* scan it now, not in 60s */
    wreg_signal(WORKER_SIG_RESCAN);        /* workers: CC update + announce */
    log_printf(LOG_INFO, "daemon: folder '%s' added at runtime (%s, %s)",
               id, path,
               mode == FOLDER_SENDONLY ? "sendonly" :
               mode == FOLDER_RECEIVEONLY ? "receiveonly" : "sendreceive");
    return 1;
}

int daemon_folder_remove(const ArexxContext *ctx, const char *id)
{
    Config *cfg;
    int     i;

    if (!ctx || !ctx->cfg_rw || !id || !id[0])
        return 0;
    cfg = ctx->cfg_rw;

    for (i = 0; i < cfg->num_folders; i++) {
        ConfigFolder *f = &cfg->folders[i];
        if (f->removed || strcmp(f->id, id) != 0)
            continue;

        Forbid();
        f->removed = 1;                    /* tombstone; slot must not move */
        cfg->config_gen++;
        Permit();

        if (!config_remove_folder(CONFIG_PATH_DEFAULT, id))
            log_printf(LOG_WARN, "daemon: removed folder '%s' but no config "
                       "line was found to delete", id);
        {
            char sp[256];                  /* drop the persisted index */
            if (folder_state_path(cfg->statedir, id, sp, sizeof(sp)))
                DeleteFile((STRPTR)sp);
        }
        wreg_signal(WORKER_SIG_RESCAN);    /* workers: CC update, stop announcing */
        log_printf(LOG_INFO, "daemon: folder '%s' removed at runtime", id);
        return 1;
    }
    return 0;
}

int daemon_run(Config *cfg)
{
    ArexxPort      *ax;
    PeerManager    *pm;
    ListenerHandle *listener;
    DiscoHandle    *disco;
    ScannerHandle  *scanner;
    FolderState    *folders = NULL;   /* shared per-folder index, [num_folders] */
    struct MsgPort *discoport;
    DiscoSeenList   seen = {0};   /* unconfigured devices seen on the LAN */
    StatusTimer     stimer;
    AppIconUI      *ai;
    StatusWin      *sw;
    ArexxContext    ctx;
    char            ourid[DEVICE_ID_BUFSZ];   /* our device ID, for STATUS */
    ULONG           memtrace;                 /* startup memory trace, see mem_stage */
    unsigned long   axsig, peersig, discosig, statsig, aisig, waitmask, sigs;
    int             running = 1;

    ax = arexx_open(cfg->rexx_port);
    if (!ax) {
        log_printf(LOG_ERROR,
                   "could not open ARexx port '%s' (already running?)",
                   cfg->rexx_port);
        return 1;
    }
    log_printf(LOG_INFO, "daemon up; ARexx port '%s' open", cfg->rexx_port);
    check_clock();

    /* Apply file-versioning config before any worker/scanner subprocess runs;
     * they share the data segment, so this single flag is visible to all. */
    folder_set_versioning(cfg->versioning);

    /* Same contract for the clock's offset from UTC: config first, else ask
     * locale.library, else 0. Said out loud whichever way it goes, because it
     * re-dates every file - the first scan after it changes finds every
     * timestamp moved and re-announces the lot - and because a wrong answer
     * here is otherwise invisible. */
    {
        int offs = cfg->tz_offset_s, found = cfg->tz_offset_set;
        const char *src = "tzoffset";

        /* Locale prefs are the default answer: it is where this machine
         * already says what time zone it keeps, and asking twice would be
         * asking the user to repeat themselves. 'tzoffset' overrides it, for
         * a machine whose Locale is unset or set to a zone its clock does not
         * actually keep. Changing whichever one applies is safe because the
         * indexes remember what they were written under (see retime_folder);
         * without that, an upgrade would silently re-date every folder. */
        if (!cfg->tz_offset_set) {
            offs = locale_utc_offset_s(&found);
            src  = "locale.library";
            if (!found && cfg->tz_from_locale)
                log_printf(LOG_WARN, "daemon: tzoffset = locale, but Locale "
                           "prefs have no time zone set - times stay UTC");
        }
        folder_set_tz_offset(offs);
        if (offs) {
            int m = offs / 60, a = m < 0 ? -m : m;
            log_printf(LOG_INFO, "daemon: clock is local time, UTC%c%02d:%02d "
                       "(from %s)", m < 0 ? '-' : '+', a / 60, a % 60, src);
        } else if (found) {
            log_printf(LOG_INFO, "daemon: clock keeps UTC (from %s)", src);
        }
    }

    /* A TCP/IP stack (anything providing bsdsocket.library) is required for all
     * networking. Probe it once here so the user gets one clear message rather
     * than every worker failing cryptically later. Non-fatal: the daemon still
     * answers ARexx, and a stack started afterwards will be picked up on the
     * next dial. */
    {
        struct Library *sb = OpenLibrary("bsdsocket.library", 4);
        if (sb)
            CloseLibrary(sb);
        else
            log_printf(LOG_WARN,
                       "daemon: no TCP/IP stack found (bsdsocket.library) - "
                       "start Roadshow/AmiTCP/Miami; peering is disabled until then");
    }

    /* Open the shared AmiSSL instance once, here in the main process, before any
     * networking subprocess is spawned. Each worker/discovery subprocess binds
     * to it with ssl_subtask_init(); the listener uses plain sockets only. A
     * failure is not fatal - the daemon still answers ARexx - but TLS peering
     * will not work until AmiSSL is available. */
    memtrace = mem_free_fast();
    log_printf(LOG_DEBUG, "mem: fast RAM free at startup: %lu",
               (unsigned long)memtrace);

    if (!ssl_open()) {
        log_printf(LOG_ERROR,
                   "daemon: AmiSSL unavailable; TLS peering disabled");
        ssl_close();
    }
    mem_stage("ssl_open", &memtrace);

    /* One shared FolderState per folder, owned here in main and handed by
     * pointer to BOTH the workers (which read it to announce and write it on
     * receive) and the scanner (which hashes each folder once and keeps it
     * current), so it is allocated before either starts. At FULL capacity
     * (CONFIG_MAX_FOLDERS), not num_folders: folders can be added at runtime
     * (ARexx ADDFOLDER) and both index this array by position, so it must
     * never move or grow. Without it there is no shared index, so peering is
     * skipped - the daemon still answers ARexx. */
    folders = AllocVec(sizeof(FolderState) * CONFIG_MAX_FOLDERS,
                       MEMF_ANY | MEMF_CLEAR);
    if (folders) {
        uint64_t sid = our_short_id(cfg);
        int      i;
        folder_ensure_dir(cfg->statedir);   /* best-effort; saves need it */
        /* EVERY slot, not just the configured ones: daemon_folder_add takes
         * the lock of the slot it is about to fill (foldstate_reset), and an
         * all-zero SignalSemaphore is not a free one - InitSemaphore leaves
         * ss_QueueCount at -1, cleared memory reads as 0, so ObtainSemaphore
         * decides another task holds it and queues the caller on a MinList
         * that was never linked. The ARexx task then waits for a signal
         * nobody will ever send: adding the second folder at runtime hung the
         * daemon (and QUIT with it) every time. */
        for (i = 0; i < CONFIG_MAX_FOLDERS; i++)
            foldstate_init(&folders[i],
                           i < cfg->num_folders ? cfg->folders[i].id : "", sid);
        for (i = 0; i < cfg->num_folders; i++) {
            folders[i].index_id = make_index_id(sid, i);
            load_folder_index(cfg, &folders[i]);   /* before any worker runs */
        }

        /* Indexes are in; reconcile them if the clock offset has moved since
         * they were written. Before the scanner and the workers start. */
        {
            int was = 0, now = folder_tz_offset(), n = 0;

            tz_state_load(cfg, &was);
            if (was != now) {
                log_printf(LOG_INFO, "daemon: clock offset changed by %ld "
                           "minute(s); reconciling what is already indexed",
                           (long)(now - was) / 60);
                for (i = 0; i < cfg->num_folders; i++)
                    n += retime_folder(&cfg->folders[i], &folders[i]);
                tz_state_save(cfg, now);
            }
        }
    } else {
        log_printf(LOG_ERROR, "daemon: out of memory for folder index; "
                   "peering disabled");
    }

    /* index_ok is false only when we have folders to share but couldn't allocate
     * their index; with no folders, peering an empty share is still fine. */
    {
        int index_ok = (cfg->num_folders == 0) || (folders != NULL);

        mem_stage("folder indexes", &memtrace);

        /* Bring up the peer workers. A failure here is not fatal: the daemon
         * still runs (and answers ARexx), it just won't connect to peers. */
        pm = index_ok ? peer_manager_create(cfg, folders) : NULL;
        if (pm) {
            peer_manager_start(pm);
            log_printf(LOG_INFO, "daemon: %d peer(s) configured", cfg->num_peers);
        } else {
            log_printf(LOG_ERROR, "daemon: peer manager unavailable; no peering");
        }

        /* Inbound listener (off if listenport = 0). */
        listener = index_ok ? listener_start(cfg, folders) : NULL;
        if (listener)
            log_printf(LOG_INFO, "daemon: listening on port %u", cfg->listen_port);
        mem_stage("peers + listener", &memtrace);
    }

    /* Local-discovery broadcaster + receiver (config 'discovery', on by
     * default; receive-only when there is no listenport).
     * The receiver posts discovered peer addresses to 'discoport'. */
    discoport = CreateMsgPort();
    disco     = disco_start(cfg, discoport);
    if (disco)
        log_printf(LOG_INFO, "daemon: local discovery enabled");
    mem_stage("discovery", &memtrace);

    /* The scanner owns scanning/hashing for the shared index; it needs the shared
     * AmiSSL instance for SHA-256. Runs only if the index was allocated. */
    scanner = folders ? scanner_start(cfg, folders, cfg->num_folders) : NULL;
    /* (started even with zero folders: a runtime ADDFOLDER joins its next pass) */
    if (scanner)
        log_printf(LOG_INFO, "daemon: scanner started over %d folder(s)",
                   cfg->num_folders);
    mem_stage("scanner", &memtrace);

    /* Status export to ENV:amisync/status. Ensure the ENV:amisync drawer
     * exists first (SetVar writes a file into it); best-effort, non-fatal if
     * the timer can't open - the daemon just won't publish live status. */
    {
        BPTR d = CreateDir("ENV:amisync");
        if (d) UnLock(d);
    }
    status_timer_open(&stimer);            /* best-effort; fields valid either way */
    status_publish(&stimer, pm);           /* initial value, even without the timer */
    status_timer_arm(&stimer);             /* no-op if the device didn't open       */
    statsig = status_timer_sig(&stimer);

    /* Workbench AppIcon mirroring the status (best-effort, config 'appicon').
     * At boot Workbench isn't up yet - appicon_update() retries the actual
     * AddAppIcon on each status tick until it lands. */
    ai = appicon_create(cfg->appicon);
    appicon_update(ai, stimer.last);
    aisig = appicon_sigmask(ai);

    /* The live status window the AppIcon/Tools-menu Status opens. Created
     * windowless here; its signal joins the Wait() mask only while open. */
    sw = statuswin_create();
    mem_stage("statuswin", &memtrace);

    /* Live daemon state for the ARexx verbs and the AppIcon's double-click
     * STATUS requester; the pointers stay valid for the daemon's lifetime. */
    ctx.cfg      = cfg;
    ctx.cfg_rw   = cfg;
    ctx.pm       = pm;
    ctx.listener = listener;
    ctx.scanner  = scanner;
    ctx.seen     = &seen;
    ctx.folders  = folders;

    /* Needs the shared AmiSSL instance, so derived only now (after ssl_open;
     * empty when the cert is unreadable or TLS is unavailable). */
    if (!device_id_from_cert_file(cfg->cert_path, ourid))
        ourid[0] = '\0';
    ctx.our_id = ourid;
    if (ourid[0])
        /* The full ID in the log (Syncthing does the same at startup): what
         * a peer's owner needs to configure us, without running SHOWID. */
        log_printf(LOG_INFO, "daemon: our device ID is %s", ourid);
    {
        struct DateStamp ds = {0};
        DateStamp(&ds);
        ctx.start_day = ds.ds_Days;
        ctx.start_min = ds.ds_Minute;
    }

    axsig    = arexx_signal(ax);
    peersig  = peer_manager_sigmask(pm);
    discosig = (disco && discoport) ? (1UL << discoport->mp_SigBit) : 0;

    while (running) {
        /* The status window's signal exists only while the window is open, so
         * the mask is rebuilt each pass (everything else in it is constant). */
        unsigned long swsig = statuswin_sigmask(sw);
        waitmask = axsig | peersig | discosig | statsig | aisig | swsig |
                   SIGBREAKF_CTRL_C;
        sigs = Wait(waitmask);

        if (sigs & SIGBREAKF_CTRL_C) {
            log_printf(LOG_INFO, "CTRL-C received; shutting down");
            running = 0;
        }

        if (sigs & statsig) {
            GetMsg(stimer.port);           /* dequeue the fired request */
            stimer.armed = 0;
            status_publish(&stimer, pm);
            peer_manager_retry(pm);            /* re-dial a failed spawn    */
            appicon_update(ai, stimer.last);   /* retry add / refresh label */
            statuswin_update(sw, &ctx);        /* live report, if open      */
            status_timer_arm(&stimer);     /* re-arm for the next tick  */
        }

        if (sigs & discosig)
            drain_discovered(pm, &seen, discoport);

        if (sigs & peersig) {
            peer_manager_handle(pm);
            status_publish(&stimer, pm);   /* connect/disconnect: refresh now */
            appicon_update(ai, stimer.last);
            statuswin_update(sw, &ctx);
        }

        if (sigs & swsig) {
            /* window events; 1 = Quit button, confirmed */
            if (statuswin_handle(sw, &ctx)) {
                log_printf(LOG_INFO, "status window Quit; shutting down");
                running = 0;
            }
        }

        if (sigs & aisig) {
            /* icon double-click / Tools-menu picks; 1 = confirmed Quit */
            if (appicon_handle(ai, &ctx, sw)) {
                log_printf(LOG_INFO, "Tools-menu Quit; shutting down");
                running = 0;
            }
        }

        if (sigs & axsig) {
            if (arexx_dispatch(ax, &ctx) == AREXX_QUIT) {
                log_printf(LOG_INFO, "QUIT command; shutting down");
                running = 0;
            }
        }
    }

    log_printf(LOG_INFO, "daemon stopping");
    status_write("Stopped");
    statuswin_destroy(sw);       /* before appicon_destroy: it closes intuition */
    appicon_destroy(ai);         /* remove the icon first; NULL-safe */
    status_timer_close(&stimer);
    disco_stop(disco);           /* stops + joins the broadcaster (NULL-safe) */
    listener_stop(listener);     /* stops + joins inbound workers (NULL-safe) */
    peer_manager_shutdown(pm);   /* stops + joins all dialers (NULL-safe)     */
    scanner_stop(scanner);       /* last: its final index save captures the   */
                                 /* workers' receives now that they've stopped */
    if (discoport) {
        drain_discovered(NULL, NULL, discoport);   /* free any unprocessed finds */
        DeleteMsgPort(discoport);
    }
    ssl_close();                 /* now that every subprocess has exited       */
    if (folders) {
        int i;
        for (i = 0; i < cfg->num_folders; i++)
            foldstate_free(&folders[i]);   /* release each folder's record table
                                            * (runtime-added ones included:
                                            * num_folders is the live count) */
        FreeVec(folders);        /* after the scanner (its writer) has joined  */
    }
    arexx_close(ax);
    return 0;
}
