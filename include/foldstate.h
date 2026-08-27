/* foldstate.h - shared, semaphore-guarded per-folder index for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The per-folder index must be single-source-of-truth: if each per-peer
 * worker kept its own records, version vectors and sequence counter, two
 * peers sharing a folder would be handed different versions/sequences for
 * the same file - a permanent conflict once those peers later sync with
 * each other. So there is one FolderState per configured folder, allocated
 * by the main process at startup and shared (by pointer) with every worker
 * and the scanner. AmigaOS has one address space, so a struct main
 * allocates is directly usable by any task - this is the same trick netbase's
 * registry uses.
 *
 * FolderState holds the AUTHORITATIVE per-folder state: the local index
 * (SyncMeta records), the monotonic per-folder sequence high-water, a dirty
 * flag (for the save path), and a SignalSemaphore guarding all of it.
 *
 * LOCKING DISCIPLINE (the thing to get right): critical sections are pure
 * memory ops - look up a record, compare, update one record, bump the sequence.
 * Hashing and disk I/O happen OUTSIDE the lock. A semaphore must never be held
 * across a SHA-256 or a file read, or workers serialize on it. The accessors
 * below do NOT lock; the caller brackets a critical section with
 * foldstate_lock()/foldstate_unlock() and does its I/O outside that bracket.
 *
 * The pure data ops (init/find/upsert/next_seq) are host-tested
 * (tests/test_foldstate.c, FOLDSTATE_HOST_TEST); the SignalSemaphore field and
 * the lock/unlock wrappers are Amiga-only, behind the same guard.
 */

#ifndef AMISYNC_FOLDSTATE_H
#define AMISYNC_FOLDSTATE_H

#include "syncmodel.h"   /* SyncMeta - the per-file index record */
#include "bep.h"        /* BEP_*_MAX sizing, BEP_HASH_LEN, stdint */

#ifndef FOLDSTATE_HOST_TEST
#include <exec/semaphores.h>
#endif

/* Initial record capacity. The table is allocated lazily (on the first upsert)
 * and grows by doubling, so a folder's index costs about what it holds rather
 * than a fixed worst-case block per configured folder. */
#define FOLDSTATE_INIT_FILES  64

/* Safety ceiling on records per folder. The table grows on demand up to here;
 * beyond it foldstate_upsert refuses new entries (returns 0, the same "index
 * full" contract callers already cope with) rather than let a runaway peer
 * exhaust RAM. Far above any realistic 68k folder, so practically unreachable. */
#define FOLDSTATE_MAX_FILES  100000

/* One-fetcher-per-file claims. Every peer sharing a folder offers the same
 * files, and each peer's worker is a separate process with its own want queue -
 * so without a claim two of them fetch one file into one staged temp at the
 * same time. This is the only state the workers share for the purpose, which is
 * why it lives here beside the index, under the same semaphore.
 *
 * Slots are keyed by a 32-bit hash of the name, not the name: a collision costs
 * one worker a deferred fetch (it comes back for it next pass), never
 * correctness, and 16 slots of 8 bytes beats 16 of BEP_PATH_MAX in a struct
 * allocated for every folder slot at startup. A worker fetches one file at a
 * time so it holds at most one claim, which is why release needs no name. */
#define FOLDSTATE_MAX_CLAIMS 16

typedef struct {
    void    *owner;        /* claiming worker's Sync block; NULL = free slot */
    uint32_t name_hash;
} FolderClaim;

/* The CONTENT every worker still wants in this folder.
 *
 * A file about to be deleted may be the only local copy of content another
 * fetch is about to want - that is the whole reason a rename is cheap, and the
 * reason a peer's deletions are held back at all. The question "is this
 * content still wanted?" was being asked of one worker's own queue, but the
 * file it protects is on disk and shared with every worker. Measured on the
 * three-node rig: one worker's flush removed a source three seconds before the
 * other worker asked for it, and those files came over the wire.
 *
 * So the question is asked HERE, of the folder, by every worker.
 *
 * Keyed by a 32-bit fold of the content hash mixed with the size, for the same
 * reason FolderClaim keys by a name hash: a collision costs a deletion a little
 * more time on disk, never correctness. That asymmetry is what makes a folded
 * hash fine here and unacceptable for deciding to RENAME a source away, where a
 * collision would destroy a live file.
 *
 * Add-only within a busy period, cleared wholesale when a worker has nothing
 * left pending. That is deliberately an over-approximation: a content stays
 * "wanted" until its worker goes idle, even after the fetch that wanted it has
 * finished. It buys the one property that matters - no per-completion removal
 * to forget - and it only ever delays the deletion of content that was wanted
 * during this burst, which is precisely a rename's source. Deletions of
 * anything else still flow immediately, which is what a blanket "hold
 * everything while a transfer runs" rule could not do. */
#define FOLDSTATE_WANT_MAX  4096   /* per worker; past this, assume everything */

typedef struct {
    void     *owner;       /* owning worker's Sync block; NULL = free slot   */
    uint32_t *keys;        /* open-addressed table, [cap]; 0 = empty         */
    int       cap;         /* power of two, 0 until first use                */
    int       n;           /* live keys                                      */
    int       overflow;    /* hit the cap: answer "wanted" for anything      */
} FolderWantSet;

/* chg_verb values: the folder's most recent file change, Syncthing's "Latest
 * Change" (0 = none yet this run). Set by foldstate_upsert for live/deleted
 * FILE records (dirs and invalid entries don't count); never persisted - the
 * daemon zeroes it after replaying the stored index through upsert at load. */
#define FOLDSTATE_CHG_ADDED    1
#define FOLDSTATE_CHG_UPDATED  2
#define FOLDSTATE_CHG_DELETED  3

/* Counters kept inline in a stored record before it spills to an allocation.
 * Four covers a folder shared by four devices, which is already a large mesh
 * for this target; beyond that the record allocates and nothing breaks. */
#define FOLDREC_VIN  4

/* The STORED form of one record: every SyncMeta field except the name, which
 * lives in the parallel names[] as an owned string instead of a 256-byte array
 * inside every record.
 *
 * That array was 42% of a 616-byte SyncMeta and the index is the largest single
 * part of the daemon's footprint - measured at 45% of 6.3 MB on an A4000, 754
 * bytes a record. Amiga names are short (FFS caps a component at 30 characters),
 * so nearly all of those 256 bytes were padding on every file the user owns.
 *
 * The field NAMES are deliberately identical to SyncMeta's. foldstate_find
 * returns one of these, and every caller that reads or writes an individual
 * field - h->deleted, h->version, h->content_hash - compiles unchanged against
 * it. Only whole-record copies need converting, which is what foldstate_meta is
 * for. No caller has ever read ->name off a find result; that was checked
 * before this split, and the compile would catch it now if one started.
 *
 * Keep this list in step with SyncMeta. The assertion below is what enforces
 * it: add a field to one and not the other and the build stops here rather than
 * silently dropping it from every stored record. */
typedef struct {
    int64_t       size;
    uint32_t      permissions;
    int64_t       modified_s;
    int32_t       modified_ns;
    uint64_t      modified_by;
    int64_t       sequence;
    int32_t       block_size;
    /* The version vector, small-buffer style. A BepVector is 16 counters and
     * 264 bytes, and after the name came out that was 73% of a stored record -
     * while a real folder is shared by two to four devices, so one to four
     * counters are ever used.
     *
     * A smaller FIXED cap would have been one line and is the wrong answer: a
     * vector that overflows cannot record our counter, so our edit stops
     * dominating and quietly loses conflicts, and a peer sending more counters
     * than we store would be silently truncated - which corrupts the
     * comparison rather than just crowding it. Spilling has no such cliff.
     *
     * So: up to FOLDREC_VIN counters inline, and beyond that an allocation
     * ('vext', owned exactly like names[] and blocks[]). The common case never
     * allocates. nver is the true count either way. */
    int           nver;
    BepCounter    vin[FOLDREC_VIN];
    BepCounter   *vext;                 /* NULL while nver <= FOLDREC_VIN */
    unsigned char content_hash[BEP_HASH_LEN];
    unsigned char type;
    unsigned char deleted;
    unsigned char invalid;
    unsigned char has_content_hash;
} FolderRec;

/* Drift guard: see "roundtrip: every field survives" in test_foldstate.
 *
 * This was a sizeof() identity while exactly one field differed between the two
 * structs. With two differing - one of them replaced by members of a different
 * alignment - the arithmetic became padding-dependent and failed on the host for
 * a struct that was perfectly correct. A guard that cries wolf gets deleted, so
 * it was replaced rather than patched.
 *
 * The test is the stronger check anyway: it fills a zeroed SyncMeta with a
 * distinct value in every field, puts it through the index, brings it back and
 * memcmps the two. A field added to both structs but forgotten in
 * rec_from_meta/meta_from_rec comes back zero and fails - which no size
 * assertion could ever have caught. */

/* One configured folder's authoritative, shared index. Allocated by main, never
 * by a worker. All fields are guarded by 'lock'; touch them only between
 * foldstate_lock() and foldstate_unlock().
 *
 * The record table (files/blocks/nblocks/seen) is a grown allocation, not
 * inline: the four parallel arrays are each [cap] long with num_files used,
 * reallocated by doubling in foldstate_upsert. A grow MOVES the arrays, so a
 * SyncMeta* from foldstate_find is only valid until the next upsert - callers
 * already copy the value out under the lock (the documented discipline), so
 * this is safe.
 *
 * Block hashes: SyncMeta stays a lean value type (copied into the want queue, the
 * host tests and the 4b on-disk format), so the per-file block-hash lists live in
 * PARALLEL, owned arrays - blocks[i]/nblocks[i] go with files[i]. Storing them
 * here (once, in the single shared index) is what delivers the "hash once"
 * promise: a worker announces a file by copying these out, never re-reading the
 * file. */
typedef struct FolderState {
    char     folder_id[BEP_FOLDER_ID_MAX];  /* the configured folder id        */
    uint64_t short_id;                      /* our device short ID (vers. key) */
    int64_t  sequence;                      /* per-folder monotonic high-water */
    int64_t  prune_gen;                     /* bumped whenever a tombstone prune
                                             * swap-removes a record; lets a
                                             * concurrent announce pass detect
                                             * that a slot may have moved under
                                             * it even if num_files is unchanged */
    int      dirty;                         /* unsaved changes (persistence)  */
    /* When the scanner last finished a pass over this folder, as a DateStamp
     * (ds_Days/ds_Minute; both 0 = never scanned). Plain longs so the host
     * tests need no Amiga headers. For STATUS display. */
    long     scan_day;
    long     scan_min;
    /* Per-RUN identity of this index incarnation, advertised in our
     * ClusterConfig device entry (BEP Device.index_id). Set by the daemon at
     * folder creation, never persisted: we re-announce the full index on
     * every connection anyway, so a fresh id per run is the honest claim -
     * "discard what you stored, a full stream follows". What it must NOT do
     * is change between two CCs of one run (that reads as churn) or sit at
     * zero (a repeated CC with zeros reads as an index REGRESSION and makes
     * Syncthing doubt our newest records - seen live, the peer re-requesting
     * the whole index on every reconnect). */
    uint64_t index_id;
    /* Most recent file change (see FOLDSTATE_CHG_*): what the status report
     * shows as "latest change". Maintained by upsert; not persisted. */
    int      chg_verb;
    char     chg_name[BEP_PATH_MAX];
    int      num_files;
    int      cap;                           /* allocated length of the arrays  */
    FolderRec      *files;                  /* [cap], num_files used; grows     */
    char          **names;                  /* [cap], each owned; parallel to files
                                             * (see FolderRec) - NULL past num_files */
    unsigned char **blocks;                 /* [cap], each owned [nblocks][32]/NULL */
    int            *nblocks;                /* [cap], block count parallel to files */
    unsigned char  *seen;                   /* [cap], per-scan liveness mark; NOT
                                             * persisted (scanner mark-and-sweep) */
    /* Name-lookup index: chained hash over files[].name so find/upsert cost
     * O(1) instead of a linear scan - the scanner does several lookups per
     * file per pass, which went quadratic once folders stopped being capped.
     * hhead[cap] holds each bucket's first slot (-1 empty), hnext[cap] the
     * chain. Maintained incrementally on insert, rebuilt on grow and after a
     * prune compaction. Internal to foldstate.c; never persisted. */
    int            *hhead;
    int            *hnext;
#ifndef FOLDSTATE_HOST_TEST
    struct SignalSemaphore lock;            /* guards everything above         */
#endif
    /* Bumped whenever something on OUR side changes what we need from a peer
     * in a way that cannot be recomputed. A peer's Index is classified as it
     * arrives and then discarded, and BEP has no resend - so un-hiding a file,
     * or forgetting a record in a receive-only mirror, leaves us wanting
     * something we can no longer ask for. Workers snapshot this and, once
     * their queue has drained, close the session so the peer replays its
     * Index. Deliberately NOT persisted: it means "since this daemon started".
     */
    int64_t need_gen;
    /* Files currently being fetched, one slot per claiming worker. */
    FolderClaim claims[FOLDSTATE_MAX_CLAIMS];
    /* Content every worker still wants here; see FolderWantSet. */
    FolderWantSet wants[FOLDSTATE_MAX_CLAIMS];
} FolderState;

/* Initialise an (already-allocated, zeroed) FolderState for one folder. On the
 * Amiga build this also InitSemaphore()s the lock. Pure data otherwise. */
void foldstate_init(FolderState *fs, const char *folder_id, uint64_t short_id);

/* Free all owned memory: each slot's block-hash array AND the record table
 * itself (call at shutdown, after the scanner and all workers have stopped
 * writing). Leaves the struct empty but reusable - the next upsert re-grows the
 * table lazily, so it doubles as the "clear contents before reload" reset.
 * Does NOT lock: it is the shutdown/quiescent-slot form. */
void foldstate_free(FolderState *fs);

/* Re-key a slot IN USE for a (possibly different) folder: empty the index and
 * reset the sequence, identity and index_id, all under the slot's own lock and
 * WITHOUT touching the lock itself. This is what a runtime folder add must use
 * to resurrect a tombstoned slot - foldstate_init would InitSemaphore() a
 * semaphore a scanner or worker mid-pass may hold, and foldstate_free alone
 * would pull the record table out from under it. The scanner still checks the
 * folder's 'removed'/'gen' as it walks, so the re-key waits at most one file. */
void foldstate_reset(FolderState *fs, const char *folder_id, uint64_t short_id,
                     uint64_t index_id);

/* Look up a record by name, or NULL. Call under the lock. */
/* Take the fetch claim on 'name' for 'owner' (the worker's Sync block), so no
 * other peer's worker starts the same download. Returns 1 if the claim is ours
 * (already holding it counts), 0 if another owner has it or every slot is
 * taken - in both cases the caller should leave the file queued and come back
 * to it. Release with foldstate_unclaim, which drops whatever this owner
 * holds; a worker that exits without releasing leaves the file unfetchable
 * until the daemon restarts, so release on EVERY exit from a download. */
int  foldstate_claim(FolderState *fs, const char *name, void *owner);
void foldstate_unclaim(FolderState *fs, void *owner);

/* Note that 'owner' still wants content (hash, size) in this folder. Call it
 * wherever a file joins that worker's backlog - queued, parked on a spill, or
 * requeued. Cheap and idempotent. A full table stops recording and answers
 * "wanted" for everything from then on, which is the safe direction. */
void foldstate_want_add(FolderState *fs, void *owner,
                        const unsigned char *content_hash, int64_t size);

/* Does ANY worker still want this content? The question a deferred deletion
 * has to answer before it removes a file. */
int  foldstate_want_any(FolderState *fs,
                        const unsigned char *content_hash, int64_t size);

/* 'owner' has nothing pending any more: forget what it wanted. This is what
 * keeps the set from growing without bound, and it is the ONLY removal - there
 * is no per-file drop to forget to call. */
void foldstate_want_clear(FolderState *fs, void *owner);

/* 'owner' is going away: free its table and release the slot. */
void foldstate_want_release(FolderState *fs, void *owner);

/* Does NOBODY want anything here? True once every worker has gone idle and
 * cleared its set. This is what a bulk of parked deletions waits for: the
 * spill is a sequential file, so it is read and applied in one pass rather
 * than sifted per record, and the moment it is safe to do that is the moment
 * no content in this folder is spoken for. */
int  foldstate_want_idle(FolderState *fs);

FolderRec *foldstate_find(FolderState *fs, const char *name);

/* Inflate a record from foldstate_find back into a full SyncMeta, name and all.
 * Only whole-record copies need this; reading or writing one field goes through
 * the FolderRec directly. Caller holds the lock, as for find itself. */
void foldstate_meta(const FolderState *fs, const FolderRec *rec, SyncMeta *out);

/* The name of a record from foldstate_find; "" if it is not one of ours. Same
 * locking rule. */
const char *foldstate_name(const FolderState *fs, const FolderRec *rec);

/* A stored record's version vector, inflated into 'scratch'. Returns scratch,
 * or NULL when 'rec' is NULL - so the common
 *     sync_bump_version(&m.version, foldstate_version(fs, have, &v), ...)
 * reads the same whether or not a record already existed. */
const BepVector *foldstate_version(const FolderState *fs, const FolderRec *rec,
                                   BepVector *scratch);

/* Counters currently stored for a record (0 if none). Cheaper than inflating
 * the whole vector when all the caller needs is the count. */
int foldstate_version_count(const FolderRec *rec);

/* Replace a stored record's version in place - the adopt path, which takes the
 * peer's vector onto a record it is otherwise leaving alone. Frees whatever the
 * record held. Caller holds the lock. */
void foldstate_set_version(FolderState *fs, FolderRec *rec, const BepVector *v);

/* Copy out a record's block hashes (up to 'cap' of them) into 'out', returning
 * the number copied; *total (if non-NULL) gets the file's full block count. 0 if
 * the file is unknown or has no stored blocks. Call under the lock and copy
 * before releasing it - the stored array can be freed by the next upsert. */
int foldstate_blocks(FolderState *fs, const char *name,
                     unsigned char (*out)[BEP_HASH_LEN], int cap, int *total);

/* Insert or replace the record for meta->name (matched by name), taking a COPY
 * of its 'nblocks' block hashes ('hashes' may be NULL / nblocks 0 for dirs and
 * tombstones; any previously-stored blocks for the name are freed). Returns 1 on
 * success, 0 if the index is full and a new entry could not be added. Replacing
 * an existing record never fails. Call under the lock. */
int foldstate_upsert(FolderState *fs, const SyncMeta *meta,
                     const unsigned char (*hashes)[BEP_HASH_LEN], int nblocks);

/* Allocate the next per-folder sequence number (pre-increment) and mark dirty.
 * Call under the lock. */
int64_t foldstate_next_seq(FolderState *fs);

/* The scanner's mark-and-sweep deletion pass: clear_seen zeroes every record's
 * 'seen' mark at the start of a scan; mark_seen sets the mark on the record for
 * 'name' (a no-op if there is none). After a COMPLETE walk of the folder, a
 * live record still unmarked has no file behind it and can be tombstoned -
 * subject to the scanner's sequence guard for records added mid-scan. The marks
 * are scan-pass scratch: parallel to files[], never persisted. Call both under
 * the lock. */
void foldstate_clear_seen(FolderState *fs);
void foldstate_mark_seen(FolderState *fs, const char *name);

/* Drop deleted records (tombstones) older than 'cutoff' (Unix seconds), freeing
 * their block arrays and compacting the table; returns the number removed. The
 * sequence high-water is left unchanged. Call under the lock. */
int foldstate_prune_tombstones(FolderState *fs, int64_t cutoff);

/* Forget a record outright - NOT a tombstone. Nothing is announced and no
 * deletion is implied: the row simply stops existing, so the next Index a peer
 * sends classifies that file as one we do not have and fetches it. This is how
 * a receive-only folder stays a mirror: local edits and deletions there are not
 * the truth, and recording them as ours would mask the peer's copy for good.
 * Returns 1 if a record was removed. */
/* Note that what we need from peers has changed under us (see need_gen), and
 * read it back. Both lock internally, so call them outside a held lock. */
void    foldstate_need_changed(FolderState *fs);
int64_t foldstate_need_gen(FolderState *fs);

int foldstate_forget(FolderState *fs, const char *name);

/* The receive-only counterpart of the scanner's deletion sweep: every record
 * the walk did not see is FORGOTTEN instead of tombstoned, under the same
 * guards (a tombstone, an 'invalid' placeholder or a record newer than the
 * walk is left alone). Deleting a file inside a mirror is not a change to
 * propagate - it is a copy to fetch again. Returns the number removed. */
int foldstate_forget_unseen(FolderState *fs, int64_t before);

#ifndef FOLDSTATE_HOST_TEST
/* Critical-section bracket. Obtain before reading/writing any field, release as
 * soon as the pure memory work is done - never hold across hashing or file I/O.
 * Exclusive (single-writer) is enough; we do not distinguish read/write yet. */
void foldstate_lock(FolderState *fs);
void foldstate_unlock(FolderState *fs);
#endif

#endif /* AMISYNC_FOLDSTATE_H */
