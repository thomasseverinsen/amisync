/* syncmodel.h - pure sync decision logic for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The decisions that drive two-way sync - what to fetch, what to delete, what
 * counts as a local change, how the version/sequence bookkeeping works - are
 * the trickiest and most bug-prone part of the daemon, yet they are pure: they
 * depend only on FileInfo/Config data, not on AmiSSL, sockets or the file
 * system. This module isolates them so they can be unit-checked on the build
 * host (tests/test_syncmodel.c) with a fast edit/run loop, while the worker
 * keeps the actual I/O (folder reads/writes, BEP sends).
 *
 * The authoritative index (records, versions, per-folder sequence)
 * moved to the shared FolderState (foldstate.h); what stays here is the
 * per-connection state the worker still owns - the queue of files we want to
 * pull - plus the pure helpers that decide what to do with a peer's FileInfo
 * (classify, content-compare, version bookkeeping, tombstones).
 */

#ifndef AMISYNC_SYNCMODEL_H
#define AMISYNC_SYNCMODEL_H

#include "bep.h"
#include "config.h"

/* The daemon's largest fixed commitment, and it is PER WORKER - a SyncModel
 * lives in every connection's Sync block. want[] embeds a whole SyncMeta each,
 * so the two together are most of a quarter megabyte per peer. Fixed pools
 * (no allocation on the receive path) are the right discipline for this
 * target; SYNC_MAX_WANT is the dial if that trade needs revisiting. */
#define SYNC_MAX_WANT  256   /* queued downloads; ~160 KB of WantFile         */
#define SYNC_HASH_POOL 2048  /* block-hash slots shared by the want stack (64 KB) */

/* Lean persistent metadata for one file: everything we keep about it EXCEPT its
 * block list. Block geometry is derived (offset = i*block_size); the only piece
 * we cannot re-derive - the per-block hashes - is held transiently for queued
 * (want) and in-flight downloads, never here. content_hash is the file's
 * "blocksHash" (SHA-256 over its concatenated block hashes): the peer's
 * authoritative fingerprint when set from a received FileInfo, ours when folded
 * on scan. It is what sync_content_same compares, so we no longer store blocks
 * just to tell whether two copies match. The field names mirror BepFileInfo so
 * the worker can read t->fi.name, t->fi.size, ... unchanged. */
typedef struct {
    char          name[BEP_PATH_MAX];
    int64_t       size;
    uint32_t      permissions;
    int64_t       modified_s;
    int32_t       modified_ns;
    uint64_t      modified_by;       /* short device ID of the last modifier */
    int64_t       sequence;
    int32_t       block_size;
    BepVector     version;
    unsigned char content_hash[BEP_HASH_LEN];
    /* Grouped, and unsigned char rather than int: this is the one type whose
     * count scales with the user's file count (FolderState.files[] holds up to
     * FOLDSTATE_MAX_FILES of them), so 12 bytes a record is real memory here.
     * 'type' is a BEP_FILE_* value; the other three are 0/1. The on-disk
     * format is unaffected - index_store converts field by field. */
    unsigned char type;
    unsigned char deleted;
    unsigned char invalid;
    unsigned char has_content_hash;
} SyncMeta;

/* A queued download: lean metadata plus a reference into the shared block-hash
 * pool (the expected per-block hashes captured from the peer's FileInfo).
 * 'conflict' marks a concurrent-edit loser: before fetching, the worker
 * preserves the existing local copy under a conflict name. */
typedef struct {
    int      folder_idx;
    SyncMeta fi;
    int      hash_off;          /* start index into SyncModel.want_hashes */
    int      num_blocks;        /* block hashes stored for this file      */
    int      conflict;          /* rename local aside before this fetch   */
    int      attempts;          /* fetches of this file already abandoned */
} WantFile;

typedef struct {
    int      num_want;
    int      hash_used;         /* high-water mark of want_hashes (LIFO)     */
    WantFile want[SYNC_MAX_WANT];
    /* Block-hash pool, used as a LIFO stack mirroring want[]: pushing a wanted
     * file appends its hashes, popping it frees them from the top. Cheap for the
     * common small file (one hash) and bounded for large ones. */
    unsigned char want_hashes[SYNC_HASH_POOL][BEP_HASH_LEN];
} SyncModel;

/* What to do with a peer's FileInfo. */
typedef enum {
    SYNC_IGNORE,                /* already have it / ours wins / not for us  */
    SYNC_FETCH,                 /* pull it (caller enqueues + downloads)     */
    SYNC_DELETE,                /* remove our local copy (peer deleted it)   */
    SYNC_ADOPT,                 /* identical content, and either the peer's
                                 * version dominates (e.g. our index was
                                 * rebuilt by a folder remove/re-add) or the
                                 * versions are EQUAL with differing metadata:
                                 * take the peer's record - vector, mtime,
                                 * perms - and stamp the disk; no transfer.
                                 * Without this the peer counts us out of
                                 * sync forever                              */
    SYNC_CONFLICT               /* concurrent edit, peer's copy wins: caller
                                 * preserves ours under a conflict name, then
                                 * fetches theirs (enqueue like SYNC_FETCH)  */
} SyncAction;

/* How two version vectors relate. A vector "dominates" when every counter is
 * >= the other's (missing counters count as 0) and at least one is greater. */
typedef enum {
    SYNC_V_EQUAL,               /* identical                                 */
    SYNC_V_OURS,                /* ours dominates: our copy is newer         */
    SYNC_V_THEIRS,              /* theirs dominates: their copy is newer     */
    SYNC_V_CONCURRENT           /* neither dominates: concurrent edits       */
} SyncVerRel;

/* Reset the want queue (the only per-connection state the model still holds). */
void sync_init(SyncModel *m);

/* First 8 bytes of the raw device key, big-endian, as Syncthing's short ID. The
 * version-counter key now lives in FolderState; this is used by the daemon to
 * derive it once for the shared index. */
uint64_t sync_short_id_from_raw(const unsigned char raw[32]);

/* Index of the configured folder with this id, or -1. */
int sync_folder_index(const Config *cfg, const char *id);

/* True if our stored copy and a peer FileInfo have identical content: same size
 * and same content_hash (both must have one). */
int sync_content_same(const SyncMeta *have, const BepFileInfo *peer);

/* Fill 'fi' with a deletion tombstone for 'name' of the given type
 * (BEP_FILE_FILE or BEP_FILE_DIRECTORY). */
void sync_make_tombstone(BepFileInfo *fi, const char *name, int type,
                         uint64_t short_id, int64_t when, int64_t seq);

/* Produce the version vector for a local change we are about to announce: start
 * from 'prev' (the file's existing version, or NULL for a brand-new file),
 * preserve every other device's counter, and set ours (short_id) to 'value' -
 * forced strictly above any previous value of ours. Carrying the other devices'
 * counters forward is what makes a re-add/edit DOMINATE the peer's prior version
 * (e.g. its deletion tombstone) instead of looking concurrent. */
void sync_bump_version(BepVector *out, const BepVector *prev,
                       uint64_t short_id, uint64_t value);

/* Compare our version vector against a peer's. */
SyncVerRel sync_version_compare(const BepVector *ours, const BepVector *theirs);

/* 1 if 'v' carries a non-zero counter for device 'id' - that device modified
 * this file at some point in its history. A record whose vector has no counter
 * of ours is one we hold exactly as a peer produced it, which is what lets a
 * receive-only folder announce what it mirrors without claiming authorship. */
int sync_version_has(const BepVector *v, uint64_t id);

/* Decide what to do with a peer's FileInfo for a folder of the given mode. Pure
 * (no mutation): considers only our stored record 'have' (NULL if we have no
 * record for this name, e.g. looked up in FolderState). Version vectors decide
 * when both sides carry one; the last-writer (mtime) rule is the fallback.
 * Concurrent edits resolve Syncthing-style - a modification beats a deletion,
 * and between two live copies the newer mtime wins (ties: modified_ns, then
 * content_hash) - returning SYNC_CONFLICT when the peer's copy wins so the
 * caller preserves ours first. Caller skips invalid / non-file entries. */
SyncAction sync_classify_incoming(const SyncMeta *have, FolderMode mode,
                                  const BepFileInfo *peer);

/* Build the conflict-copy name for 'name': the suffix is inserted before the
 * extension, Syncthing-style - "dir/a.txt" becomes
 * "dir/a.sync-conflict-20260717-123456-TAG.txt" ('tag' is our device ID's
 * 7-char prefix). 'compact' selects a short ".cnfl-HHMMSS" suffix instead, for
 * filesystems with tight name limits (FFS). 'now_s' is unix UTC seconds.
 * Returns 1, or 0 if the result would not fit 'cap'. */
int sync_make_conflict_name(char *out, int cap, const char *name,
                            int64_t now_s, const char *tag, int compact);

/* Wanted-queue management (LIFO). push stores the file's metadata plus its
 * 'num_blocks' expected block hashes in the pool; returns 1, or 0 if the queue
 * or the hash pool is full (caller defers - the file is re-offered later). has
 * reports membership by name (dedup). pop takes the most recent entry, copying
 * its block hashes into 'hashes_out' (up to 'cap' of them) and freeing the pool
 * space; returns 1, or 0 if empty. 'has' reports membership by (folder, name),
 * not by name alone - two folders may legitimately hold the same relative
 * path, and deduping across them would drop a wanted file.
 *
 * push_again is push for a fetch that already failed once: it carries the
 * file's attempt count forward so the worker can re-queue a torn transfer
 * without retrying a genuinely broken one for ever. A newly offered file
 * always starts at 0 attempts, which is what plain push records. */
int sync_want_push(SyncModel *m, int folder_idx, const BepFileInfo *meta,
                   const unsigned char (*hashes)[BEP_HASH_LEN], int num_blocks,
                   int conflict);
int sync_want_push_again(SyncModel *m, int folder_idx, const BepFileInfo *meta,
                         const unsigned char (*hashes)[BEP_HASH_LEN],
                         int num_blocks, int conflict, int attempts);
int sync_want_has(const SyncModel *m, int folder_idx, const char *name);
/* Identify the entry pop would take next without removing it (and without
 * copying its block hashes, which is the expensive part). Lets the caller
 * decide whether it may fetch that file before committing to the pop.
 * Returns 1, or 0 if the queue is empty. */
int sync_want_peek(const SyncModel *m, int *folder_idx, char *name, int cap);
int sync_want_pop(SyncModel *m, WantFile *out,
                  unsigned char (*hashes_out)[BEP_HASH_LEN], int cap);

#endif /* AMISYNC_SYNCMODEL_H */
