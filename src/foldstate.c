/* foldstate.c - shared, semaphore-guarded per-folder index for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See foldstate.h. The find/upsert/next_seq core is pure memory work, mirroring
 * the per-peer helpers it replaces in syncmodel.c (sync_local_find /
 * sync_local_upsert / sync_next_seq), so it is host-tested. The per-file
 * block-hash arrays are owned here (AllocVec on Amiga, malloc under the host
 * test). The lock/unlock wrappers and the SignalSemaphore init are Amiga-only.
 */

#include <string.h>

#include "foldstate.h"

#ifdef FOLDSTATE_HOST_TEST
#include <stdlib.h>
#define FS_ALLOC(n)  malloc((size_t)(n))
#define FS_FREE(p)   free(p)
#define FS_LOCK(fs)    ((void)0)   /* single-threaded under the host tests */
#define FS_UNLOCK(fs)  ((void)0)
#else
#include <exec/memory.h>
#include <proto/exec.h>
#define FS_ALLOC(n)  AllocVec((ULONG)(n), MEMF_ANY)
#define FS_FREE(p)   FreeVec(p)
#define FS_LOCK(fs)    ObtainSemaphore(&(fs)->lock)
#define FS_UNLOCK(fs)  ReleaseSemaphore(&(fs)->lock)
#endif

void foldstate_init(FolderState *fs, const char *folder_id, uint64_t short_id)
{
    memset(fs, 0, sizeof(*fs));   /* cap 0, arrays NULL: the table is
                                   * allocated lazily on the first upsert */
    strncpy(fs->folder_id, folder_id, BEP_FOLDER_ID_MAX - 1);
    fs->folder_id[BEP_FOLDER_ID_MAX - 1] = '\0';
    fs->short_id = short_id;
#ifndef FOLDSTATE_HOST_TEST
    InitSemaphore(&fs->lock);
#endif
}

/* Free the six parallel arrays (not the per-record block lists). Shared by
 * foldstate_free and ensure_cap so a seventh array cannot be freed in one and
 * leaked in the other; the pointers are left dangling for the caller to
 * reassign or null. */
static void free_version(FolderRec *r);

static void free_arrays(FolderState *fs)
{
    if (fs->files)   FS_FREE(fs->files);
    if (fs->names)   FS_FREE(fs->names);   /* the array; strings are the
                                            * caller's, as for blocks[] */
    if (fs->blocks)  FS_FREE(fs->blocks);
    if (fs->nblocks) FS_FREE(fs->nblocks);
    if (fs->seen)    FS_FREE(fs->seen);
    if (fs->hhead)   FS_FREE(fs->hhead);
    if (fs->hnext)   FS_FREE(fs->hnext);
}

void foldstate_free(FolderState *fs)
{
    int i;
    for (i = 0; i < fs->num_files; i++) {
        if (fs->blocks[i])
            FS_FREE(fs->blocks[i]);
        if (fs->names && fs->names[i])
            FS_FREE(fs->names[i]);
        free_version(&fs->files[i]);
    }
    free_arrays(fs);
    fs->files     = NULL;
    fs->names     = NULL;
    fs->blocks    = NULL;
    fs->nblocks   = NULL;
    fs->seen      = NULL;
    fs->hhead     = NULL;
    fs->hnext     = NULL;
    fs->cap       = 0;
    fs->num_files = 0;
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++) {   /* wanted-content tables */
        if (fs->wants[i].keys)
            FS_FREE(fs->wants[i].keys);
        fs->wants[i].keys     = NULL;
        fs->wants[i].cap      = 0;
        fs->wants[i].n        = 0;
        fs->wants[i].overflow = 0;
        fs->wants[i].owner    = NULL;
    }
    /* Per-folder display state goes with the records it described: without
     * this a "latest change" or last-scan stamp survives a reload and is
     * reported against an index that no longer contains the file. */
    fs->chg_verb    = 0;
    fs->chg_name[0] = '\0';
    fs->scan_day    = 0;
    fs->scan_min    = 0;
}

void foldstate_reset(FolderState *fs, const char *folder_id, uint64_t short_id,
                     uint64_t index_id)
{
    FS_LOCK(fs);
    foldstate_free(fs);        /* records, block arrays and display state */
    /* The rest of what foldstate_init would zero. NOT a memset: the lock we
     * are holding lives in this struct, and re-initialising a semaphore that
     * another task owns (or is queued on) corrupts it - that task's release
     * then unlinks from a wait queue that has been zeroed under it. */
    fs->sequence  = 0;
    fs->prune_gen = 0;
    fs->dirty     = 0;
    fs->index_id  = index_id;
    strncpy(fs->folder_id, folder_id, BEP_FOLDER_ID_MAX - 1);
    fs->folder_id[BEP_FOLDER_ID_MAX - 1] = '\0';
    fs->short_id = short_id;
    memset(fs->claims, 0, sizeof(fs->claims));   /* a new folder owes nobody */
    FS_UNLOCK(fs);
}

/* ---- name-lookup hash (see foldstate.h) ------------------------------- */

/* 32-bit FNV-1a of a record name. uint32_t keeps the wrap identical on the
 * 68k build and the 64-bit host tests. */
static uint32_t name_hash(const char *s)
{
    uint32_t h = 2166136261UL;
    while (*s)
        h = (h ^ (uint32_t)(unsigned char)*s++) * 16777619UL;
    return h;
}

int foldstate_claim(FolderState *fs, const char *name, void *owner)
{
    uint32_t h = name_hash(name);
    int      i, slot = -1, ok = 0;

    FS_LOCK(fs);
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++) {
        if (!fs->claims[i].owner) {
            if (slot < 0)
                slot = i;                  /* remember the first free one */
        } else if (fs->claims[i].name_hash == h) {
            ok   = (fs->claims[i].owner == owner);   /* ours already: idempotent */
            slot = -1;                     /* held - do not hand out a second */
            break;
        }
    }
    if (slot >= 0) {
        fs->claims[slot].owner     = owner;
        fs->claims[slot].name_hash = h;
        ok = 1;
    }
    FS_UNLOCK(fs);
    return ok;
}

void foldstate_unclaim(FolderState *fs, void *owner)
{
    int i;

    FS_LOCK(fs);
    /* Every slot, not the first match: a leaked claim from an earlier download
     * would otherwise pin a file for the life of the daemon. */
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++)
        if (fs->claims[i].owner == owner)
            fs->claims[i].owner = NULL;
    FS_UNLOCK(fs);
}

/* ---- wanted content ---------------------------------------------------- */

/* One key from a content hash and a size. The size is mixed in because two
 * different files sharing a folded hash is likelier than two sharing both, and
 * the caller already has it. Never returns 0 - that value marks an empty slot. */
static uint32_t want_key(const unsigned char *content_hash, int64_t size)
{
    uint32_t h = 2166136261UL;
    int      i;

    for (i = 0; i < BEP_HASH_LEN; i++)
        h = (h ^ (uint32_t)content_hash[i]) * 16777619UL;
    h = (h ^ (uint32_t)(size & 0xffffffffL)) * 16777619UL;
    h = (h ^ (uint32_t)((size >> 32) & 0xffffffffL)) * 16777619UL;
    return h ? h : 1u;
}

/* Find this owner's set, or claim a free slot for it. NULL if none is free -
 * the caller then treats the folder as "everything is wanted", which is the
 * safe direction. Caller holds the lock. */
static FolderWantSet *want_set(FolderState *fs, void *owner)
{
    int i, free_slot = -1;

    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++) {
        if (fs->wants[i].owner == owner)
            return &fs->wants[i];
        if (!fs->wants[i].owner && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        return NULL;
    fs->wants[free_slot].owner    = owner;
    fs->wants[free_slot].n        = 0;
    fs->wants[free_slot].overflow = 0;
    return &fs->wants[free_slot];
}

/* Insert into an open-addressed table; caller guarantees room. */
static void want_put(FolderWantSet *w, uint32_t key)
{
    int mask = w->cap - 1;
    int i    = (int)(key & (uint32_t)mask);

    while (w->keys[i]) {
        if (w->keys[i] == key)
            return;                        /* already there */
        i = (i + 1) & mask;
    }
    w->keys[i] = key;
    w->n++;
}

/* Grow (or create) the table so another key fits with room to spare. Load is
 * kept under half so probes stay short. 0 if the memory is not there. */
static int want_grow(FolderWantSet *w)
{
    int       newcap = w->cap ? w->cap * 2 : 64;
    uint32_t *old    = w->keys;
    int       oldcap = w->cap, i;

    if (newcap > FOLDSTATE_WANT_MAX * 2)
        return 0;
    w->keys = (uint32_t *)FS_ALLOC((size_t)newcap * sizeof(uint32_t));
    if (!w->keys) {
        w->keys = old;
        return 0;
    }
    for (i = 0; i < newcap; i++)
        w->keys[i] = 0;
    w->cap = newcap;
    w->n   = 0;
    for (i = 0; i < oldcap; i++)          /* rehash what was there */
        if (old[i])
            want_put(w, old[i]);
    if (old)
        FS_FREE(old);
    return 1;
}

void foldstate_want_add(FolderState *fs, void *owner,
                        const unsigned char *content_hash, int64_t size)
{
    FolderWantSet *w;

    if (!fs || !content_hash)
        return;
    FS_LOCK(fs);
    w = want_set(fs, owner);
    if (w && !w->overflow) {
        if (w->n * 2 >= w->cap && !want_grow(w))
            w->overflow = 1;               /* out of room or out of memory */
        if (!w->overflow)
            want_put(w, want_key(content_hash, size));
    }
    FS_UNLOCK(fs);
}

int foldstate_want_any(FolderState *fs,
                       const unsigned char *content_hash, int64_t size)
{
    uint32_t key;
    int      i, found = 0;

    if (!fs || !content_hash)
        return 0;
    key = want_key(content_hash, size);
    FS_LOCK(fs);
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS && !found; i++) {
        FolderWantSet *w = &fs->wants[i];
        int            mask, j;

        if (!w->owner)
            continue;
        if (w->overflow) {                 /* stopped recording: assume yes */
            found = 1;
            break;
        }
        if (!w->cap)
            continue;
        mask = w->cap - 1;
        j    = (int)(key & (uint32_t)mask);
        while (w->keys[j]) {
            if (w->keys[j] == key) {
                found = 1;
                break;
            }
            j = (j + 1) & mask;
        }
    }
    FS_UNLOCK(fs);
    return found;
}

void foldstate_want_clear(FolderState *fs, void *owner)
{
    FolderWantSet *w;
    int            i;

    if (!fs)
        return;
    FS_LOCK(fs);
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++) {
        w = &fs->wants[i];
        if (w->owner != owner)
            continue;
        /* The table is kept, only emptied: a worker that goes idle and busy
         * again would otherwise pay for the allocation every time. */
        if (w->keys && w->cap) {
            int k;
            for (k = 0; k < w->cap; k++)
                w->keys[k] = 0;
        }
        w->n        = 0;
        w->overflow = 0;
    }
    FS_UNLOCK(fs);
}

int foldstate_want_idle(FolderState *fs)
{
    int i, idle = 1;

    if (!fs)
        return 1;
    FS_LOCK(fs);
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++)
        if (fs->wants[i].owner && (fs->wants[i].n > 0 || fs->wants[i].overflow)) {
            idle = 0;
            break;
        }
    FS_UNLOCK(fs);
    return idle;
}

void foldstate_want_release(FolderState *fs, void *owner)
{
    int i;

    if (!fs)
        return;
    FS_LOCK(fs);
    for (i = 0; i < FOLDSTATE_MAX_CLAIMS; i++) {
        FolderWantSet *w = &fs->wants[i];
        if (w->owner != owner)
            continue;
        if (w->keys)
            FS_FREE(w->keys);
        w->keys     = NULL;
        w->cap      = 0;
        w->n        = 0;
        w->overflow = 0;
        w->owner    = NULL;                /* last: frees the slot for reuse */
    }
    FS_UNLOCK(fs);
}

/* Link slot i at the front of its bucket's chain. */
static void hash_link(FolderState *fs, int i)
{
    uint32_t b = name_hash(fs->names[i]) % (uint32_t)fs->cap;
    fs->hnext[i] = fs->hhead[b];
    fs->hhead[b] = i;
}

/* Rebuild the whole index: after a grow (the bucket count is the table cap,
 * so every hash re-buckets) and after a prune compaction (swap-remove moves
 * slots, which a chain fix-up could track but a rebuild gets right trivially -
 * both callers already touch every record anyway). */
static void hash_rebuild(FolderState *fs)
{
    int i;
    for (i = 0; i < fs->cap; i++)
        fs->hhead[i] = -1;
    for (i = 0; i < fs->num_files; i++)
        hash_link(fs, i);
}

/* Ensure the record table can hold at least 'need' entries, doubling it (from
 * FOLDSTATE_INIT_FILES) when it must grow. Returns 1 on success, 0 if a fresh
 * entry would exceed FOLDSTATE_MAX_FILES or the allocation failed - in both
 * cases the table is left untouched and the caller treats it as "index full".
 * A grow moves the four data arrays and rebuilds the two hash arrays; see
 * foldstate.h on why moving them is safe. */
static int ensure_cap(FolderState *fs, int need)
{
    int             newcap;
    FolderRec      *nf;
    char          **nm;
    unsigned char **nb;
    int            *nn;
    unsigned char  *ns;
    int            *nh, *nx;

    if (need <= fs->cap)
        return 1;
    if (need > FOLDSTATE_MAX_FILES)
        return 0;

    newcap = fs->cap ? fs->cap : FOLDSTATE_INIT_FILES;
    while (newcap < need)
        newcap *= 2;
    if (newcap > FOLDSTATE_MAX_FILES)
        newcap = FOLDSTATE_MAX_FILES;

    nf = FS_ALLOC((size_t)newcap * sizeof(*nf));
    nm = FS_ALLOC((size_t)newcap * sizeof(*nm));
    nb = FS_ALLOC((size_t)newcap * sizeof(*nb));
    nn = FS_ALLOC((size_t)newcap * sizeof(*nn));
    ns = FS_ALLOC((size_t)newcap * sizeof(*ns));
    nh = FS_ALLOC((size_t)newcap * sizeof(*nh));
    nx = FS_ALLOC((size_t)newcap * sizeof(*nx));
    if (!nf || !nm || !nb || !nn || !ns || !nh || !nx) {
        if (nf) FS_FREE(nf);
        if (nm) FS_FREE(nm);
        if (nb) FS_FREE(nb);
        if (nn) FS_FREE(nn);
        if (ns) FS_FREE(ns);
        if (nh) FS_FREE(nh);
        if (nx) FS_FREE(nx);
        return 0;
    }

    /* The name pointers move with their records - the strings themselves are
     * not reallocated, so ownership simply transfers to the new array. */
    memset(nm, 0, (size_t)newcap * sizeof(*nm));
    if (fs->num_files > 0) {
        memcpy(nf, fs->files,   (size_t)fs->num_files * sizeof(*nf));
        memcpy(nm, fs->names,   (size_t)fs->num_files * sizeof(*nm));
        memcpy(nb, fs->blocks,  (size_t)fs->num_files * sizeof(*nb));
        memcpy(nn, fs->nblocks, (size_t)fs->num_files * sizeof(*nn));
        memcpy(ns, fs->seen,    (size_t)fs->num_files * sizeof(*ns));
    }
    free_arrays(fs);
    fs->files   = nf;
    fs->names   = nm;
    fs->blocks  = nb;
    fs->nblocks = nn;
    fs->seen    = ns;
    fs->hhead   = nh;
    fs->hnext   = nx;
    fs->cap     = newcap;
    hash_rebuild(fs);          /* bucket count follows cap: re-bucket all */
    return 1;
}

/* Index of the slot for 'name', or -1 (hash bucket walk; strcmp confirms). */
/* ---- record <-> SyncMeta, and the owned name ------------------------- */

/* Release a record's spilled counters, if any. Safe on a fresh or already
 * released record; leaves it holding nothing rather than a stale pointer. */
static void free_version(FolderRec *r)
{
    if (r->vext) {
        FS_FREE(r->vext);
        r->vext = NULL;
    }
    r->nver = 0;
}

/* Store 'v' in 'r'. Falls back to inline-only on an allocation failure, which
 * truncates rather than losing the record - the same choice sync_bump_version
 * makes when a vector is full, and preferable to failing an upsert that has
 * already changed the file on disk. */
static void set_version(FolderRec *r, const BepVector *v)
{
    int n = v->num_counters;

    free_version(r);
    if (n <= 0)
        return;
    if (n > BEP_MAX_COUNTERS)
        n = BEP_MAX_COUNTERS;
    if (n > FOLDREC_VIN) {
        r->vext = FS_ALLOC((size_t)n * sizeof(BepCounter));
        if (!r->vext)
            n = FOLDREC_VIN;
    }
    memcpy(r->vext ? r->vext : r->vin, v->counters,
           (size_t)n * sizeof(BepCounter));
    r->nver = n;
}

static void get_version(const FolderRec *r, BepVector *out)
{
    int n = r->nver;

    memset(out, 0, sizeof(*out));
    if (n <= 0)
        return;
    if (n > BEP_MAX_COUNTERS)
        n = BEP_MAX_COUNTERS;
    memcpy(out->counters, r->vext ? r->vext : r->vin,
           (size_t)n * sizeof(BepCounter));
    out->num_counters = n;
}

/* The ONE place the two field lists meet. If the compile stopped at the
 * assertion in foldstate.h, a field was added to SyncMeta and belongs here too. */
static void rec_from_meta(FolderRec *r, const SyncMeta *m)
{
    r->size             = m->size;
    r->permissions      = m->permissions;
    r->modified_s       = m->modified_s;
    r->modified_ns      = m->modified_ns;
    r->modified_by      = m->modified_by;
    r->sequence         = m->sequence;
    r->block_size       = m->block_size;
    set_version(r, &m->version);
    memcpy(r->content_hash, m->content_hash, BEP_HASH_LEN);
    r->type             = m->type;
    r->deleted          = m->deleted;
    r->invalid          = m->invalid;
    r->has_content_hash = m->has_content_hash;
}

static void meta_from_rec(SyncMeta *m, const FolderRec *r, const char *name)
{
    size_t n;

    /* Bounded copy done here rather than with the daemon's scopy: this file is
     * built for the host tests too, and must not reach outside itself. */
    if (!name)
        name = "";
    n = strlen(name);
    if (n >= sizeof(m->name))
        n = sizeof(m->name) - 1;
    memcpy(m->name, name, n);
    m->name[n] = '\0';
    m->size             = r->size;
    m->permissions      = r->permissions;
    m->modified_s       = r->modified_s;
    m->modified_ns      = r->modified_ns;
    m->modified_by      = r->modified_by;
    m->sequence         = r->sequence;
    m->block_size       = r->block_size;
    get_version(r, &m->version);
    memcpy(m->content_hash, r->content_hash, BEP_HASH_LEN);
    m->type             = r->type;
    m->deleted          = r->deleted;
    m->invalid          = r->invalid;
    m->has_content_hash = r->has_content_hash;
}

/* Slot index of a record from foldstate_find, or -1 if it is not ours. Pointer
 * arithmetic into files[] rather than a search: the caller just got it from us
 * and holds the lock, so it cannot have moved. */
static int rec_slot(const FolderState *fs, const FolderRec *rec)
{
    long i;
    if (!fs || !rec || !fs->files)
        return -1;
    i = (long)(rec - fs->files);
    return (i >= 0 && i < fs->num_files) ? (int)i : -1;
}

const char *foldstate_name(const FolderState *fs, const FolderRec *rec)
{
    int i = rec_slot(fs, rec);
    return (i >= 0 && fs->names && fs->names[i]) ? fs->names[i] : "";
}

const BepVector *foldstate_version(const FolderState *fs, const FolderRec *rec,
                                  BepVector *scratch)
{
    (void)fs;
    if (!rec || !scratch)
        return NULL;
    get_version(rec, scratch);
    return scratch;
}

int foldstate_version_count(const FolderRec *rec)
{
    return rec ? rec->nver : 0;
}

void foldstate_set_version(FolderState *fs, FolderRec *rec, const BepVector *v)
{
    if (!rec || !v)
        return;
    set_version(rec, v);
    if (fs)
        fs->dirty = 1;
}

void foldstate_meta(const FolderState *fs, const FolderRec *rec, SyncMeta *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (rec)
        meta_from_rec(out, rec, foldstate_name(fs, rec));
}

/* Replace slot i's owned name. Frees the old one first, so it is safe on a
 * live slot as well as a fresh one. Returns 0 if the copy could not be made,
 * leaving the slot without a name rather than with the wrong one. */
static int set_name(FolderState *fs, int i, const char *name)
{
    size_t n = strlen(name) + 1;
    char  *p = FS_ALLOC(n);

    if (!p)
        return 0;
    memcpy(p, name, n);
    if (fs->names[i])
        FS_FREE(fs->names[i]);
    fs->names[i] = p;
    return 1;
}

static int find_slot(FolderState *fs, const char *name)
{
    int i;
    if (fs->cap == 0)
        return -1;                     /* table not allocated yet */
    i = fs->hhead[name_hash(name) % (uint32_t)fs->cap];
    for (; i >= 0; i = fs->hnext[i])
        if (fs->names[i] && strcmp(fs->names[i], name) == 0)
            return i;
    return -1;
}

FolderRec *foldstate_find(FolderState *fs, const char *name)
{
    int i = find_slot(fs, name);
    return i < 0 ? NULL : &fs->files[i];
}

int foldstate_blocks(FolderState *fs, const char *name,
                     unsigned char (*out)[BEP_HASH_LEN], int cap, int *total)
{
    int i = find_slot(fs, name);
    int n;

    if (total)
        *total = (i >= 0) ? fs->nblocks[i] : 0;
    if (i < 0 || !fs->blocks[i] || fs->nblocks[i] <= 0)
        return 0;

    n = fs->nblocks[i] < cap ? fs->nblocks[i] : cap;
    if (n > 0 && out)
        memcpy(out, fs->blocks[i], (size_t)n * BEP_HASH_LEN);
    return n;
}

/* Replace slot i's owned block array with a fresh copy of 'nblocks' hashes (or
 * clear it when hashes is NULL / nblocks 0). On allocation failure the slot is
 * left with no blocks - the record still stands; that file just falls back to
 * re-hash-on-announce until its next scan. */
static void set_blocks(FolderState *fs, int i,
                       const unsigned char (*hashes)[BEP_HASH_LEN], int nblocks)
{
    if (fs->blocks[i]) {
        FS_FREE(fs->blocks[i]);
        fs->blocks[i]  = NULL;
        fs->nblocks[i] = 0;
    }
    if (hashes && nblocks > 0) {
        unsigned char *p = FS_ALLOC((size_t)nblocks * BEP_HASH_LEN);
        if (p) {
            memcpy(p, hashes, (size_t)nblocks * BEP_HASH_LEN);
            fs->blocks[i]  = p;
            fs->nblocks[i] = nblocks;
        }
    }
}

int foldstate_upsert(FolderState *fs, const SyncMeta *meta,
                     const unsigned char (*hashes)[BEP_HASH_LEN], int nblocks)
{
    int i = find_slot(fs, meta->name);
    int was_new = (i < 0);

    if (was_new) {
        if (!ensure_cap(fs, fs->num_files + 1))
            return 0;                      /* full/OOM: caller must cope */
        i = fs->num_files++;
        fs->blocks[i]  = NULL;             /* fresh slot (struct may be reused) */
        fs->nblocks[i] = 0;
        fs->seen[i]    = 0;
        fs->names[i]   = NULL;
        fs->files[i].vext = NULL;      /* grown slots are uninitialised, and a
                                        * vacated one still holds the pointer
                                        * its record took with it */
        fs->files[i].nver = 0;
        if (!set_name(fs, i, meta->name)) {
            fs->num_files--;               /* unwind: the slot never existed */
            return 0;
        }
        rec_from_meta(&fs->files[i], meta); /* name in place before linking */
        hash_link(fs, i);
    } else {
        rec_from_meta(&fs->files[i], meta); /* same name: existing link holds */
    }
    set_blocks(fs, i, hashes, nblocks);
    fs->dirty = 1;

    /* Note the folder's "latest change" for the status report. Every writer
     * lands here (scanner commits, worker receives, tombstones), so tracking
     * it centrally catches them all; dirs and invalid placeholders are not
     * user-visible changes. Loading the persisted index replays upserts too -
     * the daemon zeroes chg_verb after a load. */
    if (meta->type == BEP_FILE_FILE && !meta->invalid) {
        fs->chg_verb = meta->deleted ? FOLDSTATE_CHG_DELETED
                     : was_new       ? FOLDSTATE_CHG_ADDED
                                     : FOLDSTATE_CHG_UPDATED;
        strncpy(fs->chg_name, meta->name, BEP_PATH_MAX - 1);
        fs->chg_name[BEP_PATH_MAX - 1] = '\0';
    }
    return 1;
}

void foldstate_clear_seen(FolderState *fs)
{
    if (fs->num_files > 0)
        memset(fs->seen, 0, (size_t)fs->num_files);
}

void foldstate_mark_seen(FolderState *fs, const char *name)
{
    int i = find_slot(fs, name);
    if (i >= 0)
        fs->seen[i] = 1;
}

int64_t foldstate_next_seq(FolderState *fs)
{
    fs->dirty = 1;
    return ++fs->sequence;
}

void foldstate_need_changed(FolderState *fs)
{
    FS_LOCK(fs);
    fs->need_gen++;
    FS_UNLOCK(fs);
}

int64_t foldstate_need_gen(FolderState *fs)
{
    int64_t g;
    FS_LOCK(fs);
    g = fs->need_gen;
    FS_UNLOCK(fs);
    return g;
}

int foldstate_forget(FolderState *fs, const char *name)
{
    int i, last;

    for (i = 0; i < fs->num_files; i++)
        if (fs->names[i] && strcmp(fs->names[i], name) == 0)
            break;
    if (i >= fs->num_files)
        return 0;

    /* Same swap-remove as the tombstone prune below, for the same reason: the
     * arrays are parallel and the tail record moves into the hole. */
    last = fs->num_files - 1;
    if (fs->blocks[i])
        FS_FREE(fs->blocks[i]);
    if (fs->names[i])
        FS_FREE(fs->names[i]);          /* owned, like blocks[] above */
    free_version(&fs->files[i]);        /* and its spilled counters */
    fs->files[i]      = fs->files[last];
    fs->names[i]      = fs->names[last];
    fs->blocks[i]     = fs->blocks[last];
    fs->nblocks[i]    = fs->nblocks[last];
    fs->seen[i]       = fs->seen[last];
    fs->names[last]   = NULL;
    fs->files[last].vext = NULL;      /* ownership moved to slot i above */
    fs->files[last].nver = 0;
    fs->blocks[last]  = NULL;
    fs->nblocks[last] = 0;
    fs->seen[last]    = 0;
    fs->num_files--;

    fs->dirty = 1;
    fs->prune_gen++;      /* a slot moved: announce passes must re-walk */
    hash_rebuild(fs);     /* the swap-remove invalidated the lookup chains */
    return 1;
}

int foldstate_forget_unseen(FolderState *fs, int64_t before)
{
    int i = 0, removed = 0;

    while (i < fs->num_files) {
        FolderRec *m = &fs->files[i];

        /* Same exclusions the tombstone sweep applies, and for the same
         * reasons - see sweep_deletions in scanner.c. */
        if (m->deleted || m->invalid || fs->seen[i] || m->sequence > before) {
            i++;
            continue;
        }
        {
            int last = fs->num_files - 1;
            if (fs->blocks[i])
                FS_FREE(fs->blocks[i]);
            if (fs->names[i])
                FS_FREE(fs->names[i]);
            free_version(&fs->files[i]);
            fs->files[i]      = fs->files[last];
            fs->names[i]      = fs->names[last];
            fs->blocks[i]     = fs->blocks[last];
            fs->nblocks[i]    = fs->nblocks[last];
            fs->seen[i]       = fs->seen[last];
            fs->names[last]   = NULL;
            fs->files[last].vext = NULL;   /* ownership moved to slot i */
            fs->files[last].nver = 0;
            fs->blocks[last]  = NULL;
            fs->nblocks[last] = 0;
            fs->seen[last]    = 0;
            fs->num_files--;
            removed++;
            /* re-check slot i, now holding the record moved in from the tail */
        }
    }
    if (removed) {
        fs->dirty = 1;
        fs->prune_gen++;
        hash_rebuild(fs);
    }
    return removed;
}

int foldstate_prune_tombstones(FolderState *fs, int64_t cutoff)
{
    int i = 0, removed = 0;

    while (i < fs->num_files) {
        FolderRec *m = &fs->files[i];
        if (m->deleted && m->modified_s < cutoff) {
            int last = fs->num_files - 1;
            if (fs->blocks[i])
                FS_FREE(fs->blocks[i]);
            if (fs->names[i])
                FS_FREE(fs->names[i]);
            free_version(&fs->files[i]);
            fs->files[i]     = fs->files[last];   /* move the tail in to compact */
            fs->names[i]     = fs->names[last];
            fs->blocks[i]    = fs->blocks[last];
            fs->nblocks[i]   = fs->nblocks[last];
            fs->seen[i]      = fs->seen[last];
            fs->names[last]  = NULL;
            fs->files[last].vext = NULL;   /* ownership moved to slot i */
            fs->files[last].nver = 0;
            fs->blocks[last] = NULL;
            fs->nblocks[last] = 0;
            fs->seen[last]   = 0;
            fs->num_files--;
            removed++;
            /* re-check slot i, now holding the moved record */
        } else {
            i++;
        }
    }
    if (removed) {
        fs->dirty = 1;
        fs->prune_gen++;   /* signal announce passes: a slot may have moved */
        hash_rebuild(fs);  /* swap-removes invalidated the lookup chains */
    }
    return removed;
}

#ifndef FOLDSTATE_HOST_TEST

void foldstate_lock(FolderState *fs)
{
    FS_LOCK(fs);
}

void foldstate_unlock(FolderState *fs)
{
    FS_UNLOCK(fs);
}

#endif /* FOLDSTATE_HOST_TEST */
