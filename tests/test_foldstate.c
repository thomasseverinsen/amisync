/* test_foldstate.c - host unit check for the shared per-folder index
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host (see `make test-foldstate`). FOLDSTATE_HOST_TEST
 * excludes the SignalSemaphore field and the lock/unlock wrappers, leaving the
 * pure memory ops (init / find / upsert / next_seq / block storage) - the exact
 * pieces the scanner and workers drive under the lock - to be exercised here with
 * a fast loop, before the on-Amiga validation of the concurrency around them.
 * The block-hash arrays use malloc/free under FOLDSTATE_HOST_TEST, so this also
 * exercises their ownership (replace frees the old, free() releases all).
 */

#include "foldstate.h"   /* FOLDSTATE_HOST_TEST is set on the compile line */

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

static void mkmeta(SyncMeta *m, const char *name, int64_t size, int64_t mtime)
{
    memset(m, 0, sizeof(*m));
    strncpy(m->name, name, BEP_PATH_MAX - 1);
    m->type       = BEP_FILE_FILE;
    m->size       = size;
    m->modified_s = mtime;
}

static void test_init(void)
{
    FolderState fs;
    foldstate_init(&fs, "default", 0x1122334455667788ULL);
    ok("init id",        strcmp(fs.folder_id, "default") == 0);
    ok("init short_id",  fs.short_id == 0x1122334455667788ULL);
    ok("init empty",     fs.num_files == 0);
    ok("init seq zero",  fs.sequence == 0);
    ok("init clean",     fs.dirty == 0);
}

static void test_upsert_find(void)
{
    FolderState fs;
    SyncMeta    a, b;
    FolderRec  *got;

    foldstate_init(&fs, "f", 1);
    mkmeta(&a, "a.txt", 100, 10);
    ok("insert a",       foldstate_upsert(&fs, &a, NULL, 0) == 1);
    ok("count 1",        fs.num_files == 1);
    ok("dirty set",      fs.dirty == 1);

    got = foldstate_find(&fs, "a.txt");
    ok("find a",         got && got->size == 100);
    ok("find miss",      foldstate_find(&fs, "nope") == NULL);

    /* Replace in place: same name, new size, count unchanged. */
    mkmeta(&b, "a.txt", 200, 20);
    ok("replace a",      foldstate_upsert(&fs, &b, NULL, 0) == 1);
    ok("count still 1",  fs.num_files == 1);
    got = foldstate_find(&fs, "a.txt");
    ok("replaced size",  got && got->size == 200);

    foldstate_free(&fs);
}

static void test_blocks(void)
{
    FolderState   fs;
    SyncMeta      m;
    unsigned char hashes[3][BEP_HASH_LEN];
    unsigned char out[3][BEP_HASH_LEN];
    int           i, total;

    for (i = 0; i < 3; i++)
        memset(hashes[i], i + 1, BEP_HASH_LEN);   /* distinct per block */

    foldstate_init(&fs, "f", 1);
    mkmeta(&m, "big", 300000, 5);

    /* Store with 3 blocks; read them back. */
    ok("upsert with blocks", foldstate_upsert(&fs, &m, hashes, 3) == 1);
    total = -1;
    ok("blocks copied", foldstate_blocks(&fs, "big", out, 3, &total) == 3);
    ok("blocks total",  total == 3);
    ok("blocks content", memcmp(out, hashes, sizeof(hashes)) == 0);

    /* cap below total copies only cap, still reports the true total. */
    ok("blocks capped", foldstate_blocks(&fs, "big", out, 1, &total) == 1);
    ok("capped total still 3", total == 3);

    /* Replacing with no blocks (e.g. a tombstone) clears them. */
    mkmeta(&m, "big", 0, 9);
    m.deleted = 1;
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("blocks cleared on tombstone",
       foldstate_blocks(&fs, "big", out, 3, &total) == 0 && total == 0);

    /* Unknown file: nothing. */
    ok("blocks of unknown", foldstate_blocks(&fs, "ghost", out, 3, NULL) == 0);

    foldstate_free(&fs);   /* must not double-free the cleared slot */
    ok("free after clear ok", 1);
}

/* The record table is allocated lazily and grows by doubling. Insert well past
 * FOLDSTATE_INIT_FILES (crossing several doublings) and confirm every record
 * survives the array moves with its data intact - the move is a raw memcpy of
 * the three parallel arrays, so a bug there silently corrupts the index. */
static void test_grow(void)
{
    FolderState   fs;
    SyncMeta      m;
    unsigned char h[1][BEP_HASH_LEN];
    char          name[32];
    const int     N = FOLDSTATE_INIT_FILES * 16 + 5;   /* forces several grows */
    int           i, added = 1, present = 1, blocks_ok = 1;

    foldstate_init(&fs, "f", 1);
    ok("lazy: no table before first upsert", fs.cap == 0 && fs.files == NULL);

    for (i = 0; i < N; i++) {
        sprintf(name, "f%d", i);
        mkmeta(&m, name, i, i);
        memset(h[0], (unsigned char)i, BEP_HASH_LEN);  /* per-file block hash */
        if (!foldstate_upsert(&fs, &m, h, 1))
            added = 0;
    }
    ok("grow: all inserts succeeded", added);
    ok("grow: count", fs.num_files == N);
    ok("grow: cap absorbed N", fs.cap >= N);

    /* Every record - including the earliest, moved across every doubling -
     * is still findable with its original size and block hash. */
    for (i = 0; i < N; i++) {
        FolderRec    *got;
        unsigned char out[1][BEP_HASH_LEN];
        sprintf(name, "f%d", i);
        got = foldstate_find(&fs, name);
        if (!got || got->size != i)
            present = 0;
        if (foldstate_blocks(&fs, name, out, 1, NULL) != 1 ||
            out[0][0] != (unsigned char)i)
            blocks_ok = 0;
    }
    ok("grow: every record survived the moves", present);
    ok("grow: every block array survived the moves", blocks_ok);

    /* Replacing an existing record never grows the table. */
    {
        int cap_before = fs.cap;
        mkmeta(&m, "f0", 777, 777);
        ok("grow: replace ok", foldstate_upsert(&fs, &m, NULL, 0) == 1);
        ok("grow: replace did not grow", fs.cap == cap_before);
        ok("grow: replace count steady", fs.num_files == N);
    }

    foldstate_free(&fs);

    /* free() leaves the struct empty and reusable: a fresh upsert re-grows. */
    ok("free: table released", fs.files == NULL && fs.cap == 0 && fs.num_files == 0);
    mkmeta(&m, "again", 1, 1);
    ok("free: reusable after free", foldstate_upsert(&fs, &m, NULL, 0) == 1);
    ok("free: regrew", foldstate_find(&fs, "again") != NULL);
    foldstate_free(&fs);
}

static void test_seq_monotonic(void)
{
    FolderState fs;
    int64_t     prev, s;
    int         i;

    foldstate_init(&fs, "f", 1);
    prev = 0;
    for (i = 0; i < 100; i++) {
        s = foldstate_next_seq(&fs);
        ok("seq strictly increasing", s == prev + 1);
        prev = s;
    }
    ok("seq high-water", fs.sequence == 100);
}

static void test_prune(void)
{
    FolderState   fs;
    SyncMeta      m;
    unsigned char h[1][BEP_HASH_LEN];

    memset(h[0], 7, BEP_HASH_LEN);
    foldstate_init(&fs, "f", 1);

    /* live file, old tombstone, recent tombstone, another live file (with blocks). */
    mkmeta(&m, "live1", 10, 100);                 foldstate_upsert(&fs, &m, NULL, 0);
    mkmeta(&m, "old",   0, 100); m.deleted = 1;   foldstate_upsert(&fs, &m, NULL, 0);
    mkmeta(&m, "new",   0, 9000); m.deleted = 1;  foldstate_upsert(&fs, &m, NULL, 0);
    mkmeta(&m, "live2", 20, 100);                 foldstate_upsert(&fs, &m, h, 1);
    fs.dirty = 0;

    /* cutoff 5000: only "old" (mtime 100) is older; "new" (9000) survives. */
    ok("prune removed 1", foldstate_prune_tombstones(&fs, 5000) == 1);
    ok("prune count", fs.num_files == 3);
    ok("prune kept live1", foldstate_find(&fs, "live1") != NULL);
    ok("prune kept live2", foldstate_find(&fs, "live2") != NULL);
    ok("prune kept recent tombstone", foldstate_find(&fs, "new") != NULL);
    ok("prune dropped old tombstone", foldstate_find(&fs, "old") == NULL);
    ok("prune set dirty", fs.dirty == 1);

    /* live2's blocks survived the compaction (it was moved into the hole). */
    {
        unsigned char out[1][BEP_HASH_LEN];
        ok("prune preserved blocks",
           foldstate_blocks(&fs, "live2", out, 1, NULL) == 1 && out[0][0] == 7);
    }

    /* Nothing left old enough: no-op, stays clean. */
    fs.dirty = 0;
    ok("prune no-op", foldstate_prune_tombstones(&fs, 5000) == 0 && fs.dirty == 0);

    foldstate_free(&fs);
}

/* The scanner's mark-and-sweep 'seen' marks: cleared in bulk, set per name,
 * carried across both a table grow (raw memcpy) and prune's swap-remove - a
 * mark landing on the wrong record would either tombstone a live file or keep
 * a vanished one alive. */
static void test_seen(void)
{
    FolderState fs;
    SyncMeta    m;
    char        name[32];
    int         i;

    foldstate_init(&fs, "f", 1);
    foldstate_clear_seen(&fs);   /* empty index: must tolerate a NULL table */
    ok("seen: clear on empty index ok", fs.num_files == 0);

    mkmeta(&m, "a", 1, 100);                     foldstate_upsert(&fs, &m, NULL, 0);
    mkmeta(&m, "old", 0, 100); m.deleted = 1;    foldstate_upsert(&fs, &m, NULL, 0);
    mkmeta(&m, "b", 2, 100);                     foldstate_upsert(&fs, &m, NULL, 0);

    ok("seen: fresh slots unmarked", !fs.seen[0] && !fs.seen[1] && !fs.seen[2]);
    foldstate_mark_seen(&fs, "a");
    foldstate_mark_seen(&fs, "b");
    foldstate_mark_seen(&fs, "ghost");           /* unknown name: no-op */
    ok("seen: marked a", fs.seen[0] == 1);
    ok("seen: marked b", fs.seen[2] == 1);
    ok("seen: tombstone untouched", fs.seen[1] == 0);

    /* Prune swap-removes "old" (slot 1) by moving "b" (last, marked) into the
     * hole: the mark must travel with the record. */
    ok("seen: prune removed old", foldstate_prune_tombstones(&fs, 5000) == 1);
    ok("seen: b moved into the hole",
       strcmp(foldstate_name(&fs, &fs.files[1]), "b") == 0);
    ok("seen: mark followed the moved record", fs.seen[1] == 1);
    ok("seen: a's mark undisturbed", fs.seen[0] == 1);

    /* A grow moves the parallel arrays; marks must survive the memcpy. */
    for (i = 0; i < FOLDSTATE_INIT_FILES * 2; i++) {
        sprintf(name, "g%d", i);
        mkmeta(&m, name, i, i);
        foldstate_upsert(&fs, &m, NULL, 0);
    }
    ok("seen: marks survived the grow", fs.seen[0] == 1 && fs.seen[1] == 1);

    foldstate_clear_seen(&fs);
    for (i = 0; i < fs.num_files; i++)
        if (fs.seen[i])
            break;
    ok("seen: clear_seen wiped every mark", i == fs.num_files);

    foldstate_free(&fs);
}

/* The hashed name-lookup index: find_slot walks a bucket chain instead of the
 * whole table, and the chains are relinked on grow and rebuilt after prune's
 * swap-remove. Mirror a few hundred inserts / prunes / re-adds against a plain
 * presence array - a chain bug shows up as a false hit or a false miss. */
static void test_lookup(void)
{
    FolderState fs;
    SyncMeta    m;
    char        name[32];
    const int   N = 300;                 /* crosses several grows */
    static unsigned char present[300];
    int         i, all_ok;

    foldstate_init(&fs, "f", 1);
    ok("lookup: miss on empty index", foldstate_find(&fs, "nothing") == NULL);

    for (i = 0; i < N; i++) {
        sprintf(name, "n%d", i);
        mkmeta(&m, name, i, i);
        foldstate_upsert(&fs, &m, NULL, 0);
        present[i] = 1;
    }

    /* Tombstone a scattered third with an old mtime, prune them out. */
    for (i = 0; i < N; i += 3) {
        sprintf(name, "n%d", i);
        mkmeta(&m, name, 0, 10); m.deleted = 1;
        foldstate_upsert(&fs, &m, NULL, 0);
        present[i] = 0;
    }
    ok("lookup: prune removed the third",
       foldstate_prune_tombstones(&fs, 5000) == N / 3 + (N % 3 ? 1 : 0));

    all_ok = 1;
    for (i = 0; i < N; i++) {
        FolderRec *got;
        sprintf(name, "n%d", i);
        got = foldstate_find(&fs, name);
        if (present[i] ? (got == NULL || got->size != i) : (got != NULL))
            all_ok = 0;
    }
    ok("lookup: every name resolves correctly after prune", all_ok);

    /* Re-add some pruned names: fresh slots must link into rebuilt chains. */
    for (i = 0; i < N; i += 30) {
        sprintf(name, "n%d", i);
        mkmeta(&m, name, 1000 + i, 20);
        foldstate_upsert(&fs, &m, NULL, 0);
        present[i] = 1;
    }
    all_ok = 1;
    for (i = 0; i < N; i += 30) {
        FolderRec *got;
        sprintf(name, "n%d", i);
        got = foldstate_find(&fs, name);
        if (!got || got->size != 1000 + i)
            all_ok = 0;
    }
    ok("lookup: re-added names found with new data", all_ok);
    ok("lookup: still misses the never-added", foldstate_find(&fs, "zzz") == NULL);

    foldstate_free(&fs);
}

/* The "latest change" note the status report shows: upsert records the last
 * FILE add/update/delete; dirs and invalid placeholders don't count. */
static void test_change_note(void)
{
    FolderState fs;
    SyncMeta    m;

    foldstate_init(&fs, "f", 1);
    ok("chg: none initially", fs.chg_verb == 0);

    mkmeta(&m, "a.txt", 10, 100);
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("chg: add noted", fs.chg_verb == FOLDSTATE_CHG_ADDED &&
                         strcmp(fs.chg_name, "a.txt") == 0);

    mkmeta(&m, "a.txt", 20, 200);
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("chg: update noted", fs.chg_verb == FOLDSTATE_CHG_UPDATED);

    mkmeta(&m, "d", 0, 300);
    m.type = BEP_FILE_DIRECTORY;
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("chg: dir ignored", fs.chg_verb == FOLDSTATE_CHG_UPDATED &&
                           strcmp(fs.chg_name, "a.txt") == 0);

    mkmeta(&m, "ghost", 5, 400);
    m.invalid = 1;
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("chg: invalid ignored", strcmp(fs.chg_name, "a.txt") == 0);

    mkmeta(&m, "a.txt", 0, 500);
    m.deleted = 1;
    foldstate_upsert(&fs, &m, NULL, 0);
    ok("chg: delete noted", fs.chg_verb == FOLDSTATE_CHG_DELETED &&
                            strcmp(fs.chg_name, "a.txt") == 0);

    foldstate_free(&fs);
}

/* foldstate_reset re-keys a slot that is IN USE (a runtime folder add
 * resurrecting a tombstoned one). Everything foldstate_init would zero must be
 * zeroed - a sequence or a stale record surviving would be announced to peers
 * under the new folder's identity - but on the Amiga build the semaphore in the
 * struct must NOT be re-initialised, which is why this is not a memset. Only
 * the data half is observable here; the lock half is what the comments in
 * foldstate.c/daemon.c pin down. */
static void test_reset(void)
{
    FolderState   fs;
    SyncMeta      m;
    unsigned char h[2][BEP_HASH_LEN];

    memset(h, 0xAB, sizeof(h));
    foldstate_init(&fs, "old", 0xAAAA);
    fs.index_id = 0x1111;
    mkmeta(&m, "keep.txt", 40, 7);
    foldstate_upsert(&fs, &m, h, 2);
    mkmeta(&m, "gone.txt", 50, 8);
    m.deleted = 1;
    foldstate_upsert(&fs, &m, NULL, 0);
    foldstate_next_seq(&fs);
    fs.scan_day = 9000;
    fs.scan_min = 30;
    ok("reset: seeded",      fs.num_files == 2 && fs.sequence > 0);

    foldstate_reset(&fs, "new", 0xBBBB, 0x2222);

    ok("reset: id",          strcmp(fs.folder_id, "new") == 0);
    ok("reset: short_id",    fs.short_id == 0xBBBB);
    ok("reset: index_id",    fs.index_id == 0x2222);
    ok("reset: empty",       fs.num_files == 0);
    ok("reset: seq zero",    fs.sequence == 0);
    ok("reset: clean",       fs.dirty == 0);
    ok("reset: prune_gen",   fs.prune_gen == 0);
    ok("reset: scan stamp",  fs.scan_day == 0 && fs.scan_min == 0);
    ok("reset: latest chg",  fs.chg_verb == 0 && fs.chg_name[0] == '\0');
    ok("reset: table freed", fs.files == NULL && fs.blocks == NULL &&
                             fs.hhead == NULL && fs.cap == 0);
    ok("reset: old record gone", foldstate_find(&fs, "keep.txt") == NULL);

    /* Usable again: the table re-grows lazily, exactly as after init. */
    mkmeta(&m, "fresh.txt", 10, 1);
    ok("reset: reusable",    foldstate_upsert(&fs, &m, h, 2) == 1);
    ok("reset: seq restarts", fs.sequence == 0);   /* upsert alone never bumps */
    ok("reset: finds fresh", foldstate_find(&fs, "fresh.txt") != NULL);
    foldstate_free(&fs);
}

/* The shared wanted-content set: what stops one worker's deferred deletion
 * from removing a file another worker is about to copy from. */
static void test_wants(void)
{
    FolderState   fs;
    unsigned char a[BEP_HASH_LEN], b[BEP_HASH_LEN];
    int           owner1 = 1, owner2 = 2;   /* stand-ins for two Sync blocks */
    int           i;

    foldstate_init(&fs, "wants", 0x77);
    for (i = 0; i < BEP_HASH_LEN; i++) { a[i] = (unsigned char)i; b[i] = (unsigned char)(200 - i); }

    ok("wants: idle at rest",      foldstate_want_idle(&fs) == 1);
    ok("wants: nothing wanted",    foldstate_want_any(&fs, a, 100) == 0);

    foldstate_want_add(&fs, &owner1, a, 100);
    ok("wants: added is wanted",   foldstate_want_any(&fs, a, 100) == 1);
    ok("wants: other content no",  foldstate_want_any(&fs, b, 100) == 0);
    ok("wants: size is part of it",foldstate_want_any(&fs, a, 101) == 0);
    ok("wants: busy now",          foldstate_want_idle(&fs) == 0);

    /* The point of the whole structure: one worker's want is visible to the
     * other, because the file it protects is shared. */
    foldstate_want_add(&fs, &owner2, b, 200);
    ok("wants: second owner",      foldstate_want_any(&fs, b, 200) == 1);
    ok("wants: first still there", foldstate_want_any(&fs, a, 100) == 1);

    /* One going idle must NOT drop the other's protection. */
    foldstate_want_clear(&fs, &owner1);
    ok("wants: cleared owner gone",foldstate_want_any(&fs, a, 100) == 0);
    ok("wants: other kept",        foldstate_want_any(&fs, b, 200) == 1);
    ok("wants: still busy",        foldstate_want_idle(&fs) == 0);

    foldstate_want_clear(&fs, &owner2);
    ok("wants: idle when all clear", foldstate_want_idle(&fs) == 1);

    /* Idempotent, and it grows past the initial table. */
    for (i = 0; i < 300; i++) {
        a[0] = (unsigned char)(i & 0xff);
        a[1] = (unsigned char)(i >> 8);
        foldstate_want_add(&fs, &owner1, a, 100);
        foldstate_want_add(&fs, &owner1, a, 100);   /* twice: must not double */
    }
    a[0] = 150; a[1] = 0;
    ok("wants: found after grow",  foldstate_want_any(&fs, a, 100) == 1);
    a[0] = 44; a[1] = 1;                            /* i = 300, never added */
    ok("wants: absent after grow", foldstate_want_any(&fs, a, 100) == 0);

    /* Release frees the table and hands the slot back. */
    foldstate_want_release(&fs, &owner1);
    ok("wants: released is idle",  foldstate_want_idle(&fs) == 1);
    a[0] = 150; a[1] = 0;
    ok("wants: released forgets",  foldstate_want_any(&fs, a, 100) == 0);

    foldstate_free(&fs);
}

/* The drift guard for the SyncMeta <-> FolderRec split (see foldstate.h).
 *
 * Every field gets a distinct non-zero value, goes through the index, and comes
 * back; then the two structs are memcmp'd whole. A field that exists in both
 * structs but is missing from rec_from_meta or meta_from_rec returns as zero and
 * fails here - which is the failure a sizeof() assertion cannot see. Both sides
 * start memset to 0 so padding bytes match and only real content differs.
 *
 * Add a field to SyncMeta and this test fails until it is carried across. That
 * is deliberate: the stored index is what survives a reboot, and a field
 * silently dropped from it is data loss discovered days later. */
static void test_roundtrip_all_fields(void)
{
    FolderState fs;
    SyncMeta    in, out;
    FolderRec  *rec;
    int         i;

    foldstate_init(&fs, "rt", 0x5151);

    memset(&in, 0, sizeof(in));
    strcpy(in.name, "dir/deep/file.bin");
    in.size             = 0x0102030405060708LL;
    in.permissions      = 0644;
    in.modified_s       = 0x1122334455LL;
    in.modified_ns      = 123456789;
    in.modified_by      = 0xAABBCCDDEEFF0011ULL;
    in.sequence         = 4242;
    in.block_size       = 128 * 1024;
    in.type             = BEP_FILE_FILE;
    in.deleted          = 0;
    in.invalid          = 1;
    in.has_content_hash = 1;
    for (i = 0; i < BEP_HASH_LEN; i++)
        in.content_hash[i] = (unsigned char)(i + 1);
    in.version.num_counters = 3;
    for (i = 0; i < 3; i++) {
        in.version.counters[i].id    = 0x1000ULL + (unsigned)i;
        in.version.counters[i].value = 0x2000ULL + (unsigned)i;
    }

    ok("roundtrip: stored", foldstate_upsert(&fs, &in, NULL, 0) == 1);
    rec = foldstate_find(&fs, in.name);
    ok("roundtrip: found", rec != NULL);

    memset(&out, 0, sizeof(out));
    foldstate_meta(&fs, rec, &out);
    ok("roundtrip: every field survives", memcmp(&in, &out, sizeof(in)) == 0);

    /* A vector past the inline capacity must spill and come back whole - the
     * path that allocates, and the one a bigger mesh actually takes. */
    memset(&in, 0, sizeof(in));
    strcpy(in.name, "spill.bin");
    in.type = BEP_FILE_FILE;
    in.size = 7;
    in.version.num_counters = FOLDREC_VIN + 3;
    for (i = 0; i < in.version.num_counters; i++) {
        in.version.counters[i].id    = 0xF00ULL + (unsigned)i;
        in.version.counters[i].value = 0xB00ULL + (unsigned)i;
    }
    ok("spill: stored", foldstate_upsert(&fs, &in, NULL, 0) == 1);
    memset(&out, 0, sizeof(out));
    foldstate_meta(&fs, foldstate_find(&fs, "spill.bin"), &out);
    ok("spill: vector survives past the inline cap",
       memcmp(&in, &out, sizeof(in)) == 0);

    /* Overwrite a spilled record with a small vector, then a large one again:
     * exercises free-then-store both ways round. */
    in.version.num_counters = 1;
    ok("spill: shrunk", foldstate_upsert(&fs, &in, NULL, 0) == 1);
    memset(&out, 0, sizeof(out));
    foldstate_meta(&fs, foldstate_find(&fs, "spill.bin"), &out);
    ok("spill: shrink keeps one counter",
       out.version.num_counters == 1 &&
       out.version.counters[0].id == 0xF00ULL);

    /* Forgetting a spilled record must release it; a later reuse of the slot
     * must not inherit the pointer (the double-free this split invited). */
    ok("spill: forgotten", foldstate_forget(&fs, "spill.bin") == 1);
    memset(&in, 0, sizeof(in));
    strcpy(in.name, "reused.bin");
    in.type = BEP_FILE_FILE;
    in.version.num_counters = FOLDREC_VIN + 1;
    for (i = 0; i < in.version.num_counters; i++)
        in.version.counters[i].id = 0xC00ULL + (unsigned)i;
    ok("spill: slot reused safely", foldstate_upsert(&fs, &in, NULL, 0) == 1);
    memset(&out, 0, sizeof(out));
    foldstate_meta(&fs, foldstate_find(&fs, "reused.bin"), &out);
    ok("spill: reused slot is correct", memcmp(&in, &out, sizeof(in)) == 0);

    foldstate_free(&fs);
}

int main(void)
{
    test_init();
    test_wants();
    test_upsert_find();
    test_blocks();
    test_grow();
    test_seq_monotonic();
    test_prune();
    test_seen();
    test_lookup();
    test_change_note();
    test_reset();
    test_roundtrip_all_fields();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
