/* test_syncmodel.c - host unit check for the pure sync decision logic
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host (see `make test-syncmodel`). syncmodel is pure
 * (FileInfo/SyncMeta/Config data only) - the fetch/skip/delete decisions, the
 * last-writer rule, tombstones, version bookkeeping and the want queue. Phase 4a
 * moved the index itself into FolderState (see test_foldstate), so classify now
 * takes the stored record directly; these checks build that record by hand.
 */

#include "syncmodel.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

/* Build a peer FileInfo (a tombstone if deleted). 'tag' seeds content_hash so
 * two files with different content compare unequal. */
static void mkfile(BepFileInfo *fi, const char *name, int64_t size,
                   int64_t mtime, int deleted, unsigned char tag)
{
    memset(fi, 0, sizeof(*fi));
    strcpy(fi->name, name);
    fi->type       = BEP_FILE_FILE;
    fi->size       = deleted ? 0 : size;
    fi->modified_s = mtime;
    fi->deleted    = deleted;
    if (!deleted && size > 0) {
        fi->has_content_hash = 1;
        fi->content_hash[0]  = tag;
    }
}

/* Build a stored record (the worker's view of "what we have"). */
static void mkmeta(SyncMeta *m, const char *name, int64_t size,
                   int64_t mtime, int deleted, unsigned char tag)
{
    memset(m, 0, sizeof(*m));
    strcpy(m->name, name);
    m->type       = BEP_FILE_FILE;
    m->size       = deleted ? 0 : size;
    m->modified_s = mtime;
    m->deleted    = deleted;
    if (!deleted && size > 0) {
        m->has_content_hash = 1;
        m->content_hash[0]  = tag;
    }
}

static void test_short_id(void)
{
    unsigned char raw[32];
    int i;
    for (i = 0; i < 32; i++) raw[i] = (unsigned char)i;
    /* bytes 00 01 02 03 04 05 06 07 -> 0x0001020304050607 */
    ok("short id big-endian",
       sync_short_id_from_raw(raw) == 0x0001020304050607ULL);
}

static void test_content_same(void)
{
    SyncMeta    have;
    BepFileInfo b;

    mkmeta(&have, "x", 100, 10, 0, 1);

    mkfile(&b, "x", 100, 99, 0, 1);     /* same content, different mtime */
    ok("content same ignores mtime", sync_content_same(&have, &b));

    mkfile(&b, "x", 100, 10, 0, 2);     /* different content_hash */
    ok("content differ by hash", !sync_content_same(&have, &b));

    mkfile(&b, "x", 101, 10, 0, 1);     /* different size */
    ok("content differ by size", !sync_content_same(&have, &b));
}

static void test_want_queue(void)
{
    SyncModel     m;
    BepFileInfo   fi;
    WantFile      out;
    unsigned char h1[1][BEP_HASH_LEN], h2[2][BEP_HASH_LEN];
    unsigned char outh[4][BEP_HASH_LEN];

    sync_init(&m);
    mkfile(&fi, "p", 10, 1, 0, 1);
    memset(h1, 0, sizeof(h1)); h1[0][0] = 0x55;
    ok("want push", sync_want_push(&m, 0, &fi, h1, 1, 0) && m.num_want == 1);
    ok("want has", sync_want_has(&m, 0, "p"));
    ok("want has miss", !sync_want_has(&m, 0, "q"));
    ok("want pop", sync_want_pop(&m, &out, outh, 4) &&
                   strcmp(out.fi.name, "p") == 0 &&
                   out.num_blocks == 1 && outh[0][0] == 0x55);
    ok("want empty pop", !sync_want_pop(&m, &out, outh, 4) && m.num_want == 0);
    ok("want pool freed", m.hash_used == 0);

    /* LIFO with block hashes: push two, pop returns the second then the first,
     * each with its own hashes, and the pool drains back to empty. */
    mkfile(&fi, "a", 10, 1, 0, 1);
    memset(h2, 0, sizeof(h2)); h2[0][0] = 0xA0; h2[1][0] = 0xA1;
    sync_want_push(&m, 0, &fi, h2, 2, 0);
    mkfile(&fi, "b", 10, 1, 0, 1);
    memset(h1, 0, sizeof(h1)); h1[0][0] = 0xB0;
    sync_want_push(&m, 0, &fi, h1, 1, 0);
    ok("lifo pool used", m.hash_used == 3);
    ok("pop b first", sync_want_pop(&m, &out, outh, 4) &&
                      strcmp(out.fi.name, "b") == 0 && outh[0][0] == 0xB0);
    ok("pop a second", sync_want_pop(&m, &out, outh, 4) &&
                       strcmp(out.fi.name, "a") == 0 &&
                       out.num_blocks == 2 && outh[0][0] == 0xA0 &&
                       outh[1][0] == 0xA1);
    ok("lifo pool drained", m.hash_used == 0 && m.num_want == 0);

    /* A peer-sized block count must be refused, not wrapped into the pool. */
    mkfile(&fi, "huge", 10, 1, 0, 1);
    ok("pool overflow refused",
       !sync_want_push(&m, 0, &fi, h1, 0x7FFFFFFF, 0) && m.hash_used == 0);
    ok("pool limit refused",
       !sync_want_push(&m, 0, &fi, h1, SYNC_HASH_POOL + 1, 0) && m.hash_used == 0);
}

static void test_tombstone(void)
{
    BepFileInfo t;
    sync_make_tombstone(&t, "gone.txt", BEP_FILE_FILE, 0xBEEF, 12345, 7);
    ok("tombstone deleted", t.deleted && t.type == BEP_FILE_FILE);
    ok("tombstone empty", t.size == 0 && t.num_blocks == 0);
    ok("tombstone name", strcmp(t.name, "gone.txt") == 0);
    ok("tombstone version", t.modified_s == 12345 && t.sequence == 7 &&
                            t.version.num_counters == 1 &&
                            t.version.counters[0].id == 0xBEEF &&
                            t.version.counters[0].value == 12345);
}

static uint64_t ctr(const BepVector *v, uint64_t id)
{
    int i;
    for (i = 0; i < v->num_counters; i++)
        if (v->counters[i].id == id) return v->counters[i].value;
    return 0;
}

static void test_bump_version(void)
{
    BepVector out, prev;

    /* Brand-new file: fresh single counter. */
    memset(&out, 0, sizeof(out));
    sync_bump_version(&out, NULL, 0xA, 100);
    ok("bump new: one counter", out.num_counters == 1 && ctr(&out, 0xA) == 100);

    /* Carry a peer counter forward, add ours. */
    memset(&prev, 0, sizeof(prev));
    prev.num_counters = 1; prev.counters[0].id = 0xB; prev.counters[0].value = 5;
    sync_bump_version(&out, &prev, 0xA, 100);
    ok("bump carries peer counter",
       out.num_counters == 2 && ctr(&out, 0xB) == 5 && ctr(&out, 0xA) == 100);

    /* Our counter already present: value must strictly increase. */
    memset(&prev, 0, sizeof(prev));
    prev.num_counters = 2;
    prev.counters[0].id = 0xB; prev.counters[0].value = 5;
    prev.counters[1].id = 0xA; prev.counters[1].value = 10;
    sync_bump_version(&out, &prev, 0xA, 8);           /* 8 <= 10 -> forced to 11 */
    ok("bump forces strict increase",
       ctr(&out, 0xA) == 11 && ctr(&out, 0xB) == 5);
    sync_bump_version(&out, &prev, 0xA, 20);          /* 20 > 10 -> 20 */
    ok("bump takes larger value",
       ctr(&out, 0xA) == 20 && ctr(&out, 0xB) == 5);

    /* Many devices: a folder shared by up to BEP_MAX_COUNTERS devices keeps
     * every counter. This regresses if BEP_MAX_COUNTERS is too small (it was
     * once 4 while up to 16 peers are supported), which silently dropped our
     * counter and stalled propagation. */
    {
        int i, ok_all = 1;
        memset(&prev, 0, sizeof(prev));
        prev.num_counters = BEP_MAX_COUNTERS - 1;     /* peers 1..N-1 */
        for (i = 0; i < prev.num_counters; i++) {
            prev.counters[i].id    = (uint64_t)(0x100 + i);
            prev.counters[i].value = (uint64_t)(i + 1);
        }
        sync_bump_version(&out, &prev, 0xA, 500);     /* add ours: the Nth */
        ok("bump keeps all N device counters",
           out.num_counters == BEP_MAX_COUNTERS && ctr(&out, 0xA) == 500);
        for (i = 0; i < prev.num_counters; i++)
            if (ctr(&out, (uint64_t)(0x100 + i)) != (uint64_t)(i + 1))
                ok_all = 0;
        ok("bump preserves every peer counter", ok_all);
    }
}

static void test_classify(void)
{
    BepFileInfo peer;
    SyncMeta    have;

    /* No local record (NULL): a live file is fetched, unless send-only. */
    mkfile(&peer, "n", 10, 100, 0, 1);
    ok("fetch new file",
       sync_classify_incoming(NULL, FOLDER_SENDRECEIVE, &peer) == SYNC_FETCH);
    ok("sendonly never fetches",
       sync_classify_incoming(NULL, FOLDER_SENDONLY, &peer) == SYNC_IGNORE);
    ok("receiveonly fetches",
       sync_classify_incoming(NULL, FOLDER_RECEIVEONLY, &peer) == SYNC_FETCH);

    /* We already have identical content (same tag), newer peer mtime. */
    mkmeta(&have, "a", 10, 100, 0, 1);
    mkfile(&peer, "a", 10, 200, 0, 1);
    ok("ignore same content",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Content differs: newer wins, older loses. */
    mkfile(&peer, "a", 10, 200, 0, 2);
    ok("fetch newer differing",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_FETCH);
    mkfile(&peer, "a", 10, 50, 0, 2);
    ok("ignore older differing",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Deletions. have "a" is live at mtime 100. */
    mkfile(&peer, "a", 0, 200, 1, 0);
    ok("delete: peer delete newer",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_DELETE);
    mkfile(&peer, "a", 0, 50, 1, 0);
    ok("ignore: peer delete older",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);
    mkfile(&peer, "missing", 0, 200, 1, 0);
    ok("ignore: delete of unknown",
       sync_classify_incoming(NULL, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Tombstone locally, peer has it live again. */
    mkmeta(&have, "a", 0, 100, 1, 0);
    mkfile(&peer, "a", 10, 200, 0, 3);
    ok("fetch over tombstone if newer",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_FETCH);
    mkfile(&peer, "a", 10, 50, 0, 3);
    ok("ignore over tombstone if older",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);
    mkfile(&peer, "a", 0, 200, 1, 0);
    ok("ignore delete of tombstone",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);
}

/* Give a record/FileInfo a one-counter version vector. */
static void setver_m(SyncMeta *m, uint64_t id, uint64_t val)
{
    m->version.num_counters = 1;
    m->version.counters[0].id = id;
    m->version.counters[0].value = val;
}
static void setver_f(BepFileInfo *f, uint64_t id, uint64_t val)
{
    f->version.num_counters = 1;
    f->version.counters[0].id = id;
    f->version.counters[0].value = val;
}

static void test_version_compare(void)
{
    BepVector a, b;

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    ok("vcmp empty = equal", sync_version_compare(&a, &b) == SYNC_V_EQUAL);

    a.num_counters = 1; a.counters[0].id = 0xA; a.counters[0].value = 3;
    ok("vcmp ours only", sync_version_compare(&a, &b) == SYNC_V_OURS);
    ok("vcmp theirs only", sync_version_compare(&b, &a) == SYNC_V_THEIRS);

    b = a;
    ok("vcmp identical", sync_version_compare(&a, &b) == SYNC_V_EQUAL);

    b.counters[0].value = 5;                    /* same id, theirs larger */
    ok("vcmp theirs dominates", sync_version_compare(&a, &b) == SYNC_V_THEIRS);

    /* Disjoint ids: each side is ahead somewhere -> concurrent. */
    b.counters[0].id = 0xB;
    ok("vcmp concurrent", sync_version_compare(&a, &b) == SYNC_V_CONCURRENT);

    /* Superset dominates: {A:3,B:5} vs {A:3}. */
    a.num_counters = 2;
    a.counters[1].id = 0xB; a.counters[1].value = 5;
    b.num_counters = 1; b.counters[0].id = 0xA; b.counters[0].value = 3;
    ok("vcmp superset dominates", sync_version_compare(&a, &b) == SYNC_V_OURS);
}

/* The rule a receive-only folder's announce filter rests on: a record we hold
 * exactly as a peer produced it carries no counter of ours, and one we
 * originated does. Cheap to state, and the whole mode's promise depends on it
 * being right, so it is checked here rather than only on the wire. */
static void test_version_has(void)
{
    BepVector v;
    BepVector bumped;

    memset(&v, 0, sizeof(v));
    ok("vhas: empty vector has nobody", !sync_version_has(&v, 0xA));
    ok("vhas: NULL is not ours", !sync_version_has(NULL, 0xA));

    /* A file straight from a peer: its counters, never ours. */
    v.num_counters = 2;
    v.counters[0].id = 0xB; v.counters[0].value = 7;
    v.counters[1].id = 0xC; v.counters[1].value = 1;
    ok("vhas: peer-sourced is not ours", !sync_version_has(&v, 0xA));
    ok("vhas: finds a peer's own counter", sync_version_has(&v, 0xB));

    /* Once we modify it, sync_bump_version stamps us and the answer flips -
     * this is exactly the transition the filter must catch. */
    sync_bump_version(&bumped, &v, 0xA, 42);
    ok("vhas: ours after a local bump", sync_version_has(&bumped, 0xA));
    ok("vhas: bump keeps the peers", sync_version_has(&bumped, 0xB) &&
                                     sync_version_has(&bumped, 0xC));

    /* A zero counter is absence, not authorship. */
    memset(&v, 0, sizeof(v));
    v.num_counters = 1; v.counters[0].id = 0xA; v.counters[0].value = 0;
    ok("vhas: zero counter is not authorship", !sync_version_has(&v, 0xA));
}

static void test_classify_vectors(void)
{
    BepFileInfo peer;
    SyncMeta    have;

    /* Their version dominates ours -> fetch, even with an OLDER mtime (the
     * mtime-only rule would wrongly ignore this). */
    mkmeta(&have, "a", 10, 200, 0, 1);
    setver_m(&have, 0xA, 3);
    mkfile(&peer, "a", 10, 100, 0, 2);
    peer.version = have.version;
    peer.version.num_counters = 2;
    peer.version.counters[1].id = 0xB; peer.version.counters[1].value = 1;
    ok("v: dominated -> fetch despite older mtime",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_FETCH);

    /* Their version dominates but the content is IDENTICAL (an index
     * rebuilt from disk after a folder remove/re-add): adopt the winning
     * vector, no transfer. */
    mkmeta(&have, "a", 10, 100, 0, 1);
    setver_m(&have, 0xA, 3);
    mkfile(&peer, "a", 10, 200, 0, 1);          /* same tag = same hash */
    peer.version = have.version;
    peer.version.num_counters = 2;
    peer.version.counters[1].id = 0xB; peer.version.counters[1].value = 1;
    ok("v: dominated but identical content -> adopt",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_ADOPT);

    /* EQUAL vectors, identical content, differing mtime: a row damaged by
     * the early keep-our-mtime adopt - repair by adopting the peer's
     * metadata (the version stays). Matching metadata stays ignored. */
    mkmeta(&have, "a", 10, 100, 0, 1);
    setver_m(&have, 0xA, 3);
    mkfile(&peer, "a", 10, 200, 0, 1);          /* same tag = same hash */
    peer.version = have.version;
    ok("v: equal but differing mtime -> adopt (metadata repair)",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_ADOPT);
    mkfile(&peer, "a", 10, 100, 0, 1);
    peer.version = have.version;
    ok("v: equal and identical metadata -> ignore",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Ours dominates -> ignore, even with a NEWER peer mtime. */
    mkmeta(&have, "a", 10, 100, 0, 1);
    have.version.num_counters = 2;
    have.version.counters[0].id = 0xA; have.version.counters[0].value = 3;
    have.version.counters[1].id = 0xB; have.version.counters[1].value = 1;
    mkfile(&peer, "a", 10, 200, 0, 2);
    setver_f(&peer, 0xA, 3);
    ok("v: dominating -> ignore despite newer mtime",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Concurrent but IDENTICAL content (post remove/re-add vectors):
     * resolve deterministically with no conflict copy - peer newer ->
     * adopt its record whole; ours newer -> ignore (peer takes ours). */
    mkmeta(&have, "a", 10, 100, 0, 1);
    setver_m(&have, 0xA, 3);
    mkfile(&peer, "a", 10, 200, 0, 1);          /* same tag = same hash */
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent identical, theirs newer -> adopt",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_ADOPT);
    mkfile(&peer, "a", 10, 50, 0, 1);
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent identical, ours newer -> ignore",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Concurrent, peer's copy newer by mtime -> conflict (preserve, fetch). */
    mkmeta(&have, "a", 10, 100, 0, 1);
    setver_m(&have, 0xA, 3);
    mkfile(&peer, "a", 10, 200, 0, 2);
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent, theirs newer -> conflict",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_CONFLICT);

    /* Concurrent, ours newer -> ignore (peer preserves its side). */
    mkfile(&peer, "a", 10, 50, 0, 2);
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent, ours newer -> ignore",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Concurrent, mtime tied -> larger content hash wins. */
    mkfile(&peer, "a", 10, 100, 0, 2);          /* tag 2 > our tag 1 */
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent tie -> bigger hash wins (conflict)",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_CONFLICT);
    mkfile(&peer, "a", 10, 100, 0, 0);          /* tag 0 < our tag 1 */
    peer.has_content_hash = 1;                  /* tag 0 still hashes */
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent tie -> smaller hash loses (ignore)",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* Concurrent delete-vs-edit: the data wins, deletion is ignored. */
    mkfile(&peer, "a", 0, 500, 1, 0);
    setver_f(&peer, 0xB, 1);
    ok("v: concurrent delete loses to live copy",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_IGNORE);

    /* A dominating delete still deletes. */
    mkfile(&peer, "a", 0, 500, 1, 0);
    peer.version.num_counters = 2;
    peer.version.counters[0].id = 0xA; peer.version.counters[0].value = 3;
    peer.version.counters[1].id = 0xB; peer.version.counters[1].value = 9;
    ok("v: dominating delete deletes",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_DELETE);

    /* Our tombstone vs a concurrent live edit: their data beats our delete. */
    mkmeta(&have, "a", 0, 300, 1, 0);
    setver_m(&have, 0xA, 7);
    mkfile(&peer, "a", 10, 100, 0, 2);
    setver_f(&peer, 0xB, 2);
    ok("v: live edit beats concurrent tombstone",
       sync_classify_incoming(&have, FOLDER_SENDRECEIVE, &peer) == SYNC_FETCH);
}

static void test_conflict_name(void)
{
    char out[BEP_PATH_MAX];
    char small[24];

    ok("cname ext",
       sync_make_conflict_name(out, sizeof(out), "dir/report.txt",
                               1784291696LL, "P56IOI7", 0) &&
       strcmp(out, "dir/report.sync-conflict-20260717-123456-P56IOI7.txt") == 0);

    ok("cname no ext",
       sync_make_conflict_name(out, sizeof(out), "README",
                               1784291696LL, "P56IOI7", 0) &&
       strcmp(out, "README.sync-conflict-20260717-123456-P56IOI7") == 0);

    /* A dot in a directory name must not be mistaken for the extension. */
    ok("cname dot in dir",
       sync_make_conflict_name(out, sizeof(out), "v1.0/notes",
                               1784291696LL, "P56IOI7", 0) &&
       strcmp(out, "v1.0/notes.sync-conflict-20260717-123456-P56IOI7") == 0);

    ok("cname compact",
       sync_make_conflict_name(out, sizeof(out), "report.txt",
                               1784291696LL, "P56IOI7", 1) &&
       strcmp(out, "report.cnfl-123456.txt") == 0);

    ok("cname epoch",
       sync_make_conflict_name(out, sizeof(out), "x",
                               0LL, "TAG", 0) &&
       strcmp(out, "x.sync-conflict-19700101-000000-TAG") == 0);

    ok("cname leap day",
       sync_make_conflict_name(out, sizeof(out), "x",
                               951854402LL, "TAG", 0) &&
       strcmp(out, "x.sync-conflict-20000229-200002-TAG") == 0);

    ok("cname overflow rejected",
       !sync_make_conflict_name(small, sizeof(small), "a-rather-long-name.txt",
                                1784291696LL, "P56IOI7", 0));
}

/* ---- a small convergence simulation -------------------------------------
 * A "disk" is a set of live files; a tiny "index" (Idx) is the worker's stored
 * records. We drive one side from the other's announced files, applying classify
 * decisions, and check both ends converge. No sockets, crypto or real files. */

typedef struct { BepFileInfo f[16]; int n; } Disk;
typedef struct { SyncMeta    f[16]; int n; } Idx;

static BepFileInfo *disk_find(Disk *d, const char *name)
{
    int i;
    for (i = 0; i < d->n; i++)
        if (strcmp(d->f[i].name, name) == 0)
            return &d->f[i];
    return NULL;
}

static void disk_put(Disk *d, const BepFileInfo *fi)
{
    BepFileInfo *e = disk_find(d, fi->name);
    if (!e) e = &d->f[d->n++];
    *e = *fi;
}

static void disk_del(Disk *d, const char *name)
{
    int i;
    for (i = 0; i < d->n; i++)
        if (strcmp(d->f[i].name, name) == 0) {
            d->f[i] = d->f[--d->n];
            return;
        }
}

static SyncMeta *idx_find(Idx *x, const char *name)
{
    int i;
    for (i = 0; i < x->n; i++)
        if (strcmp(x->f[i].name, name) == 0)
            return &x->f[i];
    return NULL;
}

/* Record a BepFileInfo into the index as the lean SyncMeta the worker keeps. */
static void idx_put(Idx *x, const BepFileInfo *fi)
{
    SyncMeta *m = idx_find(x, fi->name);
    if (!m) m = &x->f[x->n++];
    memset(m, 0, sizeof(*m));
    strcpy(m->name, fi->name);
    m->type             = fi->type;
    m->size             = fi->size;
    m->modified_s       = fi->modified_s;
    m->deleted          = fi->deleted;
    m->version          = fi->version;
    m->has_content_hash = fi->has_content_hash;
    if (fi->has_content_hash)
        memcpy(m->content_hash, fi->content_hash, BEP_HASH_LEN);
}

/* Apply 'src' (one announced FileInfo) to (idx,disk) as the worker would;
 * 'self_id' is this side's short device ID (for conflict-copy version bumps). */
static void apply_one(Idx *x, Disk *disk, const BepFileInfo *src,
                      uint64_t self_id)
{
    SyncAction act = sync_classify_incoming(idx_find(x, src->name),
                                            FOLDER_SENDRECEIVE, src);
    if (act == SYNC_CONFLICT) {
        /* Preserve our loser under a conflict name as a new local file, as
         * conflict_preserve_local does, then fall through to the fetch. */
        BepFileInfo *loc = disk_find(disk, src->name);
        if (loc) {
            BepFileInfo copy = *loc;
            sync_make_conflict_name(copy.name, sizeof(copy.name), loc->name,
                                    1784291696LL, "SIMTAG7", 0);
            sync_bump_version(&copy.version, &copy.version, self_id,
                              (uint64_t)copy.modified_s);
            disk_put(disk, &copy);
            idx_put(x, &copy);
        }
        act = SYNC_FETCH;
    }
    if (act == SYNC_FETCH) {
        disk_put(disk, src);                 /* "download" the content */
        idx_put(x, src);                     /* record at peer's version */
    } else if (act == SYNC_DELETE) {
        disk_del(disk, src->name);
        idx_put(x, src);                     /* keep tombstone */
    }
}

static int disk_has(Disk *d, const char *name, unsigned char tag)
{
    BepFileInfo *e = disk_find(d, name);
    return e && !e->deleted && e->has_content_hash && e->content_hash[0] == tag;
}

static void test_convergence(void)
{
    Idx         xa, xb;
    Disk        da, db;
    BepFileInfo fi;

    memset(&xa, 0, sizeof(xa));
    memset(&xb, 0, sizeof(xb));
    memset(&da, 0, sizeof(da));
    memset(&db, 0, sizeof(db));

    /* A has file X (content tag 1, mtime 100); A records its own index. */
    mkfile(&fi, "X", 10, 100, 0, 1);
    disk_put(&da, &fi);
    idx_put(&xa, &fi);

    /* A -> B: B fetches X. */
    apply_one(&xb, &db, disk_find(&da, "X"), 0xB);
    ok("converge: B got X", disk_has(&db, "X", 1));

    /* Second announce is a no-op (B already has identical content). */
    apply_one(&xb, &db, disk_find(&da, "X"), 0xB);
    ok("converge: idempotent", db.n == 1 && disk_has(&db, "X", 1));

    /* A edits X (tag 2, newer mtime) and re-announces. */
    mkfile(&fi, "X", 10, 200, 0, 2);
    disk_put(&da, &fi);
    idx_put(&xa, &fi);
    apply_one(&xb, &db, disk_find(&da, "X"), 0xB);
    ok("converge: B got edit", disk_has(&db, "X", 2));

    /* A deletes X: build a tombstone (mtime 300) and announce it. */
    {
        BepFileInfo tomb;
        sync_make_tombstone(&tomb, "X", BEP_FILE_FILE, 0xA, 300, 3);
        disk_del(&da, "X");
        idx_put(&xa, &tomb);
        apply_one(&xb, &db, &tomb, 0xB);
    }
    ok("converge: B applied delete", disk_find(&db, "X") == NULL);

    /* A stale older delete must NOT remove a newer B file. */
    mkfile(&fi, "Y", 10, 500, 0, 1);
    disk_put(&db, &fi);
    idx_put(&xb, &fi);
    {
        BepFileInfo tomb;
        sync_make_tombstone(&tomb, "Y", BEP_FILE_FILE, 0xA, 400, 1);   /* older than B's Y */
        apply_one(&xb, &db, &tomb, 0xB);
    }
    ok("converge: stale delete ignored", disk_has(&db, "Y", 1));
}

/* Concurrent edits on both sides: the deterministic winner replaces the name
 * on both ends, the loser survives as a conflict copy on both ends. */
static void test_conflict_convergence(void)
{
    Idx         xa, xb;
    Disk        da, db;
    BepFileInfo fi;
    char        cn[BEP_PATH_MAX];

    memset(&xa, 0, sizeof(xa));
    memset(&xb, 0, sizeof(xb));
    memset(&da, 0, sizeof(da));
    memset(&db, 0, sizeof(db));

    /* Synced starting point: X (tag 1, version {A:100}) on both sides. */
    mkfile(&fi, "X", 10, 100, 0, 1);
    setver_f(&fi, 0xA, 100);
    disk_put(&da, &fi); idx_put(&xa, &fi);
    disk_put(&db, &fi); idx_put(&xb, &fi);

    /* A edits X (tag 2, mtime 200): version {A:200}. */
    mkfile(&fi, "X", 10, 200, 0, 2);
    setver_f(&fi, 0xA, 200);
    disk_put(&da, &fi); idx_put(&xa, &fi);

    /* B edits X concurrently (tag 3, mtime 150): version {A:100,B:150}. */
    mkfile(&fi, "X", 10, 150, 0, 3);
    fi.version.num_counters = 2;
    fi.version.counters[0].id = 0xA; fi.version.counters[0].value = 100;
    fi.version.counters[1].id = 0xB; fi.version.counters[1].value = 150;
    disk_put(&db, &fi); idx_put(&xb, &fi);

    /* B receives A's announce: concurrent, A's copy is newer -> B preserves
     * its tag-3 copy under a conflict name and fetches A's tag 2. */
    apply_one(&xb, &db, disk_find(&da, "X"), 0xB);
    sync_make_conflict_name(cn, sizeof(cn), "X", 1784291696LL, "SIMTAG7", 0);
    ok("conflict: B took A's winner", disk_has(&db, "X", 2));
    ok("conflict: B preserved its loser", disk_has(&db, cn, 3));

    /* A receives B's (pre-conflict) announce of its tag-3 X: concurrent but
     * older -> A keeps its own copy untouched. */
    mkfile(&fi, "X", 10, 150, 0, 3);
    fi.version.num_counters = 2;
    fi.version.counters[0].id = 0xA; fi.version.counters[0].value = 100;
    fi.version.counters[1].id = 0xB; fi.version.counters[1].value = 150;
    apply_one(&xa, &da, &fi, 0xA);
    ok("conflict: A kept its winner", disk_has(&da, "X", 2) && da.n == 1);

    /* B relays its post-conflict state: X at A's version (A ignores - same
     * content) and the conflict copy as a new file (A fetches it). */
    apply_one(&xa, &da, disk_find(&db, "X"), 0xA);
    apply_one(&xa, &da, disk_find(&db, cn), 0xA);
    ok("conflict: A got the conflict copy", disk_has(&da, cn, 3));
    ok("conflict: converged", da.n == 2 && db.n == 2 &&
       disk_has(&da, "X", 2) && disk_has(&db, "X", 2) &&
       disk_has(&da, cn, 3) && disk_has(&db, cn, 3));

    /* Re-announcing everything is a no-op both ways. */
    apply_one(&xb, &db, disk_find(&da, "X"), 0xB);
    apply_one(&xb, &db, disk_find(&da, cn), 0xB);
    ok("conflict: stable", da.n == 2 && db.n == 2 && disk_has(&db, cn, 3));
}

int main(void)
{
    test_short_id();
    test_content_same();
    test_want_queue();
    test_tombstone();
    test_bump_version();
    test_classify();
    test_version_compare();
    test_version_has();
    test_classify_vectors();
    test_conflict_name();
    test_convergence();
    test_conflict_convergence();

    if (failures) {
        printf("\n%d syncmodel check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall syncmodel checks passed\n");
    return 0;
}
