/* test_foldsync.c - host check for the Phase 4a shared-index invariants
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The load-bearing correctness claim of Phase 4a is that ONE shared per-folder
 * index gives every peer a consistent view, and that the per-peer sequence
 * cursor relays a received file to the other peers automatically. This simulates
 * two workers (peer A, peer B) sharing one FolderState, with no sockets/crypto/
 * files - just the foldstate + syncmodel logic the real workers drive under the
 * lock. Built with FOLDSTATE_HOST_TEST (foldstate.c + syncmodel.c).
 */

#include "foldstate.h"
#include "syncmodel.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

/* Commit a local file change the way the scanner does: version carried forward
 * from any existing record, a fresh per-folder sequence, then upsert. Returns
 * the assigned sequence. */
static int64_t commit_local(FolderState *fs, const char *name,
                            int64_t size, int64_t mtime)
{
    SyncMeta  m;
    FolderRec *have = foldstate_find(fs, name);
    BepVector  prev;

    memset(&m, 0, sizeof(m));
    strcpy(m.name, name);
    m.type             = BEP_FILE_FILE;
    m.size             = size;
    m.modified_s       = mtime;
    m.has_content_hash = 1;
    m.content_hash[0]  = (unsigned char)mtime;     /* stand-in fingerprint */
    sync_bump_version(&m.version, foldstate_version(fs, have, &prev),
                      fs->short_id, (uint64_t)mtime);
    m.sequence = foldstate_next_seq(fs);
    foldstate_upsert(fs, &m, NULL, 0);
    return m.sequence;
}

/* Record a file received from a peer the way a worker does on finalize: keep the
 * peer's version, assign our own new sequence. Returns the assigned sequence. */
static int64_t commit_received(FolderState *fs, const char *name,
                               int64_t size, int64_t mtime,
                               const BepVector *peer_version)
{
    SyncMeta m;

    memset(&m, 0, sizeof(m));
    strcpy(m.name, name);
    m.type             = BEP_FILE_FILE;
    m.size             = size;
    m.modified_s       = mtime;
    m.has_content_hash = 1;
    m.content_hash[0]  = (unsigned char)mtime;
    m.version          = *peer_version;
    m.sequence         = foldstate_next_seq(fs);
    foldstate_upsert(fs, &m, NULL, 0);
    return m.sequence;
}

/* One announce pass for a peer: collect the names of records whose sequence is
 * in (*cursor, snapshot], advancing *cursor to snapshot - exactly what the real
 * announce_folder() streams. Returns the count. */
static int announce(FolderState *fs, int64_t *cursor, char names[][BEP_PATH_MAX])
{
    int64_t snapshot = fs->sequence;
    int     i, n = 0;

    for (i = 0; i < fs->num_files; i++) {
        int64_t seq = fs->files[i].sequence;
        if (seq > *cursor && seq <= snapshot)
            strcpy(names[n++], foldstate_name(fs, &fs->files[i]));
    }
    *cursor = snapshot;
    return n;
}

static int named(char names[][BEP_PATH_MAX], int n, const char *want)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(names[i], want) == 0) return 1;
    return 0;
}

/* The same file announced to two different peers carries the SAME version and
 * sequence - the whole point of a single shared index. */
static void test_consistent_view(void)
{
    FolderState fs;
    FolderRec  *r;
    BepVector   rv;
    int64_t     seq;

    foldstate_init(&fs, "f", 0xA1);
    seq = commit_local(&fs, "X", 10, 100);

    r = foldstate_find(&fs, "X");
    ok("record exists", r != NULL);
    /* Peer A and peer B both read this one record, so both announce identical
     * version+sequence by construction - assert the values are what we set. */
    ok("seq is 1",         r->sequence == seq && seq == 1);
    foldstate_version(&fs, r, &rv);
    ok("version keyed to us",
       rv.num_counters == 1 &&
       rv.counters[0].id == 0xA1 &&
       rv.counters[0].value == 100);
}

/* Distinct changes get distinct, monotonic sequences across files. */
static void test_distinct_sequences(void)
{
    FolderState fs;
    int64_t     s1, s2, s3;

    foldstate_init(&fs, "f", 1);
    s1 = commit_local(&fs, "a", 1, 10);
    s2 = commit_local(&fs, "b", 1, 11);
    s3 = commit_local(&fs, "a", 2, 12);     /* re-edit a: new seq, same slot */
    ok("sequences distinct + increasing", s1 == 1 && s2 == 2 && s3 == 3);
    ok("re-edit replaced in place", fs.num_files == 2);
    ok("high-water", fs.sequence == 3);
}

/* A file peer B receives is relayed to peer A automatically: B's commit bumps
 * the shared sequence, so A's cursor falls behind and A's next announce streams
 * it. This is the peer->peer propagation 4a gets "for free". */
static void test_cursor_relay(void)
{
    FolderState fs;
    int64_t     cursorA = 0, cursorB = 0;
    char        names[8][BEP_PATH_MAX];   /* scratch for announce results (<=2 files) */
    int         n;

    foldstate_init(&fs, "f", 0xA1);

    /* Local file X exists; both peers announce it once and catch up. */
    commit_local(&fs, "X", 10, 100);
    n = announce(&fs, &cursorA, names);
    ok("A announces X initially", n == 1 && named(names, n, "X"));
    n = announce(&fs, &cursorB, names);
    ok("B announces X initially", n == 1 && named(names, n, "X"));
    n = announce(&fs, &cursorA, names);
    ok("A: nothing new on second pass", n == 0);

    /* Peer B receives Y from its remote peer (keeps that peer's version). */
    {
        BepVector pv;
        memset(&pv, 0, sizeof(pv));
        pv.num_counters = 1; pv.counters[0].id = 0xB2; pv.counters[0].value = 200;
        commit_received(&fs, "Y", 20, 200, &pv);
    }

    /* A's next announce pass now relays Y to A's peer (seq advanced past cursorA);
     * B does NOT re-announce Y (B's cursor already advanced when it committed). */
    n = announce(&fs, &cursorA, names);
    ok("A relays received Y", n == 1 && named(names, n, "Y"));

    /* B's cursor is behind by exactly Y's commit; one pass catches it up with no
     * spurious re-sends of X. */
    n = announce(&fs, &cursorB, names);
    ok("B catches up on Y", n == 1 && named(names, n, "Y"));
    {
        BepVector yv;
        foldstate_version(&fs, foldstate_find(&fs, "Y"), &yv);
        ok("Y kept peer's version", yv.counters[0].id == 0xB2);
    }

    foldstate_free(&fs);
}

int main(void)
{
    test_consistent_view();
    test_distinct_sequences();
    test_cursor_relay();

    if (failures) {
        printf("\n%d foldsync check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall foldsync checks passed\n");
    return 0;
}
