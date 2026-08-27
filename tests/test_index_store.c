/* test_index_store.c - host check for the Phase 4b on-disk index codec
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Round-trips a FolderState through index_store_encode/decode and checks the
 * records, block hashes and sequence high-water survive; plus the rejection
 * cases (wrong folder, wrong short_id, bad magic, truncation) that must make the
 * caller fall back to a clean full rescan. Built with FOLDSTATE_HOST_TEST
 * (index_store.c + foldstate.c + pbuf.c).
 */

#include "index_store.h"
#include "foldstate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

static void mkfile(SyncMeta *m, const char *name, int64_t size, int64_t mtime,
                   uint64_t verid, uint64_t verval)
{
    memset(m, 0, sizeof(*m));
    strcpy(m->name, name);
    m->type             = BEP_FILE_FILE;
    m->size             = size;
    m->permissions      = 0644;
    m->modified_s       = mtime;
    m->block_size       = 128 * 1024;
    m->has_content_hash = 1;
    m->content_hash[0]  = (unsigned char)size;
    m->sequence         = mtime;            /* arbitrary distinct value */
    m->version.num_counters      = 1;
    m->version.counters[0].id    = verid;
    m->version.counters[0].value = verval;
}

/* Populate a folder with a few representative records. */
static void populate(FolderState *fs)
{
    SyncMeta      m;
    unsigned char h[3][BEP_HASH_LEN];
    int           i;

    for (i = 0; i < 3; i++) memset(h[i], 0x10 + i, BEP_HASH_LEN);

    mkfile(&m, "a.txt", 100, 1000, 0xA1, 7);
    foldstate_upsert(fs, &m, h, 1);                 /* 1 block */

    mkfile(&m, "sub/big.bin", 300000, 1001, 0xA1, 9);
    foldstate_upsert(fs, &m, h, 3);                 /* 3 blocks */

    memset(&m, 0, sizeof(m));                        /* a directory (no blocks) */
    strcpy(m.name, "sub");
    m.type = BEP_FILE_DIRECTORY; m.permissions = 0755; m.modified_s = 1002;
    m.modified_by = 0xC0FFEE01UL;                    /* survives the codec */
    m.sequence = 3;
    m.version.num_counters = 1; m.version.counters[0].id = 0xA1; m.version.counters[0].value = 3;
    foldstate_upsert(fs, &m, NULL, 0);

    memset(&m, 0, sizeof(m));                        /* a tombstone */
    strcpy(m.name, "gone.txt");
    m.type = BEP_FILE_FILE; m.deleted = 1; m.modified_s = 1003; m.sequence = 4;
    m.version.num_counters = 1; m.version.counters[0].id = 0xA1; m.version.counters[0].value = 4;
    foldstate_upsert(fs, &m, NULL, 0);

    memset(&m, 0, sizeof(m));    /* an invalid "we knowingly don't store this"
                                  * record (see worker.c announce_unstorable);
                                  * losing the flag across a restart would let
                                  * the scanner tombstone it - i.e. propagate a
                                  * DELETE of the peer's file - so it must
                                  * round-trip. */
    strcpy(m.name, "unstorable-name-way-too-long.mkv");
    m.type = BEP_FILE_FILE; m.invalid = 1; m.size = 5000; m.modified_s = 1004;
    m.sequence = 5;
    m.version.num_counters = 1; m.version.counters[0].id = 0xB2; m.version.counters[0].value = 9;
    foldstate_upsert(fs, &m, NULL, 0);

    fs->sequence = 42;                               /* high-water */
}

/* True if two records match on the fields the codec carries. */
static int meta_eq(const SyncMeta *a, const SyncMeta *b)
{
    if (strcmp(a->name, b->name) || a->type != b->type || a->size != b->size ||
        a->permissions != b->permissions || a->modified_s != b->modified_s ||
        a->modified_ns != b->modified_ns ||
        a->modified_by != b->modified_by || a->deleted != b->deleted ||
        a->invalid != b->invalid || a->sequence != b->sequence ||
        a->block_size != b->block_size ||
        a->has_content_hash != b->has_content_hash)
        return 0;
    if (a->has_content_hash &&
        memcmp(a->content_hash, b->content_hash, BEP_HASH_LEN))
        return 0;
    if (a->version.num_counters != b->version.num_counters)
        return 0;
    {
        int i;
        for (i = 0; i < a->version.num_counters; i++)
            if (a->version.counters[i].id != b->version.counters[i].id ||
                a->version.counters[i].value != b->version.counters[i].value)
                return 0;
    }
    return 1;
}

static void test_roundtrip(void)
{
    FolderState   src, dst;
    unsigned char buf[8192];
    int           len, i, all = 1;

    foldstate_init(&src, "default", 0xDEADBEEF);
    populate(&src);

    len = index_store_encode(&src, buf, sizeof(buf));
    ok("encode non-zero", len > 0 && (size_t)len <= index_store_size(&src));

    foldstate_init(&dst, "default", 0xDEADBEEF);
    ok("decode ok", index_store_decode(&dst, buf, len) == 1);
    ok("record count", dst.num_files == src.num_files);
    ok("seq high-water restored", dst.sequence == 42);
    ok("decoded clean", dst.dirty == 0);

    for (i = 0; i < src.num_files; i++) {
        SyncMeta   sm, dm;
        FolderRec *dr;

        foldstate_meta(&src, &src.files[i], &sm);
        dr = foldstate_find(&dst, sm.name);
        if (!dr) { all = 0; continue; }
        foldstate_meta(&dst, dr, &dm);
        if (!meta_eq(&sm, &dm)) { all = 0; continue; }
        /* block hashes survive */
        {
            unsigned char a[8][BEP_HASH_LEN], b[8][BEP_HASH_LEN];
            int na, nb, ta, tb;
            na = foldstate_blocks(&src, sm.name, a, 8, &ta);
            nb = foldstate_blocks(&dst, sm.name, b, 8, &tb);
            if (na != nb || ta != tb || memcmp(a, b, (size_t)na * BEP_HASH_LEN))
                all = 0;
        }
    }
    ok("all records + blocks round-trip", all);

    foldstate_free(&src);
    foldstate_free(&dst);
}

static void test_rejects(void)
{
    FolderState   src, dst;
    unsigned char buf[8192];
    int           len;

    foldstate_init(&src, "default", 0xDEADBEEF);
    populate(&src);
    len = index_store_encode(&src, buf, sizeof(buf));

    /* Wrong folder id -> reject, leave dst empty. */
    foldstate_init(&dst, "other", 0xDEADBEEF);
    ok("reject wrong folder", index_store_decode(&dst, buf, len) == 0);
    ok("empty after reject (folder)", dst.num_files == 0 && dst.sequence == 0);

    /* Wrong short id -> reject. */
    foldstate_init(&dst, "default", 0x1234);
    ok("reject wrong short_id", index_store_decode(&dst, buf, len) == 0);

    /* Corrupt magic (first payload byte after the field-1 tag). */
    {
        unsigned char bad[8192];
        memcpy(bad, buf, len);
        bad[1] ^= 0xFF;                          /* mangle the magic varint */
        foldstate_init(&dst, "default", 0xDEADBEEF);
        ok("reject bad magic", index_store_decode(&dst, bad, len) == 0);
    }

    /* Truncation -> reject, dst empty (full rescan). */
    foldstate_init(&dst, "default", 0xDEADBEEF);
    ok("reject truncated", index_store_decode(&dst, buf, len - 5) == 0);
    ok("empty after truncation", dst.num_files == 0);

    /* Empty/zero-length -> not our index. */
    foldstate_init(&dst, "default", 0xDEADBEEF);
    ok("reject empty blob", index_store_decode(&dst, buf, 0) == 0);

    foldstate_free(&src);
}

/* index_store_size must never under-estimate index_store_encode, because the
 * caller allocates from the estimate and an overflowed encode returns 0 - a
 * folder that then never persists. The estimate is a hand-tallied budget, so
 * this drives it with records built to be maximal on the wire rather than
 * merely realistic: every int64 negative (pbuf_write_int64 sign-extends, so
 * those cost a full-width 10-byte varint - a peer can put a negative size or
 * mtime in a FileInfo and meta_from_fileinfo copies it through unclamped),
 * every uint64 all-ones, a longest-possible name, a full counter vector, and
 * a large block list. Asserts the RELATION, not a byte count, so it keeps
 * holding when a field is added. */
static void test_size_estimate_covers_worst_case(void)
{
    FolderState    fs;
    unsigned char *buf;
    unsigned char  hashes[64][BEP_HASH_LEN];
    size_t         est;
    int            i, len, worst_slack = 1 << 30;

    foldstate_init(&fs, "a-folder-id-of-quite-considerable-length-for-a-test",
                   0xFFFFFFFFFFFFFFFFULL);
    memset(hashes, 0xEE, sizeof(hashes));

    for (i = 0; i < 40; i++) {
        SyncMeta m;
        int      k;

        memset(&m, 0, sizeof(m));
        memset(m.name, 'n', BEP_PATH_MAX - 1);       /* longest storable name */
        m.name[BEP_PATH_MAX - 1] = '\0';
        m.name[0] = (char)('a' + (i % 26));          /* keep them distinct */
        m.name[1] = (char)('a' + (i / 26));
        m.type             = 200;                    /* not a real enum value */
        m.size             = -1;                     /* 10-byte varints below */
        m.modified_s       = -1;
        m.modified_ns      = -1;
        m.sequence         = -1;
        m.block_size       = -1;
        m.permissions      = 0xFFFFFFFFUL;
        m.modified_by      = 0xFFFFFFFFFFFFFFFFULL;
        m.deleted          = 1;
        m.invalid          = 1;
        m.has_content_hash = 1;
        memset(m.content_hash, 0xAB, BEP_HASH_LEN);
        m.version.num_counters = BEP_MAX_COUNTERS;
        for (k = 0; k < BEP_MAX_COUNTERS; k++) {
            m.version.counters[k].id    = 0xFFFFFFFFFFFFFFFFULL;
            m.version.counters[k].value = 0xFFFFFFFFFFFFFFFFULL;
        }
        if (!foldstate_upsert(&fs, &m, hashes, 64)) {
            ok("worst-case: upsert", 0);
            foldstate_free(&fs);
            return;
        }
    }

    est = index_store_size(&fs);
    buf = malloc(est);
    if (!buf) { ok("worst-case: alloc", 0); foldstate_free(&fs); return; }

    len = index_store_encode(&fs, buf, est);
    ok("worst-case encode fits the estimate", len > 0);
    ok("worst-case estimate is not an under-count", len > 0 && (size_t)len <= est);
    if (len > 0)
        worst_slack = (int)(est - (size_t)len);
    printf("     (estimate %lu, encoded %d, slack %d over %d records)\n",
           (unsigned long)est, len, worst_slack, fs.num_files);

    /* And it still decodes - an estimate fixed by over-allocating would pass
     * the check above while writing something the reader chokes on. */
    if (len > 0) {
        FolderState dst;
        foldstate_init(&dst, "a-folder-id-of-quite-considerable-length-for-a-test",
                       0xFFFFFFFFFFFFFFFFULL);
        ok("worst-case round-trips", index_store_decode(&dst, buf, len) == 1 &&
                                     dst.num_files == fs.num_files);
        foldstate_free(&dst);
    }

    free(buf);
    foldstate_free(&fs);
}

/* A blob cut short must be REFUSED, not half-decoded. pbuf_read_tag reports a
 * clean end at any field boundary, so before the header carried a record count
 * a truncated file decoded as a valid one: whatever half a record had been
 * assembled was committed with the missing fields at their memset defaults -
 * a tombstone reloading LIVE, or a real file reloading with block_size 0,
 * which the announce path then turns into a malformed Index for the peer.
 * Truncation is reachable: folder_state_write is atomic, but a power loss or
 * a Guru before the filesystem flushes the renamed file is exactly the history
 * this project has. Every cut is tried, not a sample. */
static void test_truncation_refused(void)
{
    FolderState   src;
    unsigned char buf[8192];
    int           len, cut, accepted = 0, first_bad = -1;

    foldstate_init(&src, "default", 0xDEADBEEF);
    populate(&src);
    len = index_store_encode(&src, buf, sizeof(buf));
    ok("truncation: encoded", len > 0);

    for (cut = 1; cut < len; cut++) {
        FolderState dst;
        foldstate_init(&dst, "default", 0xDEADBEEF);
        if (index_store_decode(&dst, buf, cut) == 1) {
            accepted++;
            if (first_bad < 0)
                first_bad = cut;
        }
        foldstate_free(&dst);
    }
    if (accepted)
        printf("     (%d of %d truncations accepted, first at %d bytes)\n",
               accepted, len - 1, first_bad);
    ok("every truncation refused", accepted == 0);

    /* The whole blob is of course still fine. */
    {
        FolderState dst;
        foldstate_init(&dst, "default", 0xDEADBEEF);
        ok("untruncated still accepted",
           index_store_decode(&dst, buf, len) == 1 &&
           dst.num_files == src.num_files);
        foldstate_free(&dst);
    }
    foldstate_free(&src);
}

/* A tag whose wire type does not match its field is corruption, and taking it
 * at face value reinterprets the rest of the stream. */
static void test_wire_type_refused(void)
{
    FolderState   src, dst;
    unsigned char buf[8192];
    int           len, i, flipped = 0, accepted = 0;

    foldstate_init(&src, "default", 0xDEADBEEF);
    populate(&src);
    len = index_store_encode(&src, buf, sizeof(buf));

    /* Byte 0 is unambiguously the F_MAGIC tag (field 1, wire type 0 = 0x08);
     * flip it to length-delimited. Only known tag positions are targeted -
     * flipping a byte that happens to sit in a payload proves nothing, since
     * the reader never looks at it as a tag. */
    (void)i;
    ok("first byte is the magic tag", buf[0] == 0x08);
    buf[0] = 0x0A;                              /* field 1, wire type 2 */
    flipped++;
    foldstate_init(&dst, "default", 0xDEADBEEF);
    if (index_store_decode(&dst, buf, len) == 1)
        accepted++;
    foldstate_free(&dst);
    buf[0] = 0x08;

    ok("wire-type flips tried", flipped > 0);
    ok("wire-type flip refused", accepted == 0);
    foldstate_free(&src);
}

int main(void)
{
    test_roundtrip();
    test_rejects();
    test_size_estimate_covers_worst_case();
    test_truncation_refused();
    test_wire_type_refused();
    if (failures) { printf("\n%d index_store check(s) FAILED\n", failures); return 1; }
    printf("\nall index_store checks passed\n");
    return 0;
}
