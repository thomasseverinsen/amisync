/* test_converge.c - randomized convergence property test for the sync model
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The unit checks in test_syncmodel.c verify individual decisions against
 * hand-built cases. This drives TWO simulated devices through thousands of
 * randomized operation sequences - creates, edits, deletes, re-adds, and
 * partial/out-of-order announcements, including concurrent edits of the same
 * file - and then asserts the properties that actually matter to a user:
 *
 *   CONVERGENCE   after both sides have exchanged everything, their live file
 *                 sets are identical (same names, same content).
 *   TERMINATION   that exchange reaches a fixed point instead of ping-ponging
 *                 forever (a sync loop would burn the peer's bandwidth).
 *   NO LOST WORK  for a file only ever touched by ONE device, the other device
 *                 ends up with exactly that device's final state - no lost
 *                 update, no resurrected file, no spurious deletion.
 *
 * The decision logic under test is the real one (sync_classify_incoming,
 * sync_version_compare, sync_bump_version, sync_make_conflict_name); only the
 * "disk", the index and the transport are simulated, so this runs on the build
 * host with no AmiSSL, sockets or files.
 *
 * Usage: test_converge [scenarios] [seed]   (defaults 4000, 0x5EED1234)
 * A failure prints the seed and scenario number so it can be replayed.
 */

#include "syncmodel.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAXF        64        /* files per node (names + conflict copies)   */
#define NAME_POOL    5        /* distinct file names an operation may pick  */
#define MAX_OPS     14        /* local/sync operations per scenario         */
#define SETTLE_MAX  24        /* announce rounds allowed to reach a fixpoint */

static int failures;
static unsigned long rng;
static int tracing;              /* dump operations for one scenario */
/* Wall clock for conflict-copy names. Real conflict names embed the current
 * time, so two conflicts on the same file produce different names; advance it
 * per conflict or the second copy would overwrite the first (a simulation
 * artifact, not a real behaviour). */
static long conflict_clock = 1784291696L;

static unsigned rnd(unsigned n)
{
    rng = rng * 1103515245UL + 12345UL;
    return (unsigned)((rng >> 16) % n);
}

/* ---- simulated device ------------------------------------------------- */

typedef struct { BepFileInfo f[MAXF]; int n; } Disk;
typedef struct { SyncMeta    f[MAXF]; int n; } Idx;

typedef struct {
    Idx         idx;          /* what we would announce to a peer          */
    Disk        disk;         /* what is actually on this device           */
    uint64_t    id;           /* short device id (version-counter key)     */
    const char *tag;          /* 7-char id prefix for conflict copy names  */
} Node;

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
    if (!e) {
        if (d->n >= MAXF)
            return;                       /* simulation capacity, not a bug */
        e = &d->f[d->n++];
    }
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

static void idx_put(Idx *x, const BepFileInfo *fi)
{
    SyncMeta *m = idx_find(x, fi->name);
    if (!m) {
        if (x->n >= MAXF)
            return;
        m = &x->f[x->n++];
    }
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

/* Announce one record from a peer and apply it exactly as the worker does. */
static void apply_one(Node *n, const BepFileInfo *src)
{
    SyncAction act = sync_classify_incoming(idx_find(&n->idx, src->name),
                                            FOLDER_SENDRECEIVE, src);
    if (act == SYNC_CONFLICT) {
        BepFileInfo *loc = disk_find(&n->disk, src->name);
        if (loc) {                        /* preserve our loser, then fetch */
            BepFileInfo copy = *loc;
            if (sync_make_conflict_name(copy.name, sizeof(copy.name), loc->name,
                                        (int64_t)conflict_clock++, n->tag, 0)) {
                sync_bump_version(&copy.version, &copy.version, n->id,
                                  (uint64_t)copy.modified_s);
                disk_put(&n->disk, &copy);
                idx_put(&n->idx, &copy);
            }
        }
        act = SYNC_FETCH;
    }
    if (act == SYNC_FETCH) {
        disk_put(&n->disk, src);          /* "download" the content */
        idx_put(&n->idx, src);
    } else if (act == SYNC_ADOPT) {
        idx_put(&n->idx, src);            /* metadata only: content already here */
    } else if (act == SYNC_DELETE) {
        disk_del(&n->disk, src->name);
        idx_put(&n->idx, src);            /* keep the tombstone */
    }
}

/* Announce every record we hold to 'to' (a full index exchange). */
static void announce_all(Node *from, Node *to)
{
    int i;
    for (i = 0; i < from->idx.n; i++) {
        BepFileInfo fi;
        SyncMeta   *m = &from->idx.f[i];
        memset(&fi, 0, sizeof(fi));
        strcpy(fi.name, m->name);
        fi.type             = m->type;
        fi.size             = m->size;
        fi.modified_s       = m->modified_s;
        fi.deleted          = m->deleted;
        fi.version          = m->version;
        fi.has_content_hash = m->has_content_hash;
        if (m->has_content_hash)
            memcpy(fi.content_hash, m->content_hash, BEP_HASH_LEN);
        apply_one(to, &fi);
    }
}

/* ---- local (scanner-side) operations ---------------------------------- */

/* A local create or edit: new content, version bumped with our counter -
 * exactly what scanner.c commit_file does. */
static void local_write(Node *n, const char *name, unsigned char content,
                        int64_t mtime)
{
    BepFileInfo  fi;
    SyncMeta    *prev = idx_find(&n->idx, name);

    memset(&fi, 0, sizeof(fi));
    strcpy(fi.name, name);
    fi.type             = BEP_FILE_FILE;
    fi.size             = 100 + content;      /* size tracks content */
    fi.modified_s       = mtime;
    fi.has_content_hash = 1;
    fi.content_hash[0]  = content;
    sync_bump_version(&fi.version, prev ? &prev->version : NULL, n->id,
                      (uint64_t)mtime);
    disk_put(&n->disk, &fi);
    idx_put(&n->idx, &fi);
}

/* A local delete: tombstone carrying our bumped counter, as the scanner's
 * missing-file sweep (commit_deletions) records it. */
static void local_delete(Node *n, const char *name, int64_t when)
{
    BepFileInfo  tomb;
    SyncMeta    *prev = idx_find(&n->idx, name);

    if (!disk_find(&n->disk, name))
        return;                                   /* nothing to delete */
    memset(&tomb, 0, sizeof(tomb));
    strcpy(tomb.name, name);
    tomb.type       = BEP_FILE_FILE;
    tomb.deleted    = 1;
    tomb.modified_s = when;
    sync_bump_version(&tomb.version, prev ? &prev->version : NULL, n->id,
                      (uint64_t)when);
    disk_del(&n->disk, name);
    idx_put(&n->idx, &tomb);
}

/* ---- convergence checking --------------------------------------------- */

/* A cheap order-independent fingerprint of a node's LIVE files, used to detect
 * that the settle loop has stopped changing anything. */
static unsigned long live_print(Node *n)
{
    unsigned long h = 1469598103UL;
    int i;
    for (i = 0; i < n->disk.n; i++) {
        BepFileInfo *f = &n->disk.f[i];
        const char  *p;
        unsigned long e = 2166136261UL;
        if (f->deleted)
            continue;
        for (p = f->name; *p; p++)
            e = (e ^ (unsigned char)*p) * 16777619UL;
        e = (e ^ f->content_hash[0]) * 16777619UL;
        /* Avalanche before summing. Without this, a one-bit content change
         * shifts 'e' by a tiny amount, and two such shifts in one round can
         * cancel in the sum - making a genuinely changed pair of nodes look
         * unchanged and stopping the settle loop early (a false divergence). */
        e ^= e >> 15; e *= 2246822519UL;
        e ^= e >> 13; e *= 3266489917UL;
        e ^= e >> 16;
        h += e;                                   /* sum: order-independent */
    }
    return h;
}

static int live_count(Node *n)
{
    int i, c = 0;
    for (i = 0; i < n->disk.n; i++)
        if (!n->disk.f[i].deleted)
            c++;
    return c;
}

/* True if both nodes hold the same live files with the same content. */
static int disks_agree(Node *a, Node *b)
{
    int i;
    if (live_count(a) != live_count(b))
        return 0;
    for (i = 0; i < a->disk.n; i++) {
        BepFileInfo *f = &a->disk.f[i], *o;
        if (f->deleted)
            continue;
        o = disk_find(&b->disk, f->name);
        if (!o || o->deleted || o->content_hash[0] != f->content_hash[0])
            return 0;
    }
    return 1;
}

/* Exchange indexes until nothing changes. Returns the number of rounds, or -1
 * if it never settled (a sync loop). */
static int settle(Node *a, Node *b)
{
    int r;
    for (r = 1; r <= SETTLE_MAX; r++) {
        unsigned long pa = live_print(a), pb = live_print(b);
        announce_all(a, b);
        announce_all(b, a);
        if (live_print(a) == pa && live_print(b) == pb)
            return r;
    }
    return -1;
}

static void fail(const char *what, unsigned long seed, int scenario)
{
    printf("FAIL %s (seed 0x%lX scenario %d)\n", what, seed, scenario);
    failures++;
}

int main(int argc, char **argv)
{
    long          scenarios = (argc > 1) ? strtol(argv[1], NULL, 0) : 4000;
    unsigned long seed      = (argc > 2) ? strtoul(argv[2], NULL, 0) : 0x5EED1234UL;
    long          trace_at  = (argc > 3) ? strtol(argv[3], NULL, 0) : -1;
    long          s;
    int           settled_max = 0;
    long          conflicts_seen = 0;

    rng = seed;
    printf("test_converge: %ld scenarios, seed 0x%lX\n", scenarios, seed);

    for (s = 0; s < scenarios; s++) {
        Node          A, B;
        unsigned char content = 1;
        int64_t       clock   = 1000;
        int           ops     = 3 + (int)rnd(MAX_OPS - 2);
        int           i, rounds;
        /* Per-name record of which devices touched it: bit 0 = A, bit 1 = B. */
        unsigned char touched[NAME_POOL];
        char          nm[NAME_POOL][8];

        tracing = (s == trace_at);
        if (tracing)
            printf("--- scenario %ld (%d ops) ---\n", s, ops);

        memset(&A, 0, sizeof(A));
        memset(&B, 0, sizeof(B));
        memset(touched, 0, sizeof(touched));
        A.id = 0xA1; A.tag = "AAAAAAA";
        B.id = 0xB2; B.tag = "BBBBBBB";
        for (i = 0; i < NAME_POOL; i++)
            sprintf(nm[i], "f%d.txt", i);

        for (i = 0; i < ops; i++) {
            int   which = (int)rnd(2);
            Node *n     = which ? &B : &A;
            int   fidx  = (int)rnd(NAME_POOL);
            int   op    = (int)rnd(10);

            clock += 1 + rnd(3);            /* mtimes advance, sometimes tie */

            if (op < 4) {                   /* create or edit */
                if (tracing)
                    printf("  %c: write %s content=%d mtime=%ld\n",
                           which ? 'B' : 'A', nm[fidx], content, (long)clock);
                local_write(n, nm[fidx], content++, clock);
                touched[fidx] |= (unsigned char)(1 << which);
            } else if (op < 6) {            /* delete */
                if (disk_find(&n->disk, nm[fidx])) {
                    if (tracing)
                        printf("  %c: delete %s mtime=%ld\n",
                               which ? 'B' : 'A', nm[fidx], (long)clock);
                    local_delete(n, nm[fidx], clock);
                    touched[fidx] |= (unsigned char)(1 << which);
                }
            } else if (op < 8) {            /* partial sync one way */
                if (tracing) printf("  sync A->B\n");
                announce_all(&A, &B);
            } else {
                if (tracing) printf("  sync B->A\n");
                announce_all(&B, &A);
            }
        }

        rounds = settle(&A, &B);
        if (tracing) {
            int k;
            printf("  settled in %d round(s)\n", rounds);
            for (k = 0; k < A.disk.n; k++)
                printf("  A disk: %-40s content=%d%s\n", A.disk.f[k].name,
                       A.disk.f[k].content_hash[0],
                       A.disk.f[k].deleted ? " (deleted)" : "");
            for (k = 0; k < B.disk.n; k++)
                printf("  B disk: %-40s content=%d%s\n", B.disk.f[k].name,
                       B.disk.f[k].content_hash[0],
                       B.disk.f[k].deleted ? " (deleted)" : "");
        }
        if (rounds < 0) {
            fail("did not settle (possible sync loop)", seed, (int)s);
            continue;
        }
        if (rounds > settled_max)
            settled_max = rounds;

        if (!disks_agree(&A, &B)) {
            fail("devices diverged after settling", seed, (int)s);
            continue;
        }

        /* No lost work: a file only one device ever touched must end up on both
         * in exactly that device's final state. */
        for (i = 0; i < NAME_POOL; i++) {
            Node        *owner, *peer;
            BepFileInfo *mine, *theirs;
            if (touched[i] != 1 && touched[i] != 2)
                continue;                    /* untouched or concurrent */
            owner = (touched[i] == 1) ? &A : &B;
            peer  = (touched[i] == 1) ? &B : &A;
            /* The owner's own disk is the reference; both must match it. */
            mine   = disk_find(&owner->disk, nm[i]);
            theirs = disk_find(&peer->disk, nm[i]);
            if (mine && !mine->deleted) {
                if (!theirs || theirs->deleted) {
                    fail("single-writer file missing on the peer", seed, (int)s);
                    break;
                }
                if (theirs->content_hash[0] != mine->content_hash[0]) {
                    fail("single-writer file has stale content on the peer",
                         seed, (int)s);
                    break;
                }
            } else if (theirs && !theirs->deleted) {
                fail("deleted file resurrected on the peer", seed, (int)s);
                break;
            }
        }

        /* Count scenarios that produced a conflict copy, so we can confirm the
         * randomiser is actually reaching the interesting states. */
        for (i = 0; i < A.disk.n; i++)
            if (strstr(A.disk.f[i].name, "sync-conflict")) { conflicts_seen++; break; }
    }

    printf("settled within %d round(s) at worst; %ld scenario(s) produced a "
           "conflict copy\n", settled_max, conflicts_seen);
    if (failures) {
        printf("\n%d convergence check(s) FAILED\n", failures);
        return 1;
    }
    printf("all convergence checks passed\n");
    return 0;
}
