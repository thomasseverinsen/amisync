/* folder.c - local folder scanning, block I/O and received-file storage
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See folder.h. dos.library does the enumeration and file I/O; AmiSSL's
 * SHA-256 hashes each block. Paths are joined with AddPart() so volume/dir
 * forms ("DH0:Sync", "Work:docs/") work without hand-rolled separator logic.
 * BEP relative names use '/', which is also AmigaOS's separator, so a relative
 * name drops straight into AddPart().
 */

#include <string.h>

#include <exec/memory.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <dos/dos.h>
#include <dos/dosextens.h>

#include <openssl/sha.h>

#include "folder.h"
#include "pathsafe.h"
#include "log.h"

/* A generous join buffer: a folder path plus a relative name plus our temp
 * suffix, with headroom. */
#define FULL_MAX  512

/* Filename length every AmigaOS filesystem stores intact: FFS's 30-char per
 * component is the floor, so a name no longer than this fits everywhere and
 * needs no probe. Longer names are filesystem-dependent (PFS3 ~107, SFS ~105,
 * FFS truncates) and must be probed. */
#define FOLDER_SAFE_NAME_LEN  30

/* Suffix marking a staged, in-progress file. skippable() hides these from the
 * scanner, gc_walk sweeps stale ones, and every buffer guard below budgets for
 * AMITMP_LEN (+1 for the NUL) rather than restating the arithmetic. */
#define AMITMP      ".amitmp"
#define AMITMP_LEN  ((int)sizeof(AMITMP) - 1)

/* 16 hex chars (plus NUL) of the 64-bit FNV-1a of 's': a stable, always-legal
 * filename stem for any string (index files, over-long temp names). */
static void fnv16_hex(const char *s, char out[17])
{
    uint64_t h = 1469598103934665603ULL;         /* FNV offset basis */
    int      i;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;                   /* FNV prime */
    }
    for (i = 0; i < 16; i++) {
        int nib = (int)((h >> ((15 - i) * 4)) & 0xF);
        out[i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    out[16] = '\0';
}

/* Seconds between the Unix epoch (1970-01-01) and the Amiga epoch (1978-01-01):
 * 2922 days (8 years incl. the 1972 and 1976 leap days) * 86400. */
#define AMIGA_UNIX_OFFSET  252460800LL

/* Seconds EAST of UTC: how far ahead of UTC this machine's clock is set. An
 * AmigaOS clock holds LOCAL time, while BEP timestamps are Unix UTC, and
 * without this the two were treated as the same thing: every file we announced
 * carried a time an offset away from the real one, and every file we received
 * was stamped on disk an offset away from what the peer meant. Sync itself
 * never noticed - the conversion was wrong symmetrically, so it round-tripped -
 * which is exactly why it could sit there unseen.
 *
 * Set once at startup from 'tzoffset'; the daemon and every subprocess share
 * the data segment, so one write is visible to all (same contract as
 * g_versioning). 0 is the old behaviour, and stays the default: a machine that
 * has not said where it is keeps reading its clock as UTC rather than being
 * silently shifted by a guess. */
static int32_t g_tz_east_s = 0;

void folder_set_tz_offset(int seconds_east)
{
    g_tz_east_s = (int32_t)seconds_east;
}

int folder_tz_offset(void)
{
    return (int)g_tz_east_s;
}

static int64_t ds_to_unix(const struct DateStamp *ds)
{
    return (int64_t)ds->ds_Days * 86400
         + (int64_t)ds->ds_Minute * 60
         + (int64_t)ds->ds_Tick / TICKS_PER_SECOND
         + AMIGA_UNIX_OFFSET
         - g_tz_east_s;                        /* local -> UTC */
}

/* Map a Unix permission mode to AmigaOS protection bits. The RWED bits are
 * active-low (a SET bit FORBIDS the operation), so a fully-accessible file has
 * them clear. We map the owner's r/w/x; write also gates delete, which is the
 * closest Amiga equivalent. Archive/script/etc. are left clear. */
static ULONG unix_mode_to_protection(uint32_t mode)
{
    ULONG p = 0;                                 /* rwed all allowed */
    if (!(mode & 0400)) p |= FIBF_READ;
    if (!(mode & 0200)) p |= FIBF_WRITE | FIBF_DELETE;
    if (!(mode & 0100)) p |= FIBF_EXECUTE;
    return p;
}

/* A DateStamp cannot represent anything before 1978, so an older mtime is
 * clamped to the Amiga epoch - silently, and the file then reports a different
 * mtime than the peer holds. Nothing can be done about the representation; it
 * is written down here because the symptom (one file that never settles) is
 * otherwise a long hunt. */
static void unix_to_ds(int64_t unix_s, struct DateStamp *ds)
{
    int64_t a = unix_s + g_tz_east_s - AMIGA_UNIX_OFFSET;   /* UTC -> local */
    if (a < 0)
        a = 0;
    ds->ds_Days   = (LONG)(a / 86400);
    ds->ds_Minute = (LONG)((a % 86400) / 60);
    ds->ds_Tick   = (LONG)((a % 60) * TICKS_PER_SECOND);
}

/* File versioning (trash-can): when on, a file about to be overwritten or
 * deleted by a remote change is first moved into <folder>/.stversions/, keeping
 * only its most recent old copy. Set once at startup (folder_set_versioning);
 * the daemon and every subprocess share the data segment, so this is visible to
 * all of them. */
static int g_versioning = 0;

void folder_set_versioning(int on)
{
    g_versioning = on ? 1 : 0;
}

/* True for entries we never sync: the .stignore file itself, our own in-progress
 * temp files, and - at the folder ROOT only - the .stversions archive drawer.
 * 'depth' is 0 at the root. .stversions is root-only (matching Syncthing) so a
 * peer's legitimately-nested directory named ".stversions" still syncs; if it
 * were skipped at every depth, the inbound path (which does not consult
 * skippable) would write and index it, then the next scan would not see it and
 * would tombstone it - a spurious DELETE back to the peer. Case-insensitive
 * (AmigaOS file systems are). */
static int skippable(const char *name, int depth)
{
    size_t n = strlen(name);
    if (strcasecmp(name, ".stignore") == 0)
        return 1;
    if (depth == 0 && strcasecmp(name, ".stversions") == 0)
        return 1;
    if (n >= AMITMP_LEN && strcasecmp(name + n - AMITMP_LEN, AMITMP) == 0)
        return 1;
    return 0;
}

/* Join 'root' and 'name' into 'full' (cap bytes), fully bounded. AddPart()
 * already guards the component append; this adds the guard the bare strcpy()
 * of 'root' was missing, so an over-long configured folder path cannot overrun
 * 'full'. Returns 1 on success, 0 if the joined path would not fit. */
static int join_full(char *full, int cap, const char *root, const char *name)
{
    if ((int)strlen(root) >= cap)
        return 0;
    strcpy(full, root);
    return AddPart((STRPTR)full, (STRPTR)name, cap) ? 1 : 0;
}

/* Make sure the directory at 'abs' exists, creating it if not. Both Lock and
 * CreateDir hand back a lock to release. Returns 1 if the directory is there
 * afterwards - including when someone else created it between our two calls,
 * which is why a failed CreateDir re-checks rather than reporting failure. */
static int ensure_dir_exists(const char *abs)
{
    BPTR lock = Lock((STRPTR)abs, ACCESS_READ);

    if (lock) {
        UnLock(lock);
        return 1;
    }
    lock = CreateDir((STRPTR)abs);
    if (lock) {
        UnLock(lock);
        return 1;
    }
    lock = Lock((STRPTR)abs, ACCESS_READ);      /* lost a race? */
    if (lock) {
        UnLock(lock);
        return 1;
    }
    return 0;
}

/* Join a relative directory prefix and a leaf name into 'out' (BEP_PATH_MAX)
 * with a '/' between. Returns 0 if the result would not fit - the relative
 * counterpart of join_full, so neither direction is bounded by hand. */
static int join_rel(char *out, const char *prefix, const char *name)
{
    size_t pl = strlen(prefix), nl = strlen(name);

    if (pl == 0) {
        if (nl >= BEP_PATH_MAX)
            return 0;
        strcpy(out, name);
        return 1;
    }
    if (pl + 1 + nl >= BEP_PATH_MAX)
        return 0;
    strcpy(out, prefix);
    out[pl] = '/';
    strcpy(out + pl + 1, name);
    return 1;
}

/* Create each directory component of 'rel' under 'root'. If 'include_last' is 0
 * the final component is treated as a file name and not created. 1 on success. */
static int ensure_path_dirs(const char *root, const char *rel, int include_last)
{
    char        abs[FULL_MAX];
    const char *p = rel;

    if (strlen(root) >= sizeof(abs))
        return 0;
    strcpy(abs, root);
    for (;;) {
        const char *seg = p;
        char        comp[BEP_PATH_MAX];
        int         seglen, last;

        while (*p && *p != '/')
            p++;
        seglen = (int)(p - seg);
        last   = (*p == '\0');

        if (last && !include_last)
            break;
        if (seglen > 0 && seglen < (int)sizeof(comp)) {
            memcpy(comp, seg, seglen);
            comp[seglen] = '\0';
            AddPart((STRPTR)abs, (STRPTR)comp, sizeof(abs));
            if (!ensure_dir_exists(abs))
                return 0;
        }
        if (last)
            break;
        p++;                                /* skip '/' */
    }
    return 1;
}

/* Syncthing's block-size ladder. The 16 MiB ceiling is the SPEC's, not ours:
 * we must compute the same block size the peer does or the block boundaries
 * disagree. What we cannot do is STORE a block over FOLDER_MAX_BLOCK_SIZE, so
 * folder_hash and folder_recv_finish refuse those - which is what caps a
 * syncable file near 2 GiB. */
int32_t folder_block_size(int64_t size)
{
    int32_t bs = FOLDER_BLOCK_SIZE;
    const int32_t max = 16 * 1024 * 1024;
    /* Smallest block in [128 KiB, 16 MiB] with size < 2000*block (Syncthing). */
    while (bs < max && size >= (int64_t)2000 * bs)
        bs <<= 1;
    return bs;
}

void folder_sha256(const void *data, int len, unsigned char out[BEP_HASH_LEN])
{
    SHA256((const unsigned char *)data, (size_t)len, out);
}

void folder_content_hash(const unsigned char (*hashes)[BEP_HASH_LEN], int n,
                         unsigned char out[BEP_HASH_LEN])
{
    SHA256((const unsigned char *)hashes, (size_t)n * BEP_HASH_LEN, out);
}

/* Read granularity for hashing/verifying. Blocks are hashed incrementally
 * (SHA256_Update over successive reads), so the scratch buffer is one of these
 * chunks rather than a whole block: hashing a large file then never needs a
 * block-sized allocation, which on a fragmented Amiga heap could fail (notably
 * the 1 MiB block of a near-2 GiB file, post-transfer). The size itself is one
 * default block per Read() - hash_block clamps to the bytes left in the block,
 * so any value is correct; this one just minimises dos.library round trips. */
#define FOLDER_HASH_CHUNK  (128 * 1024)

/* hash_path failure reasons reported via its 'why' out-param (NULL to ignore).
 * On success why is HASH_OK and *num_blocks holds the block count; on failure
 * *num_blocks holds however many whole blocks were read before stopping. */
#define HASH_OK     0
#define HASH_OPEN   1   /* could not open the file (IoErr() set)              */
#define HASH_READ   2   /* a Read() errored mid-file (IoErr() preserved)      */
#define HASH_TOOBIG 3   /* file has more than 'cap' blocks                    */

/* Feed up to 'block_size' bytes from 'fh' into 'bc', in FOLDER_HASH_CHUNK
 * reads. Returns the byte count (0 at EOF), or -1 on a read error with IoErr()
 * preserved. Boundaries are tracked by byte count, so a short read mid-block
 * does not shift them - the subtlest arithmetic in the file, hence one copy
 * for both the scanner's hash_path and the receive-verify diagnostic. */
static int hash_block(BPTR fh, unsigned char *buf, int block_size,
                      SHA256_CTX *bc)
{
    int remaining = block_size, blockbytes = 0;

    while (remaining > 0) {
        int want = remaining < FOLDER_HASH_CHUNK ? remaining : FOLDER_HASH_CHUNK;
        int got  = Read(fh, buf, want);
        if (got < 0)
            return -1;
        if (got == 0)
            break;                              /* EOF */
        SHA256_Update(bc, buf, (size_t)got);
        blockbytes += got;
        remaining  -= got;
    }
    return blockbytes;
}

/* Hash the file at 'full' in 'block_size'-byte blocks. If 'hashes' is non-NULL
 * each block hash is stored (up to 'cap'); content_hash is always folded over
 * them. Reads to EOF, so it needs no size up front. 'buf' is a caller-provided
 * FOLDER_HASH_CHUNK scratch. Returns 1 ok, 0 on open/read error (IoErr() is
 * left set), -1 if the file has more than 'cap' blocks. */
static int hash_path(const char *full, unsigned char *buf,
                     int block_size,
                     unsigned char (*hashes)[BEP_HASH_LEN], int cap,
                     int *num_blocks, unsigned char content_hash[BEP_HASH_LEN],
                     int *why)
{
    BPTR       fh;
    int        nb = 0;
    SHA256_CTX cc;

    if (why) *why = HASH_OK;
    *num_blocks = 0;

    fh = Open((STRPTR)full, MODE_OLDFILE);
    if (!fh) {
        if (why) *why = HASH_OPEN;             /* IoErr() set by Open */
        return 0;
    }

    SHA256_Init(&cc);
    for (;;) {
        unsigned char h[BEP_HASH_LEN];
        SHA256_CTX    bc;                       /* this block's hash         */
        int           blockbytes;

        SHA256_Init(&bc);
        blockbytes = hash_block(fh, buf, block_size, &bc);
        if (blockbytes < 0) {                    /* preserve the read error   */
            LONG e = IoErr(); Close(fh); SetIoErr(e);
            *num_blocks = nb;
            if (why) *why = HASH_READ;
            return 0;
        }
        /* Clean EOF at a block boundary ends the loop - EXCEPT for a zero-
         * length file, which still yields ONE zero-length block (the SHA-256
         * of nothing). That is Syncthing's convention: a live file always
         * carries at least one block, and an index entry with an empty block
         * list is a protocol error the peer answers by dropping the whole
         * connection ("file with empty block list"). */
        if (blockbytes == 0 && nb > 0)
            break;
        if (nb >= cap) {
            Close(fh);
            *num_blocks = nb;
            if (why) *why = HASH_TOOBIG;
            return -1;
        }
        SHA256_Final(h, &bc);
        SHA256_Update(&cc, h, BEP_HASH_LEN);     /* fold into blocksHash */
        if (hashes)
            memcpy(hashes[nb], h, BEP_HASH_LEN);
        nb++;
        if (blockbytes == 0)
            break;                               /* the empty file's one block */
    }
    Close(fh);

    SHA256_Final(content_hash, &cc);
    *num_blocks = nb;
    return 1;
}

int folder_hash(const char *path, const char *name, int64_t size,
                unsigned char (*hashes)[BEP_HASH_LEN], int cap,
                int *num_blocks, unsigned char content_hash[BEP_HASH_LEN])
{
    char           full[FULL_MAX];
    unsigned char *buf;
    int32_t        bs = folder_block_size(size);
    int            rc;

    if (bs > FOLDER_MAX_BLOCK_SIZE)
        return -1;                             /* too big: needs bigger blocks */

    buf = AllocVec(FOLDER_HASH_CHUNK, MEMF_ANY);
    if (!buf)
        return 0;

    if (!join_full(full, sizeof(full), path, name)) {
        FreeVec(buf);
        return -1;
    }
    rc = hash_path(full, buf, bs, hashes, cap,
                   num_blocks, content_hash, NULL);

    FreeVec(buf);
    return rc;
}

/* ---- recursive walk -------------------------------------------------- */

typedef struct {
    FolderWalkFn     cb;
    void            *ctx;
    const IgnoreSet *ig;
    int              stopped;    /* cb aborted: unwind the whole recursion */
} WalkCtx;

static void walk(WalkCtx *c, const char *abspath, const char *relprefix, int depth)
{
    BPTR                  lock;
    struct FileInfoBlock *fib;

    lock = Lock((STRPTR)abspath, ACCESS_READ);
    if (!lock)
        return;
    fib = AllocDosObject(DOS_FIB, NULL);
    if (!fib) {
        UnLock(lock);
        return;
    }

    if (Examine(lock, fib)) {
        while (!c->stopped && ExNext(lock, fib)) {
            const char *name = fib->fib_FileName;
            int         isdir = fib->fib_DirEntryType >= 0;
            FolderEntry e;

            if (skippable(name, depth))
                continue;

            if (!join_rel(e.name, relprefix, name))
                continue;                      /* too long to name on the wire */

            if (c->ig && ignore_match(c->ig, e.name))
                continue;

            e.is_dir     = isdir;
            /* Through ULONG first: fib_Size is a signed LONG, so a file of
             * 2 GiB or more reads back negative (see folder_recv_finish). */
            e.size       = isdir ? 0 : (int64_t)(ULONG)fib->fib_Size;
            e.modified_s = ds_to_unix(&fib->fib_Date);

            if (!c->cb(c->ctx, &e)) {
                c->stopped = 1;
                break;
            }

            if (isdir && depth + 1 < FOLDER_MAX_DEPTH) {
                char sub[FULL_MAX];
                if (!join_full(sub, sizeof(sub), abspath, name))
                    continue;
                walk(c, sub, e.name, depth + 1);
            }
        }
    }

    FreeDosObject(DOS_FIB, fib);
    UnLock(lock);
}

int folder_walk(const char *path, const IgnoreSet *ig, FolderWalkFn cb,
                void *ctx)
{
    WalkCtx c;
    BPTR    probe;

    probe = Lock((STRPTR)path, ACCESS_READ);
    if (!probe)
        return -1;
    UnLock(probe);

    c.cb      = cb;
    c.ctx     = ctx;
    c.ig      = ig;
    c.stopped = 0;
    walk(&c, path, "", 0);
    return c.stopped ? 0 : 1;
}

int folder_mkdir(const char *path, const char *name)
{
    return ensure_path_dirs(path, name, 1);
}

/* One-shot latch for warnings about conditions that persist across scan
 * passes (an over-long .stignore stays over-long; without this the scanner
 * would repeat the warning every 60 s and every worker on every refresh).
 * Keyed by a kind tag + path hash; a full table just lets duplicates through.
 * Static data is shared by the daemon and all its subprocesses (same segment,
 * like g_versioning), so one warning covers every process; the unlocked
 * updates race benignly - worst case is a duplicate line in the log. */
#define WARN_ONCE_SLOTS 16
static ULONG warn_once_keys[WARN_ONCE_SLOTS];
static int   warn_once_n;

static int warn_once(char kind, const char *path)
{
    ULONG h = 5381u ^ (unsigned char)kind;
    int   i;
    while (*path)
        h = h * 33u + (unsigned char)*path++;
    if (h == 0)
        h = 1;
    for (i = 0; i < warn_once_n && i < WARN_ONCE_SLOTS; i++)
        if (warn_once_keys[i] == h)
            return 0;
    if (warn_once_n < WARN_ONCE_SLOTS)
        warn_once_keys[warn_once_n++] = h;
    return 1;
}

/* #include resolution for .stignore: read <root>/<name> and parse it inline,
 * depth-guarded against include loops. */
typedef struct {
    const char *root;
    int         depth;
} IncludeCtx;

/* Read an ignore file whole into 'buf' (bufsz). Returns the byte count, or -1
 * if it could not be opened. A read that exactly fills the buffer almost
 * certainly means the file goes on beyond it, and the patterns past the cut
 * are silently missing - which shows up as "why is amisync syncing that?" -
 * so warn once per path. */
static LONG read_ignore_file(const char *full, char *buf, LONG bufsz)
{
    BPTR fh = Open((STRPTR)full, MODE_OLDFILE);
    LONG len;

    if (!fh)
        return -1;
    len = Read(fh, buf, bufsz);
    Close(fh);
    if (len == bufsz && warn_once('s', full))
        log_printf(LOG_WARN, "ignore: '%s' is larger than %ld bytes; patterns "
                   "past that are not applied", full, (long)bufsz);
    return len;
}

static void folder_include(void *vctx, const char *name, IgnoreSet *set)
{
    IncludeCtx *c = (IncludeCtx *)vctx;
    IncludeCtx  child;
    char        full[FULL_MAX];
    char        buf[8192];
    LONG        len;

    if (c->depth >= 4)
        return;                             /* stop runaway includes */

    if (!join_full(full, sizeof(full), c->root, name))
        return;
    len = read_ignore_file(full, buf, (LONG)sizeof(buf));

    child.root  = c->root;
    child.depth = c->depth + 1;
    if (len > 0)
        ignore_parse(set, buf, (int)len, folder_include, &child);
}

int folder_load_ignores(const char *path, IgnoreSet *set)
{
    char       full[FULL_MAX];
    char       buf[8192];
    LONG       len;
    IncludeCtx ctx;

    ignore_clear(set);

    if (!join_full(full, sizeof(full), path, ".stignore"))
        return 0;

    len = read_ignore_file(full, buf, (LONG)sizeof(buf));
    if (len < 0)
        /* "No rules" and "could not read the rules" must not look alike: the
         * first is a real change the caller may act on, the second is a blip
         * that would otherwise read as every rule being deleted. */
        return folder_exists(path, ".stignore") ? -1 : 0;

    ctx.root  = path;
    ctx.depth = 0;
    if (len > 0)
        ignore_parse(set, buf, (int)len, folder_include, &ctx);

    /* Patterns the parser could not keep (set full, or a single pattern over
     * the length cap) - counted across this file AND its #includes. Real
     * lines the user wrote that are NOT being enforced, so say so once. */
    if (set->dropped > 0 && warn_once('p', full))
        log_printf(LOG_WARN, "ignore: '%s': %d pattern(s) not applied (more "
                   "than %d patterns total, or a pattern over %d chars)",
                   full, set->dropped, IGNORE_MAX_PATTERNS,
                   IGNORE_PATTERN_MAX - 1);
    return 1;
}

int folder_delete(const char *path, const char *name)
{
    char full[FULL_MAX];
    BPTR lk;

    if (!join_full(full, sizeof(full), path, name))
        return 0;
    if (DeleteFile((STRPTR)full))
        return 1;

    /* Delete-protected? We are most likely the ones who protected it:
     * unix_mode_to_protection maps a missing owner-write bit to FIBF_DELETE,
     * so any file the peer stores read-only (mode 0444 and friends) lands here
     * with deletion forbidden. Without clearing that, a peer's deletion of such
     * a file can NEVER be applied - it is re-offered on every reconnect and we
     * warn and give up every time. Clear the bits and retry once. */
    SetProtection((STRPTR)full, 0);
    if (DeleteFile((STRPTR)full))
        return 1;

    /* DeleteFile failed. Report success only if the object is gone anyway
     * (it never existed, or something else removed it): the caller uses this
     * to decide whether to record a tombstone, and a tombstone for something
     * STILL on disk is a lie the next scan turns into a resurrection - it
     * re-discovers the object, sees a deleted record, and announces it to the
     * peer as a new local creation with a dominating version. The common real
     * failure is a non-empty directory (its contents are not all synced yet).
     * Lock() is the reliable existence test; IoErr codes vary by handler. */
    lk = Lock((STRPTR)full, ACCESS_READ);
    if (lk) {
        UnLock(lk);
        return 0;                          /* still there: deletion failed */
    }
    return 1;                              /* gone: nothing left to delete */
}

void folder_archive(const char *path, const char *name, int always)
{
    static const char VDIR[] = ".stversions/";
    char                  src[FULL_MAX], dst[FULL_MAX], rel[FULL_MAX];
    struct FileInfoBlock *fib;
    BPTR                  lk;
    int                   is_file = 0;

    if (!g_versioning && !always)
        return;
    if (!join_full(src, sizeof(src), path, name))
        return;

    /* Only archive an existing regular file; a missing file or a directory has
     * nothing to preserve. */
    lk = Lock((STRPTR)src, ACCESS_READ);
    if (!lk)
        return;
    fib = AllocDosObject(DOS_FIB, NULL);
    if (fib && Examine(lk, fib))
        is_file = fib->fib_DirEntryType < 0;
    if (fib) FreeDosObject(DOS_FIB, fib);
    UnLock(lk);
    if (!is_file)
        return;

    /* dst = <path>/.stversions/<name>; create its parent dirs, drop any prior
     * archived copy (trash-can keeps only the latest), then move ours in. All
     * best-effort: on any failure the caller still overwrites/deletes 'src'. */
    if (sizeof(VDIR) - 1 + strlen(name) + 1 > sizeof(rel))
        return;
    strcpy(rel, VDIR);
    strcat(rel, name);
    if (!ensure_path_dirs(path, rel, 0))
        return;
    if (!join_full(dst, sizeof(dst), path, rel))
        return;
    DeleteFile((STRPTR)dst);                    /* Rename won't replace */
    Rename((STRPTR)src, (STRPTR)dst);           /* best-effort */
}

int folder_rename(const char *path, const char *from, const char *to)
{
    char a[FULL_MAX], b[FULL_MAX];
    if (!join_full(a, sizeof(a), path, from) ||
        !join_full(b, sizeof(b), path, to))
        return 0;
    return Rename((STRPTR)a, (STRPTR)b) ? 1 : 0;
}

/* Build the staged-temp path for <path>/<name>: normally <joined>.amitmp, but
 * when the final component plus ".amitmp" would exceed the FFS floor
 * (FOLDER_SAFE_NAME_LEN) the temp becomes <dir>/<hex16-of-name>.amitmp
 * instead. A temp name the filesystem would truncate loses its .amitmp suffix
 * ON DISK: the scanner then indexes the partial as a real file (and announces
 * it), the temp GC never reclaims it, and lookups by the untruncated name stop
 * matching - the source of the truncated junk files seen on FFS. The hash
 * covers the whole relative name, so the temp stays deterministic (a resumed
 * download finds its earlier partial) and unique within its directory.
 * Returns 1, or 0 if the path will not fit 'cap'. */
static int temp_path(char *tmp, int cap, const char *path, const char *name)
{
    const char *base = name, *p;

    for (p = name; *p; p++)
        if (*p == '/')
            base = p + 1;

    if ((int)strlen(base) + AMITMP_LEN <= FOLDER_SAFE_NAME_LEN) {
        if (!join_full(tmp, cap, path, name))
            return 0;
        if ((int)strlen(tmp) + AMITMP_LEN + 1 > cap)
            return 0;
        strcat(tmp, AMITMP);
        return 1;
    }

    {
        char hashed[BEP_PATH_MAX];
        int  dlen = (int)(base - name);          /* dir prefix incl. '/' */
        char hex[17];

        fnv16_hex(name, hex);
        if (dlen + 16 + AMITMP_LEN + 1 > (int)sizeof(hashed))
            return 0;
        memcpy(hashed, name, (size_t)dlen);
        strcpy(hashed + dlen, hex);
        strcat(hashed + dlen, AMITMP);
        return join_full(tmp, cap, path, hashed);
    }
}

/* Where the existing target is parked while its replacement is renamed into
 * place: <dir>/<hex16-of-name>.old.amitmp. Always the hashed form - it is 27
 * characters, inside FFS's 30-char floor for ANY name, so parking can never
 * fail for the same reason the rename it protects might. The .amitmp tail
 * keeps it invisible to the scanner and reclaimable by the temp GC, so a
 * copy stranded by a crash mid-swap is swept rather than indexed. */
static int aside_path(char *out, int cap, const char *path, const char *name)
{
    const char *base = name, *p;
    char        parked[BEP_PATH_MAX];
    char        hex[17];
    int         dlen;

    for (p = name; *p; p++)
        if (*p == '/')
            base = p + 1;
    dlen = (int)(base - name);                   /* dir prefix incl. '/' */

    fnv16_hex(name, hex);
    if (dlen + 16 + 4 + AMITMP_LEN + 1 > (int)sizeof(parked))
        return 0;
    memcpy(parked, name, (size_t)dlen);
    strcpy(parked + dlen, hex);
    strcat(parked + dlen, ".old" AMITMP);
    return join_full(out, cap, path, parked);
}

void folder_delete_temp(const char *path, const char *name)
{
    char full[FULL_MAX];
    if (!temp_path(full, sizeof(full), path, name))   /* matches recv_open */
        return;
    DeleteFile((STRPTR)full);              /* best-effort: absent is fine */
}

/* Recursively delete *.amitmp files older than 'cutoff' under 'abspath'. */
static int gc_walk(const char *abspath, int64_t cutoff, int depth)
{
    BPTR                  lock;
    struct FileInfoBlock *fib;
    int                   removed = 0;

    lock = Lock((STRPTR)abspath, ACCESS_READ);
    if (!lock)
        return 0;
    fib = AllocDosObject(DOS_FIB, NULL);
    if (!fib) {
        UnLock(lock);
        return 0;
    }

    if (Examine(lock, fib)) {
        while (ExNext(lock, fib)) {
            const char *name = fib->fib_FileName;
            size_t      ln   = strlen(name);
            char        sub[FULL_MAX];

            if (fib->fib_DirEntryType >= 0) {          /* directory: recurse */
                if (depth + 1 < FOLDER_MAX_DEPTH &&
                    join_full(sub, sizeof(sub), abspath, name))
                    removed += gc_walk(sub, cutoff, depth + 1);
                continue;
            }
            if (ln >= AMITMP_LEN &&
                strcasecmp(name + ln - AMITMP_LEN, AMITMP) == 0 &&
                ds_to_unix(&fib->fib_Date) < cutoff &&
                join_full(sub, sizeof(sub), abspath, name)) {
                if (DeleteFile((STRPTR)sub))           /* fails harmlessly if open */
                    removed++;
            }
        }
    }

    FreeDosObject(DOS_FIB, fib);
    UnLock(lock);
    return removed;
}

int folder_gc_temps(const char *path, int64_t cutoff)
{
    return gc_walk(path, cutoff, 0);
}

int64_t folder_now(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return ds_to_unix(&ds);
}

uint64_t folder_version_stamp(int64_t modified_s)
{
    int64_t now = folder_now();

    return (uint64_t)(now > modified_s ? now : modified_s);
}

int folder_read_block(const char *path, const char *name,
                      int64_t offset, int32_t size, unsigned char *buf)
{
    char full[FULL_MAX];
    BPTR fh;
    int  got;

    if (!join_full(full, sizeof(full), path, name))
        return -1;

    fh = Open((STRPTR)full, MODE_OLDFILE);
    if (!fh)
        return -1;
    if (Seek(fh, (LONG)offset, OFFSET_BEGINNING) < 0) {
        Close(fh);
        return -1;
    }
    /* Fill the whole block: Read() can return a short count mid-file, which the
     * caller would otherwise treat as a missing/short block and refuse to serve. */
    got = 0;
    while (got < size) {
        int n = Read(fh, buf + got, size - got);
        if (n < 0) { Close(fh); return -1; }
        if (n == 0) break;                     /* EOF */
        got += n;
    }
    Close(fh);
    return got;
}

int folder_name_safe(const char *name)
{
    return path_name_safe(name);   /* pure logic in pathsafe.c (host-tested) */
}

int folder_name_fits(const char *path, const char *name)
{
    char                  full[FULL_MAX], probe[FULL_MAX], dead[FULL_MAX];
    char                  pname[BEP_PATH_MAX];
    const char           *base, *p;
    BPTR                  fh, lock;
    struct FileInfoBlock *fib;
    int                   fits = 1, blen;

    base = name;                               /* last component of 'name' */
    for (p = name; *p; p++)
        if (*p == '/' || *p == ':')
            base = p + 1;
    blen = (int)strlen(base);

    /* Fits on any filesystem: skip the probe entirely (the common case). */
    if (blen <= FOLDER_SAFE_NAME_LEN)
        return 1;

    fib = AllocDosObject(DOS_FIB, NULL);

    /* If the target already exists, its very presence proves the name is
     * storable; Examine confirms it was not truncated. Never create/delete
     * over it (that would destroy the user's file just to test its name). */
    if (join_full(full, sizeof(full), path, name) &&
        (lock = Lock((STRPTR)full, ACCESS_READ)) != 0) {
        if (fib && Examine(lock, fib))
            fits = (strcmp(fib->fib_FileName, base) == 0);
        UnLock(lock);
        goto out;
    }

    /* Ask THIS filesystem what it records - but probe with a SYNTHETIC name of
     * the same length in the folder ROOT, never the real target name. A probe
     * at the real name is a trap: a truncating filesystem stores it under a
     * DIFFERENT name than we later DeleteFile() by, and the 0-byte leftover
     * gets scanned, indexed and announced as a real file. The synthetic name
     * ends in ".amitmp", so even a leaked probe is invisible to the scanner
     * and reclaimed by the temp GC. Truncation depends only on the component's
     * length, so same length = same verdict; a long-name FS (PFS3/SFS) keeps
     * it and this returns 1, FFS truncates it and this returns 0. Any failure
     * to probe fails open, as before. */
    if (blen >= (int)sizeof(pname))
        goto out;                              /* cannot probe: fail open */
    memset(pname, 'x', (size_t)blen);
    pname[blen] = '\0';
    memcpy(pname, "amisync-probe-", 14);       /* blen > 30 > 14+7: fits */
    memcpy(pname + blen - AMITMP_LEN, AMITMP, AMITMP_LEN);

    if (!join_full(probe, sizeof(probe), path, pname))
        goto out;                              /* cannot probe: fail open */
    lock = Lock((STRPTR)probe, ACCESS_READ);
    if (lock) {                                /* astonishing, but don't touch */
        UnLock(lock);
        goto out;
    }

    fh = Open((STRPTR)probe, MODE_NEWFILE);
    if (!fh)
        goto out;                              /* cannot probe: fail open */
    if (fib && ExamineFH(fh, fib)) {
        /* The handle tells us the STORED name, whatever the filesystem did to
         * it - so the compare and the cleanup are both exact. */
        fits = (strcmp(fib->fib_FileName, pname) == 0);
        Close(fh);
        if (join_full(dead, sizeof(dead), path, fib->fib_FileName))
            DeleteFile((STRPTR)dead);
    } else {
        /* No ExamineFH (unusual handler): treat an unprovable name as fitting
         * (fail open) and sweep both plausible on-disk forms - the whole name
         * and its FFS 30-char truncation. */
        Close(fh);
        DeleteFile((STRPTR)probe);
        {
            char trunc[FOLDER_SAFE_NAME_LEN + 1];
            memcpy(trunc, pname, FOLDER_SAFE_NAME_LEN);
            trunc[FOLDER_SAFE_NAME_LEN] = '\0';
            if (join_full(dead, sizeof(dead), path, trunc))
                DeleteFile((STRPTR)dead);
        }
    }

out:
    if (fib) FreeDosObject(DOS_FIB, fib);
    return fits;                        /* 1 unless a probe proved otherwise */
}

FolderFile folder_recv_open(const char *path, const char *name,
                            char *tmp, int tmpcap, int32_t block_size,
                            int num_blocks, int *resume_from)
{
    BPTR fh;
    long existing;

    *resume_from = 0;

    /* Ensure the folder root and any parent directories of 'name' exist. */
    if (!ensure_dir_exists(path))
        return 0;
    if (!ensure_path_dirs(path, name, 0))   /* parents of the file */
        return 0;

    if (!temp_path(tmp, tmpcap, path, name))
        return 0;

    /* Resume: if a partial temp survived an earlier attempt, keep its whole
     * leading blocks (floor of its size) and re-open it preserving the data, so
     * only the remaining blocks are fetched. A partial trailing block is dropped
     * by the floor and re-requested. */
    existing = (block_size > 0) ? folder_state_size(tmp) : -1;
    /* A temp longer than the whole file cannot be a prefix of it: the name was
     * re-used for different content (the peer replaced the file while an
     * abandoned temp from the old one survived), and the old bytes are not a
     * head start, they are a different file. Capping the block count at
     * num_blocks instead - what this used to do - resumed a 49 KB file from a
     * 3 MB leftover, called it complete, and failed the whole-file verify on
     * every attempt, so the fetch could never make progress. Drop it and
     * start clean. */
    if ((int64_t)existing > (int64_t)num_blocks * (int64_t)block_size)
        existing = 0;                      /* 64-bit: the product overflows a long */
    if (existing > 0) {
        int rf = (int)(existing / block_size);
        if (rf > num_blocks)
            rf = num_blocks;
        if (rf > 0) {
            fh = Open((STRPTR)tmp, MODE_READWRITE);   /* preserve existing data */
            if (fh) {
                *resume_from = rf;
                return (FolderFile)fh;
            }
            /* couldn't reopen: fall through and start fresh */
        }
    }

    fh = Open((STRPTR)tmp, MODE_NEWFILE);             /* fresh (truncates) */
    return (FolderFile)fh;
}

FolderWriteResult folder_recv_write(FolderFile fh, int64_t offset,
                                    const void *data, int len)
{
    BPTR f = (BPTR)fh;
    LONG end;

    /* Where the temp currently ends. Seek reports the position it moved AWAY
     * from, so this pair both parks the position at the end and reads it back
     * as the file's size. */
    if (Seek(f, 0, OFFSET_END) < 0)
        return FOLDER_WRITE_FAIL;
    end = Seek(f, 0, OFFSET_CURRENT);
    if (end < 0)
        return FOLDER_WRITE_FAIL;
    if (offset > (int64_t)end)
        return FOLDER_WRITE_AHEAD;             /* would leave a hole: see above */

    if (Seek(f, (LONG)offset, OFFSET_BEGINNING) < 0)
        return FOLDER_WRITE_FAIL;
    return Write(f, (APTR)data, len) == len ? FOLDER_WRITE_OK : FOLDER_WRITE_FAIL;
}

/* On a failed whole-file verify, re-read the staged temp block by block and
 * return the index of the first block whose on-disk hash differs from the
 * expected per-block hash (the one the transfer already matched in memory), with
 * its byte offset in *off_out. Returns -1 if every block matches (so the
 * mismatch is elsewhere) or the temp can't be read. 'buf' is the caller's
 * FOLDER_HASH_CHUNK scratch - allocating our own here would ask for memory at
 * the worst possible moment, a transfer having just gone wrong. Diagnostic
 * only. */
static int recv_first_bad_block(const char *tmp, int32_t bs,
                                const unsigned char (*expect)[BEP_HASH_LEN],
                                int num_blocks, unsigned char *buf,
                                int64_t *off_out)
{
    BPTR fh;
    int  i, bad = -1;

    *off_out = -1;
    fh = Open((STRPTR)tmp, MODE_OLDFILE);
    if (!fh)
        return -1;

    for (i = 0; i < num_blocks; i++) {
        unsigned char h[BEP_HASH_LEN];
        SHA256_CTX    bc;
        int           blockbytes;

        SHA256_Init(&bc);
        blockbytes = hash_block(fh, buf, bs, &bc);
        if (blockbytes <= 0) break;            /* read error, or short file */
        SHA256_Final(h, &bc);
        if (memcmp(h, expect[i], BEP_HASH_LEN) != 0) {
            bad = i; *off_out = (int64_t)i * bs; break;
        }
    }
    Close(fh);
    return bad;
}

FolderRecvResult folder_recv_finish(const char *path, const char *name,
                                    const char *tmp, FolderFile fh,
                                    int64_t modified_s, uint32_t perms,
                                    int32_t block_size, int64_t expect_size,
                                    int skip_verify, int archive_always,
                                    const unsigned char expect[BEP_HASH_LEN],
                                    const unsigned char (*block_hashes)[BEP_HASH_LEN],
                                    int num_blocks, FolderRecvInfo *info)
{
    char             full[FULL_MAX];
    struct DateStamp ds;
    unsigned char   *buf;
    unsigned char    got_hash[BEP_HASH_LEN];
    int              nb, rc, why = HASH_OK;
    int32_t          bs = block_size > 0 ? block_size : FOLDER_BLOCK_SIZE;

    if (info) {
        info->bad_block  = -1;
        info->bad_off    = -1;
        info->got_blocks = -1;
        info->exp_blocks = num_blocks;
        info->io_reason  = FOLDER_IO_NONE;
        info->ioerr      = 0;
    }

    /* Flush + close the staged temp. The per-block Write()s only buffer into the
     * filesystem; the data is forced to the medium here, so a full disk or write
     * error first surfaces as a failed Close - never caught by the earlier
     * per-block writes, which already "succeeded". Treat it as a finish failure
     * so we don't verify (and silently discard) a file that never fully landed. */
    if (!Close((BPTR)fh)) {
        DeleteFile((STRPTR)tmp);
        return FOLDER_RECV_CLOSE;
    }

    /* Fast path: every block of this temp was SHA-256-verified against the
     * peer's expected hash as it was written IN THIS SESSION (network fetch or
     * local prefill), so re-reading and re-hashing the whole file here would
     * only repeat that work - doubling the I/O and SHA cost of every receive
     * on the 68k. What in-line verification cannot see is the flush: confirm
     * the staged file's on-disk size before the rename (a failed buffered
     * write surfaces as a short file even when Close succeeded). Resumed temps
     * take the full re-verify below instead - their prefix blocks were written
     * by an earlier run and never verified in this one. */
    if (skip_verify) {
        BPTR                  lk  = Lock((STRPTR)tmp, ACCESS_READ);
        struct FileInfoBlock *fib = lk ? AllocDosObject(DOS_FIB, NULL) : NULL;
        int64_t               got = -1;

        if (fib) {
            if (Examine(lk, fib))
                got = (int64_t)(ULONG)fib->fib_Size;
            FreeDosObject(DOS_FIB, fib);
        }
        if (lk)
            UnLock(lk);
        if (got != expect_size) {
            if (info) {
                info->io_reason = FOLDER_IO_SIZE;
                info->ioerr     = IoErr();
            }
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_IO;
        }
    }

    /* Final verify: re-hash the staged temp at the file's block size and confirm
     * it reproduces the peer's content fingerprint before we let it replace the
     * target. A failure here (e.g. a bad disk write past the per-block checks)
     * must leave any existing copy untouched. */
    if (expect && !skip_verify) {
        if (bs > FOLDER_MAX_BLOCK_SIZE) {       /* peer's block size is absurd */
            if (info) info->io_reason = FOLDER_IO_TOOBIG;
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_IO;
        }
        buf = AllocVec(FOLDER_HASH_CHUNK, MEMF_ANY);   /* small read chunk */
        if (!buf) {
            if (info) info->io_reason = FOLDER_IO_NOMEM;
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_IO;
        }
        rc = hash_path(tmp, buf, bs, NULL, FOLDER_MAX_BLOCKS,
                       &nb, got_hash, &why);
        if (rc != 1) {
            FreeVec(buf);
            if (info) {
                info->got_blocks = nb;                    /* blocks read so far */
                info->io_reason  = (why == HASH_OPEN)   ? FOLDER_IO_OPEN   :
                                   (why == HASH_READ)   ? FOLDER_IO_READ   :
                                   (why == HASH_TOOBIG) ? FOLDER_IO_TOOBIG :
                                                          FOLDER_IO_NONE;
                info->ioerr      = (why == HASH_READ || why == HASH_OPEN) ? IoErr() : 0;
            }
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_IO;
        }
        if (memcmp(got_hash, expect, BEP_HASH_LEN) != 0) {
            if (info) {
                info->got_blocks = nb;
                /* A wrong block count is itself the strongest signal (a short
                 * temp -> truncation); only chase a specific block when the count
                 * lines up and we hold the expected per-block hashes. */
                if (block_hashes && nb == num_blocks)
                    info->bad_block = recv_first_bad_block(tmp, bs, block_hashes,
                                                           num_blocks, buf,
                                                           &info->bad_off);
            }
            FreeVec(buf);
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_MISMATCH;
        }
        FreeVec(buf);
    }

    if (!join_full(full, sizeof(full), path, name)) {
        if (info) info->io_reason = FOLDER_IO_PATH;
        DeleteFile((STRPTR)tmp);          /* don't strand the staged temp */
        return FOLDER_RECV_IO;
    }

    /* Keep the old copy if versioning is on - or unconditionally when the
     * caller says this is a receive-only revert, where what is about to be
     * overwritten is the user's own edit and exists nowhere else. Deliberately
     * HERE rather than earlier: folder_archive MOVES the file, so archiving
     * before the transfer is verified would delete the user's copy on a fetch
     * that then failed. */
    folder_archive(path, name, archive_always);

    /* Swap the staged file in without a moment where neither copy exists.
     * Rename cannot replace an existing file, so the target has to go first -
     * but DELETING it first means a rename that then fails (the FOLDER_IO_RENAME
     * path below is not hypothetical: a full disk, a write error, a name this
     * filesystem will not take) leaves the old copy gone and the new one
     * discarded. The file would vanish locally, and the next scan - finding a
     * live index record with nothing behind it - would tombstone it and
     * announce the DELETE, taking the peer's good copy with it. So park the
     * old file instead, and put it back if the swap does not complete. Same
     * shape as doc_save's config snapshot-and-restore. */
    {
        char aside[FULL_MAX];
        int  parked = 0;
        BPTR lk = Lock((STRPTR)full, ACCESS_READ);

        if (lk) {
            UnLock(lk);
            /* Clear any protection we applied from the peer's mode: a
             * read-only file (no owner-write -> FIBF_DELETE) refuses both the
             * park below and the plain delete after it. */
            SetProtection((STRPTR)full, 0);
            if (aside_path(aside, sizeof(aside), path, name)) {
                DeleteFile((STRPTR)aside);          /* a crash left one behind */
                parked = Rename((STRPTR)full, (STRPTR)aside) ? 1 : 0;
            }
            if (!parked)
                DeleteFile((STRPTR)full);           /* cannot park: as before */
        }

        if (!Rename((STRPTR)tmp, (STRPTR)full)) {
            if (info) { info->io_reason = FOLDER_IO_RENAME; info->ioerr = IoErr(); }
            if (parked)
                Rename((STRPTR)aside, (STRPTR)full);   /* put the old one back */
            DeleteFile((STRPTR)tmp);
            return FOLDER_RECV_IO;
        }
        if (parked)
            DeleteFile((STRPTR)aside);              /* superseded */
    }

    if (perms != 0)                       /* honour the peer's mode (best-effort) */
        SetProtection((STRPTR)full, unix_mode_to_protection(perms));
    unix_to_ds(modified_s, &ds);
    SetFileDate((STRPTR)full, &ds);       /* best-effort */
    return FOLDER_RECV_OK;
}

int folder_touch(const char *path, const char *name, int64_t modified_s,
                 uint32_t perms)
{
    char             full[FULL_MAX];
    struct DateStamp ds;

    if (!join_full(full, sizeof(full), path, name))
        return 0;
    if (perms != 0)
        SetProtection((STRPTR)full, unix_mode_to_protection(perms));
    unix_to_ds(modified_s, &ds);
    return SetFileDate((STRPTR)full, &ds) ? 1 : 0;
}

void folder_recv_abort(FolderFile fh, const char *tmp)
{
    /* Keep the temp so a later attempt can resume from its completed blocks (see
     * folder_recv_open). A genuinely-orphaned temp (peer or file gone) is a
     * *.amitmp, which the scanner ignores; it just uses disk until reclaimed. */
    (void)tmp;
    if (fh)
        Close((BPTR)fh);
}

/* ---- shared-index persistence ----------------------------- */

int folder_state_path(const char *statedir, const char *folder_id,
                      char *out, int cap)
{
    char fname[24];                 /* 16 hex + ".idx" + NUL */

    fnv16_hex(folder_id, fname);    /* stable, always-legal filename stem */
    strcpy(fname + 16, ".idx");
    return join_full(out, cap, statedir, fname);
}

int folder_aux_path(const char *statedir, const char *leaf, char *out, int cap)
{
    return join_full(out, cap, statedir, leaf);
}

int folder_ensure_dir(const char *path)
{
    char  tmp[FULL_MAX];
    BPTR  lock;
    int   i, n = (int)strlen(path);

    lock = Lock((STRPTR)path, ACCESS_READ);      /* already there? */
    if (lock) { UnLock(lock); return 1; }
    if (n >= FULL_MAX)
        return 0;


    /* Create each component after the device ':' (e.g. ENVARC:Amisync/state). */
    strcpy(tmp, path);
    for (i = 0; i < n; i++) {
        if (tmp[i] != '/')
            continue;
        tmp[i] = '\0';
        if (i > 0 && tmp[i - 1] != ':')          /* skip a bare "vol:/" (and a
                                                  * leading '/': tmp[-1] would
                                                  * read before the buffer) */
            ensure_dir_exists(tmp);              /* best-effort: the final
                                                  * CreateDir below decides */
        tmp[i] = '/';
    }

    return ensure_dir_exists(path);
}

int folder_exists(const char *path, const char *name)
{
    char full[FULL_MAX];
    BPTR lock;

    if (!join_full(full, sizeof(full), path, name))
        return 1;                          /* cannot ask: assume it is there */

    /* A SHARED lock succeeds on anything that exists however many readers it
     * already has, so this separates "gone" from "busy" where Open cannot. */
    lock = Lock((STRPTR)full, SHARED_LOCK);
    if (lock) {
        UnLock(lock);
        return 1;
    }
    return IoErr() != ERROR_OBJECT_NOT_FOUND;
}

long folder_state_size(const char *path)
{
    BPTR fh = Open((STRPTR)path, MODE_OLDFILE);
    long sz;

    if (!fh)
        return -1;
    if (Seek(fh, 0, OFFSET_END) < 0) { Close(fh); return -1; }
    sz = Seek(fh, 0, OFFSET_BEGINNING);          /* returns the prior (=end) pos */
    Close(fh);
    return sz < 0 ? -1 : sz;
}

int folder_state_read(const char *path, void *buf, int cap)
{
    BPTR fh = Open((STRPTR)path, MODE_OLDFILE);
    int  total = 0;
    LONG n = 0;

    if (!fh)
        return 0;                                /* absent */
    while (total < cap && (n = Read(fh, (char *)buf + total, cap - total)) > 0)
        total += (int)n;
    Close(fh);
    return n < 0 ? -1 : total;
}

int folder_state_write(const char *path, const void *data, int len)
{
    char tmp[FULL_MAX];
    BPTR fh;

    if ((int)strlen(path) + AMITMP_LEN + 1 > FULL_MAX)
        return 0;
    strcpy(tmp, path);
    strcat(tmp, AMITMP);

    fh = Open((STRPTR)tmp, MODE_NEWFILE);
    if (!fh)
        return 0;
    if (Write(fh, (APTR)data, len) != len) {
        Close(fh);
        DeleteFile((STRPTR)tmp);
        return 0;
    }
    Close(fh);

    DeleteFile((STRPTR)path);                    /* Rename won't replace existing */
    if (!Rename((STRPTR)tmp, (STRPTR)path)) {
        DeleteFile((STRPTR)tmp);
        return 0;
    }
    return 1;
}
