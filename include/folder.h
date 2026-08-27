/* folder.h - local folder scanning, block I/O and received-file storage
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The file layer over AmigaOS dos.library. Scanning turns a local
 * directory into the BEP FileInfo list we advertise (with 128 KiB blocks and
 * SHA-256 hashes); the read side serves a peer's Request from disk; the receive
 * side writes a peer's Response blocks to a temp file and renames it into place.
 *
 * Scope: regular files and the directories containing them, recursed to
 * FOLDER_MAX_DEPTH. Files are transferred in Syncthing-sized blocks, scaling
 * from 128 KiB up to FOLDER_MAX_BLOCK_SIZE, which covers files to ~2 GiB;
 * anything larger is skipped. Paths are
 * forward-slash relative (BEP convention; AmigaOS uses '/' too). Entries matched
 * by the folder's .stignore are skipped, as are the .stignore file itself and
 * our *.amitmp temp files. Symlinks are not handled. Uses dos.library + AmiSSL
 * (SHA-256) only - no sockets - so it is Amiga-only and validated on hardware.
 */

#ifndef AMISYNC_FOLDER_H
#define AMISYNC_FOLDER_H

#include "bep.h"
#include "ignore.h"

/* Syncthing's minimum (and base) block size. A file's actual block size is the
 * smallest power-of-two in [128 KiB, 16 MiB] that splits it into < 2000 blocks
 * (see folder_block_size); both sides use the same value so block boundaries -
 * and every block hash - line up, and a Request/Response carries one block. */
#define FOLDER_BLOCK_SIZE  (128 * 1024)

/* The largest block we buffer, i.e. our ceiling on a file's block size. Files
 * whose Syncthing block size exceeds this are skipped. 1 MiB covers files up to
 * ~2 GiB (1 MiB * 2048 blocks). It sizes the worker's block buffer and the hash
 * scratch, and must stay below BEP_MSG_MAX (a block rides in one BEP message).
 * Raising it toward 16 MiB lifts the file-size ceiling but costs RAM per
 * connection (the BEP buffers grow with it). */
#define FOLDER_MAX_BLOCK_SIZE  (1024 * 1024)

/* Per-file block cap. A file always splits into < 2000 blocks at its chosen
 * block size, so 2048 is enough regardless of size (up to the block-size cap). */
#define FOLDER_MAX_BLOCKS  2048

/* How deep we recurse into subdirectories. */
#define FOLDER_MAX_DEPTH   12

/* Syncthing's per-file block size: the smallest power-of-two block in
 * [128 KiB, 16 MiB] for which the file splits into fewer than 2000 blocks. */
int32_t folder_block_size(int64_t size);

/* SHA-256 of a buffer (thin AmiSSL wrapper for the worker's per-block verify). */
void folder_sha256(const void *data, int len, unsigned char out[BEP_HASH_LEN]);

/* A file's content fingerprint: SHA-256 over its 'n' concatenated block hashes,
 * i.e. Syncthing's blocksHash. Folded from our own block hashes on scan and from
 * a peer FileInfo's block hashes on receipt, so equal fingerprint => equal
 * content (both sides use the same per-file block size, so boundaries align). */
void folder_content_hash(const unsigned char (*hashes)[BEP_HASH_LEN], int n,
                         unsigned char out[BEP_HASH_LEN]);

/* Hash <path>/<name> (a 'size'-byte file) in its Syncthing block size into
 * 'hashes' (capacity 'cap' entries), setting *num_blocks and content_hash.
 * Returns 1 on success, 0 if the file cannot be read, -1 if it is too large for
 * us (its block size exceeds FOLDER_MAX_BLOCK_SIZE, or it needs more than 'cap'
 * blocks). */
int folder_hash(const char *path, const char *name, int64_t size,
                unsigned char (*hashes)[BEP_HASH_LEN], int cap,
                int *num_blocks, unsigned char content_hash[BEP_HASH_LEN]);

/* A cheap directory listing entry (no hashing): used by rescan to spot changes
 * by name/size/mtime before deciding what to re-hash. */
typedef struct {
    char    name[BEP_PATH_MAX];   /* forward-slash relative path */
    int64_t size;
    int64_t modified_s;
    int     is_dir;
} FolderEntry;

/* Per-entry callback for folder_walk. 'e' points at walk-local storage - copy
 * out anything needed beyond the call. Return nonzero to continue the walk,
 * 0 to abort it (folder_walk then reports the walk as partial). */
typedef int (*FolderWalkFn)(void *ctx, const FolderEntry *e);

/* Walk 'path' recursively (files and directories, to FOLDER_MAX_DEPTH, ignored
 * entries filtered by 'ig' or all kept if NULL) without hashing, invoking 'cb'
 * once per kept entry. Nothing is materialised, so there is no entry cap.
 * Returns 1 when the walk ran to completion, 0 when 'cb' aborted it (a partial
 * walk: entries not reached look "missing", so the caller must NOT reconcile
 * deletions from it), or -1 if the folder cannot be opened. */
int folder_walk(const char *path, const IgnoreSet *ig, FolderWalkFn cb,
                void *ctx);

/* Create directory <path>/<name> (and any missing parents). 1 if it exists
 * afterwards. Takes an unjoined pair where folder_ensure_dir takes one path;
 * note they differ on failure - this one stops at the first component it
 * cannot create, while folder_ensure_dir presses on and reports only whether
 * the FINAL directory ended up there. */
int folder_mkdir(const char *path, const char *name);

/* Load <path>/.stignore into 'set' (cleared first). Returns 1 when rules were
 * read, 0 when there is no .stignore at all, and -1 when one exists but could
 * not be read. A caller that acts on rule CHANGES must treat -1 as "unknown,
 * keep what you had": an unreadable file is not an emptied one, and reading it
 * as such would look exactly like the user deleting every rule. */
int folder_load_ignores(const char *path, IgnoreSet *set);

/* Delete <path>/<name>. Returns 1 on success, 0 on failure. */
int folder_delete(const char *path, const char *name);

/* Rename <path>/<from> to <path>/<to> (same volume by construction). Used to
 * preserve a conflict loser before its slot is re-downloaded. Returns 1/0. */
int folder_rename(const char *path, const char *from, const char *to);

/* Delete a leftover download temp <path>/<name>.amitmp, if any (best-effort).
 * Called when a file is removed so its abandoned partial doesn't linger. */
void folder_delete_temp(const char *path, const char *name);

/* Reclaim orphaned download temps: recursively delete every *.amitmp under
 * 'path' whose modification time is older than 'cutoff' (Unix seconds). An
 * actively-resumed temp is written as blocks arrive so it stays fresh; one in
 * use can't be deleted and is simply retried next sweep. Returns the count
 * removed. */
int folder_gc_temps(const char *path, int64_t cutoff);

/* Read 'size' bytes at 'offset' from <path>/<name> into 'buf' (cap >= size).
 * Returns the number of bytes read, or -1 on error (missing file, short read). */
int folder_read_block(const char *path, const char *name,
                      int64_t offset, int32_t size, unsigned char *buf);

/* Does the folder's filesystem store 'name's final component without truncating
 * it? If the target already exists its recorded name is examined; otherwise a
 * zero-length SYNTHETIC probe of the same length (a ".amitmp" name, invisible
 * to the scanner) is created in the folder root, examined via its handle, and
 * removed by the name the filesystem actually stored - so a truncating
 * filesystem cannot strand a leftover under a name we never asked for. Returns
 * 1 if it fits (or the probe couldn't run - fail open), 0 if truncated (e.g.
 * an over-30-char name on FFS), meaning the file cannot be stored/synced under
 * its real name. Lets the caller skip such a file up front instead of fetching
 * it and failing the rename. */
int folder_name_fits(const char *path, const char *name);

/* Is 'name' a safe relative path to use under a folder root? A peer supplies
 * these over the wire, and they are joined with AddPart(), which on AmigaOS
 * treats a ':' component as an absolute (volume) path and a leading '/' as a
 * parent-directory escape - so an unvalidated name like "S:User-Startup" or
 * "/foo" would read/write outside the synced folder. Rejects: empty names, a
 * leading '/', any ':' or '\\', a "//" (empty) component, and "."/".."
 * components. Returns 1 if safe to use, 0 if it must be refused. */
int folder_name_safe(const char *name);

/* Enable/disable file versioning (trash-can). When on, folder_archive() moves a
 * file about to be replaced or deleted into <folder>/.stversions/ first. Set
 * once at startup, before any worker runs. */
void folder_set_versioning(int on);

/* If <path>/<name> is an existing regular file, move it to
 * <path>/.stversions/<name> (keeping only the most recent old copy). No-op when
 * the file is absent or is a directory. Best-effort: callers proceed to
 * overwrite/delete regardless.
 *
 * 'always' overrides the versioning setting. It exists for one case: a
 * receive-only folder replacing a file the user edited HERE. Everywhere else
 * the copy being replaced still exists on the peer, so keeping it is a
 * preference; there it exists nowhere else in the world, and a preference is
 * the wrong thing to gate destroying someone's only copy of their own work. */
void folder_archive(const char *path, const char *name, int always);

/* Receive side. A FolderFile is an opaque dos.library file handle; 0 means
 * "none/invalid". The temp lives in the same folder as its target, so the
 * rename that publishes it stays within one volume and is atomic; recv_abort
 * closes the handle but KEEPS the temp, so the next attempt can resume from
 * it. Per-function contracts are on the prototypes below. */
typedef long FolderFile;

/* Outcome of folder_recv_finish. Callers treat any value > 0 as success; the
 * negative codes split the old opaque "verify failed" into causes that need
 * different responses (a flush failure is a disk/medium problem, not a bad
 * transfer). */
typedef enum {
    FOLDER_RECV_OK       =  1,  /* re-hashed clean and renamed into place      */
    FOLDER_RECV_MISMATCH =  0,  /* staged content differs from expected        */
    FOLDER_RECV_CLOSE    = -1,  /* final flush/close failed (disk full / I/O)  */
    FOLDER_RECV_IO       = -2   /* could not re-read the temp, or out of memory */
} FolderRecvResult;

/* Why a FOLDER_RECV_IO happened (info->io_reason). */
typedef enum {
    FOLDER_IO_NONE   = 0,
    FOLDER_IO_NOMEM  = 1,  /* verify read-buffer allocation failed            */
    FOLDER_IO_OPEN   = 2,  /* could not re-open the staged temp (see ioerr)   */
    FOLDER_IO_READ   = 3,  /* a read errored while verifying (see ioerr)      */
    FOLDER_IO_TOOBIG = 4,  /* more blocks than the cap, or an absurd block size*/
    FOLDER_IO_PATH   = 5,  /* final path too long to assemble                 */
    FOLDER_IO_RENAME = 6,  /* verify passed but rename into place failed      */
    FOLDER_IO_SIZE   = 7   /* staged size differs from expect_size (fast path)*/
} FolderIoReason;

/* Diagnostic detail for a FOLDER_RECV_MISMATCH (optional out-param to
 * recv_finish). Distinguishes a truncated/short temp (got_blocks != exp_blocks)
 * from a specific corrupted block (bad_block >= 0), so a systematic offset bug
 * reads differently from scattered media/memory corruption. */
typedef struct {
    int     bad_block;    /* first block whose on-disk hash differs, or -1     */
    int64_t bad_off;      /* byte offset of bad_block, or -1                   */
    int     got_blocks;   /* whole blocks read from the staged temp, or -1     */
    int     exp_blocks;   /* blocks expected                                   */
    FolderIoReason io_reason;                  /* behind a FOLDER_RECV_IO     */
    long    ioerr;        /* DOS IoErr() for io_reason OPEN/READ, else 0       */
} FolderRecvInfo;

/* Open (or resume) the staged temp for <path>/<name>. If a partial temp survives
 * from an earlier attempt, it is reused and *resume_from is set to the count of
 * whole leading blocks already present (floor(tempsize/block_size), capped at
 * num_blocks) so the caller fetches only the rest; otherwise a fresh (truncated)
 * temp is created and *resume_from is 0. The trusted prefix is guarded by the
 * final whole-file verify in recv_finish, which discards a stale/mismatched temp
 * and re-fetches. Returns the handle, or 0 on failure. */
FolderFile folder_recv_open(const char *path, const char *name,
                            char *tmp, int tmpcap, int32_t block_size,
                            int num_blocks, int *resume_from);
/* What folder_recv_write could do with a block. A staged temp is only ever
 * written forward: AmigaOS filesystems refuse a Seek past EOF (FFS returns -1),
 * and one that allowed it would leave a hole full of whatever was on disk. A
 * block whose offset is beyond the temp's current end therefore cannot be
 * stored yet - the caller re-requests it once the blocks before it have
 * landed. */
typedef enum {
    FOLDER_WRITE_OK    =  1,   /* stored                                      */
    FOLDER_WRITE_FAIL  =  0,   /* seek/write error - the transfer is finished  */
    FOLDER_WRITE_AHEAD = -1    /* offset past the temp's end: not its turn yet */
} FolderWriteResult;

FolderWriteResult folder_recv_write(FolderFile fh, int64_t offset,
                                    const void *data, int len);
/* Close the temp, verify it, and rename it over the final name. Returns a
 * FolderRecvResult. With 'skip_verify' (set when EVERY block was SHA-verified
 * as it was written in this session - i.e. the temp was not resumed from an
 * earlier run) only the staged file's flushed size is checked against
 * 'expect_size'; otherwise the whole temp is re-read and re-hashed against
 * 'expect' (the folded content hash). The optional 'block_hashes'/'num_blocks'
 * (the expected per-block hashes) let a full-verify mismatch be localised to
 * the first divergent block, reported via 'info' (also optional). On any
 * failure the temp is deleted and the target left untouched. */
FolderRecvResult folder_recv_finish(const char *path, const char *name,
                                    const char *tmp, FolderFile fh,
                                    int64_t modified_s, uint32_t perms,
                                    int32_t block_size, int64_t expect_size,
                                    int skip_verify, int archive_always,
                                    const unsigned char expect[BEP_HASH_LEN],
                                    const unsigned char (*block_hashes)[BEP_HASH_LEN],
                                    int num_blocks, FolderRecvInfo *info);
void folder_recv_abort(FolderFile fh, const char *tmp);

/* Stamp an existing file's datestamp (and protection bits, when 'perms'
 * is non-zero) from a record's metadata - the SYNC_ADOPT path aligns the
 * disk with the record it just took from the peer, exactly as a finished
 * download would. Best-effort; returns 1 on success. */
int  folder_touch(const char *path, const char *name, int64_t modified_s,
                  uint32_t perms);

/* Index persistence (in the state directory, not a synced folder).
 * folder_state_path builds <statedir>/<hex16>.idx, where hex16 is a stable
 * 64-bit FNV-1a hash of 'folder_id' (a legal AmigaOS filename regardless of the
 * id's characters; no AmiSSL needed, so it works in the main process). Returns 1
 * on success, 0 if the path would not fit. */
int  folder_state_path(const char *statedir, const char *folder_id,
                       char *out, int cap);

/* Create directory 'path' (and any missing parents). 1 if it exists afterwards.
 * Intermediate components are best-effort: only the final directory's presence
 * decides the result (see folder_mkdir for the stricter, unjoined variant). */
int  folder_ensure_dir(const char *path);

/* Current wall-clock time as Unix seconds (for delete tombstone versions). */
/* How far ahead of UTC this machine's clock is set, in seconds (east
 * positive: +7200 for CEST, -14400 for EDT). An AmigaOS clock holds local
 * time; BEP timestamps are UTC. Call once at startup, before the scanner or
 * any worker runs. 0 - the default - reads the clock as if it were UTC, which
 * is what every version before this did. */
void folder_set_tz_offset(int seconds_east);

/* What that was set to, for the code that has to notice it changing. */
int  folder_tz_offset(void);

int64_t folder_now(void);

/* The value to seed OUR version counter with for a local change to a file
 * whose modification time is 'modified_s': the later of that time and the
 * clock. sync_bump_version already forces the result past our own previous
 * counter, so this is the third term of a three-way max, and the one that
 * decides what a counter starts at when we have no history for a record -
 * after an index is lost or a folder re-added.
 *
 * Neither source is trustworthy alone on this hardware. The clock is what
 * Syncthing uses, and it is right whenever the machine's is; but an Amiga
 * whose RTC battery has died can read years in the past, and then a rebuilt
 * index would seed counters BELOW the ones it issued before, and lose to its
 * own history. The file's own mtime covers exactly that case, because a file
 * we received carries the time of the machine that made it - one that
 * probably knew what time it was. Taking the later of the two inherits
 * whichever source was sound.
 *
 * An overlarge counter costs nothing: a counter is only ever compared with
 * other values for the SAME device key, so inflating ours can never beat a
 * peer's later edit - only our own earlier records, which is the point. */
uint64_t folder_version_stamp(int64_t modified_s);

/* Is <path>/<name> still on disk? Answers the question a failed hash cannot:
 * a file we could not read may be held open by another program, or may have
 * been deleted while the scan walked past it, and only the second may be
 * tombstoned. Reports "present" for anything other than a definite
 * object-not-found - saying a file is gone when it is not would announce a
 * deletion of it to every peer. */
int folder_exists(const char *path, const char *name);

/* Size of the file at 'path' in bytes; -1 if it is absent or unreadable (the
 * two are not distinguished - every caller treats <= 0 as "nothing to read").
 * Not index-specific despite the name: folder_recv_open sizes a staged temp
 * with it to decide how much of a partial download can be resumed. */
long folder_state_size(const char *path);

/* Read the whole file at 'path' into 'buf' (cap bytes): returns the byte count
 * read, 0 if absent, -1 on a read error. */
int  folder_state_read(const char *path, void *buf, int cap);

/* Write 'len' bytes to 'path' atomically (a temp file then Rename over it, both
 * in the same directory). Returns 1 on success. */
int  folder_state_write(const char *path, const void *data, int len);

/* Path to a non-index file kept beside the indexes in 'statedir' ('leaf' is a
 * plain filename; indexes are <16 hex>.idx, so anything else cannot collide). */
int  folder_aux_path(const char *statedir, const char *leaf, char *out, int cap);

#endif /* AMISYNC_FOLDER_H */
