/* spill.h - the wanted files that did not fit in the want queue
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A peer's Index is classified as it arrives and then thrown away, and the
 * want queue holds SYNC_MAX_WANT files. Everything past that used to be
 * dropped, and the only way to hear it again was to close the session so the
 * peer would send its whole Index once more - a reconnect per 256 files, and
 * the whole index re-streamed each time.
 *
 * This is the alternative: what does not fit is written to disk instead, and
 * read back as the queue drains. The peer says everything once.
 *
 * Deliberately SESSION-scoped. The file is truncated whenever a full Index
 * restates its folder, and deleted when the session ends, so it can never
 * disagree with the peer about what exists - the peer remains the authority
 * on that, exactly as before. What it removes is the need to ask twice.
 *
 * One file per (folder, peer): two workers syncing the same folder with
 * different peers each keep their own, so neither has to lock anything.
 *
 * RAM is the scarce resource on this hardware and disk is not: a spilled
 * record is a name, the metadata to fetch it, and its block hashes - a few
 * hundred bytes - and the reader holds exactly one at a time.
 */

#ifndef AMISYNC_SPILL_H
#define AMISYNC_SPILL_H

#include <stdint.h>

#include "bep.h"

typedef struct {
    void *fh;                  /* BPTR to the open file, 0 when not open   */
    long  roff;                /* read cursor; write always appends at end */
    long  woff;                /* end of file, where the next record goes  */
    int   ok;                  /* 1 while the file is usable               */
    int   failed;              /* create failed once: stop trying, and stop
                                * saying so - the caller asks per record   */
    int   nleft;               /* records parked and not yet taken back     */
    char  path[256];
} SpillFile;

/* Build this worker's spill path under 'statedir'. Both ids are
 * hashed, so any folder id or device id is a legal filename. 'ext' picks which
 * of a pair's spills is meant - ".spl" for wanted files, ".spd" for the
 * deletions held back so a rename can find its source. */
int  spill_path(const char *statedir, const char *folder_id, const char *peer_id,
                uint32_t uniq, const char *ext, char *out, int cap);

/* Create or truncate the spill and write its header. Returns 1 on success; on
 * failure 'sp' is left unusable (ok = 0) and the caller carries on without a
 * spill - the old drop-and-reconnect behaviour still works. */
int  spill_reset(SpillFile *sp, const char *path);

/* Append one wanted file: the peer's record, its block hashes, and whether the
 * local copy must be set aside as a conflict copy first. Returns 1 on success,
 * 0 if the record could not be written (out of space, no file). */
int  spill_append(SpillFile *sp, const BepFileInfo *fi,
                  const unsigned char (*hashes)[BEP_HASH_LEN], int nb,
                  int conflict);

/* Read the record at the read cursor WITHOUT consuming it: 'next' receives the
 * offset to commit to once the caller has taken it (see spill_commit), so a
 * record is never lost to a queue that turned out to be full again. Returns 1
 * when a record was read, 0 at the end of the file, -1 on a damaged one (the
 * caller should stop reading this spill). 'max_blocks' bounds what the caller's
 * hash buffer can hold. */
int  spill_next(SpillFile *sp, long *next, BepFileInfo *fi,
                unsigned char (*hashes)[BEP_HASH_LEN], int max_blocks,
                int *nb, int *conflict);

/* Accept the record that spill_next returned, advancing past it. */
void spill_commit(SpillFile *sp, long next);

/* Is there anything left to read? */
int  spill_pending(const SpillFile *sp);

/* Everything parked has been taken back: reuse the file from the top rather
 * than deleting and re-creating it, which a large index would otherwise do
 * once per burst. */
void spill_rewind(SpillFile *sp);

/* How many records are still parked - part of the folder's real backlog, and
 * the reason a status built only from the want queue would under-report a
 * large transfer by everything that did not fit in it. */
int  spill_count(const SpillFile *sp);

/* Close the file and delete it. Always safe, including on a zeroed struct. */
void spill_close(SpillFile *sp);

#endif /* AMISYNC_SPILL_H */
