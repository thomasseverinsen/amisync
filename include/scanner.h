/* scanner.h - the dedicated folder scan/hash process for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A single process, spawned by main, owns scanning/hashing (and
 * persistence) for ALL folders, writing the authoritative shared
 * FolderState. It cannot live in the main process - hashing a big folder would
 * block ARexx/QUIT - nor in the workers: they come and go per connection, so N
 * peers would race N scanners re-hashing the same folder N times. One scanner
 * means each folder is listed and SHA-256'd once regardless of peer count.
 *
 * It:
 *   - runs its own ssl_subtask_init() for SHA-256 (per-process AmiSSL base),
 *   - loads the persisted index on startup,
 *   - scans each folder, hashing only changed files OUTSIDE the FolderState
 *     lock, then updates FolderState INSIDE the lock, bumping the sequence,
 *   - re-scans on the idle tick, and within seconds of a change in a watched
 *     drawer (dos.library StartNotify on each folder root + subdirectory;
 *     best-effort - handlers without notification stay on the tick),
 *   - persists when dirty,
 *   - signals the connected workers (via wreg, WORKER_SIG_RESCAN) after any scan
 *     that advanced a folder's sequence, so they announce the new records now.
 *
 * Same single-active library-base model as the workers and the discovery
 * broadcaster (see worker.h, netbase.h): the scanner opens AmiSSL/bsdsocket for
 * its own task. Spawned/joined via scanner_start()/scanner_stop(), mirroring
 * disco_start()/disco_stop(). This whole module is Amiga-only (it does
 * dos.library + AmiSSL); the pure index logic lives in foldstate.
 */

#ifndef AMISYNC_SCANNER_H
#define AMISYNC_SCANNER_H

#include <exec/ports.h>

#include "config.h"
#include "foldstate.h"

/* Parameters handed to the scanner process via its process port. The FolderState
 * array (one entry per configured folder, same order as cfg->folders) is owned
 * by main and shared by pointer; the scanner is its single writer. */
typedef struct {
    struct Message  msg;          /* MUST be first: replied to main's port    */
    const Config   *cfg;          /* folder paths, modes, ignores             */
    FolderState    *folders;      /* shared per-folder index, [num_folders]   */
    int             num_folders;
    int             interval;     /* seconds between rescans                  */
    /* Targeted-rescan request bits, one per folder index (main sets under
     * Forbid, the scanner fetches-and-clears at pass start). Non-zero turns
     * that pass into a targeted one over just the flagged folders; 0 is the
     * normal full pass. CONFIG_MAX_FOLDERS fits comfortably. */
    volatile unsigned long rescan_mask;
    /* A full sweep is pending (ARexx RESCAN, the window's Rescan All, a
     * runtime folder add). It OUTRANKS rescan_mask: the two requests can be
     * in flight together in either order, and narrowing a "scan everything"
     * down to one folder loses the sweep - a folder added moments after a
     * per-folder Rescan would then wait out the whole interval. */
    volatile int rescan_all;
} ScannerStartup;

/* CreateNewProc entry point (pass as NP_Entry). */
void scanner_entry(void);

/* Supervisor handle owned by the daemon. */
typedef struct ScannerHandle ScannerHandle;

/* Start the scanner over the given shared FolderState array. Returns NULL if
 * there are no folders or on failure (the daemon runs without it, just
 * without shared scanning). */
ScannerHandle *scanner_start(const Config *cfg, FolderState *folders,
                             int num_folders);

/* Ask the scanner to scan all folders now (e.g. ARexx RESCAN) rather than wait
 * for the next idle tick. NULL-safe. */
void scanner_rescan(ScannerHandle *h);

/* Ask the scanner to scan ONE folder (config index) now (e.g. the status
 * window's per-folder Rescan). The next pass covers just the requested
 * folder(s); the regular full pass keeps its interval schedule. NULL-safe. */
void scanner_rescan_folder(ScannerHandle *h, int idx);

/* Signal the scanner, wait for it, and free the handle. NULL-safe. */
void scanner_stop(ScannerHandle *h);

#endif /* AMISYNC_SCANNER_H */
