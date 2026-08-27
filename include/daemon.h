/* daemon.h - main daemon lifecycle for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_DAEMON_H
#define AMISYNC_DAEMON_H

#include "config.h"

/* Run the daemon: open the ARexx port, enter the wait loop, and block until
 * either CTRL-C (SIGBREAKF_CTRL_C) or an ARexx QUIT command is received.
 * Performs an orderly shutdown before returning.
 *
 * Returns 0 on a clean exit, non-zero if startup failed.
 *
 * 'cfg' is non-const because the ARexx ADDPEER verb / Tools-menu "Add
 * Discovered" can append to its peer table at runtime (peer_manager_add). */
int daemon_run(Config *cfg);

/* Runtime folder add/remove (the ARexx ADDFOLDER/REMOVEFOLDER verbs and
 * the status window's Add/Accept/Remove). Main task only. add: 1 added,
 * 0 invalid id/path or unwritable path, -1 already configured, -2 table
 * full (tombstoned slots are resurrected on re-add of the same id, so
 * full means 8 DISTINCT live ids), -3 the path is - or nests inside or
 * around - an already-synced drawer (compared canonically via
 * Lock/NameFromLock, so assigns and case cannot sneak a duplicate in).
 * remove: 1 removed, 0 unknown id. Both persist to the config file and
 * nudge the scanner/workers. */
#include "arexx.h"   /* ArexxContext */
int daemon_folder_add(const ArexxContext *ctx, const char *id,
                      const char *path, FolderMode mode,
                      const char *label);   /* NULL/"" = label is the id */
int daemon_folder_remove(const ArexxContext *ctx, const char *id);

#endif /* AMISYNC_DAEMON_H */
