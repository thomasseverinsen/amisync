/* offered.h - folders peers offer us that we have not configured
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A peer's ClusterConfig may list folders we have no configuration for -
 * Syncthing's "device wants to share folder X with you". The workers note
 * them here as they decode CCs; the status report shows them under
 * "Offered - not configured", and the window's double-click accept flow
 * (ASL drawer requester -> daemon_folder_add under the offered id) turns
 * one into a configured folder without any typing.
 *
 * Like wreg: a small static table in the shared address space, entries
 * added/read under Forbid() (writers are worker tasks, readers the main
 * task; all operations are short pure-memory copies). An entry whose folder
 * becomes configured is filtered at DISPLAY time (sync_folder_index); see
 * offered_begin/end for the keying and the withdrawn-offer sweep.
 */

#ifndef AMISYNC_OFFERED_H
#define AMISYNC_OFFERED_H

#include "bep.h"
#include "device_id.h"

#define OFFERED_MAX 8

typedef struct {
    char id[BEP_FOLDER_ID_MAX];      /* the peer's folder id (must be used
                                      * verbatim when accepting)           */
    char label[BEP_NAME_MAX];        /* its human label, if any            */
    char device_name[BEP_NAME_MAX];  /* the offering peer's device name    */
    char device_id[DEVICE_ID_BUFSZ]; /* ...and its device id (the key)     */
} OfferedFolder;

/* Every ClusterConfig is the sending peer's COMPLETE current offer set, so
 * the worker brackets its CC decode with begin/end: begin marks that
 * device's entries stale, each note() refreshes (or adds) one and clears
 * its mark, end drops what stayed stale - a withdrawn offer disappears on
 * the very CC that withdrew it. Entries are keyed (device_id, folder id):
 * two peers offering the same folder are two entries, and one peer's sweep
 * cannot take another's offer with it. Slots are tombstoned in place, not
 * compacted (display tags carry slot indexes across ticks). All calls are
 * short Forbid()-bracketed memory ops, safe from any task. */
void offered_begin(const char *device_id);
void offered_note(const char *device_id, const char *device_name,
                  const char *id, const char *label);
void offered_end(const char *device_id);

/* Copy slot 'i' out. Returns 0 past the table - the loop terminator - else 1.
 * A tombstoned slot copies out with id[0] == '\0' and should be skipped:
 * slots are deliberately not compacted, so 1 does not mean "live". Safe from
 * any task. */
int offered_get(int i, OfferedFolder *out);

#endif /* AMISYNC_OFFERED_H */
