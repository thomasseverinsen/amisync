/* index_store.h - on-disk codec for a folder's shared index
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Persisting each folder's FolderState means a reconnect or a daemon restart
 * re-uses the stored {size, mtime, content_hash, block hashes, version, sequence}
 * and re-hashes only files that actually changed - the durable half of "hash
 * once". This module is the swappable storage-backend boundary: it is
 * pure pbuf encode/decode of the index blob, with no dos.library or AmiSSL, so it
 * is host-tested (tests/test_index_store.c). The atomic file I/O around it lives
 * in folder.c (folder_state_read/write); the scanner orchestrates load/save.
 *
 * Format (a flat pbuf field stream, not nested messages, so encoding needs no
 * per-record scratch and decoding reads block hashes zero-copy):
 *   header   fields 1..5  (magic, format, folder_id, short_id, high_seq)
 *   record   fields 20..  (a new record begins each time field 20 (name) recurs)
 * Unknown fields are skipped, so the format is forward-compatible by construction.
 */

#ifndef AMISYNC_INDEX_STORE_H
#define AMISYNC_INDEX_STORE_H

#include <stddef.h>

#include "foldstate.h"

/* An upper bound on the encoded size of 'fs', for sizing the save buffer.
 * Walks the record table, so - like index_store_encode - it does not lock and
 * the caller must serialise against writers itself. Always fits in an int on
 * this target (FOLDSTATE_MAX_FILES bounds it), which is what encode returns. */
size_t index_store_size(const FolderState *fs);

/* Encode 'fs' (its records, block hashes and sequence high-water) into 'buf'
 * (cap bytes). Returns the byte length, or 0 on overflow. Does not lock - the
 * caller serialises against writers itself (today: the scanner). */
int index_store_encode(const FolderState *fs, void *buf, size_t cap);

/* Decode 'data'/'len' into 'fs', which must already be foldstate_init()'d for the
 * target folder: the blob's folder_id and short_id are checked against it, and a
 * mismatch (or bad magic / unknown format / truncation) makes this return 0 with
 * 'fs' left empty - the caller then treats it as "no index" and full-rescans.
 * On success returns 1 with 'fs' populated, its sequence high-water restored and
 * its dirty flag clear. Any prior contents of 'fs' are released first. */
int index_store_decode(FolderState *fs, const void *data, size_t len);

#endif /* AMISYNC_INDEX_STORE_H */
