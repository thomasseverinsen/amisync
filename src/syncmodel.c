/* syncmodel.c - pure sync decision logic for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See syncmodel.h. Pure C over FileInfo/Config data - no AmiSSL, sockets or
 * dos.library - so it is exercised on the build host in tests/test_syncmodel.c.
 */

#include <stdio.h>
#include <string.h>

#include "syncmodel.h"

void sync_init(SyncModel *m)
{
    memset(m, 0, sizeof(*m));
}

uint64_t sync_short_id_from_raw(const unsigned char raw[32])
{
    uint64_t v = 0;
    int      i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | raw[i];
    return v;
}

int sync_folder_index(const Config *cfg, const char *id)
{
    int i;
    for (i = 0; i < cfg->num_folders; i++)
        if (!cfg->folders[i].removed &&
            strcmp(cfg->folders[i].id, id) == 0)
            return i;
    return -1;
}

/* Copy the persistent metadata fields out of a (transiently fully-populated)
 * BepFileInfo, dropping its block array. content_hash is carried across when the
 * caller has folded one (the worker does, on scan and on index receipt). */
static void meta_from_fi(SyncMeta *m, const BepFileInfo *fi)
{
    memset(m, 0, sizeof(*m));
    memcpy(m->name, fi->name, sizeof(m->name));
    m->type             = fi->type;
    m->size             = fi->size;
    m->permissions      = fi->permissions;
    m->modified_s       = fi->modified_s;
    m->modified_ns      = fi->modified_ns;
    m->modified_by      = fi->modified_by;
    m->deleted          = fi->deleted;
    m->invalid          = fi->invalid;
    m->sequence         = fi->sequence;
    m->block_size       = fi->block_size;
    m->version          = fi->version;
    m->has_content_hash = fi->has_content_hash;
    if (fi->has_content_hash)
        memcpy(m->content_hash, fi->content_hash, BEP_HASH_LEN);
}

int sync_content_same(const SyncMeta *have, const BepFileInfo *peer)
{
    if (have->size != peer->size)
        return 0;
    if (!have->has_content_hash || !peer->has_content_hash)
        return 0;                              /* can't prove identity */
    return memcmp(have->content_hash, peer->content_hash, BEP_HASH_LEN) == 0;
}

void sync_make_tombstone(BepFileInfo *fi, const char *name, int type,
                         uint64_t short_id, int64_t when, int64_t seq)
{
    size_t n = strlen(name);
    if (n > BEP_PATH_MAX - 1)
        n = BEP_PATH_MAX - 1;

    memset(fi, 0, sizeof(*fi));
    memcpy(fi->name, name, n);
    fi->name[n]     = '\0';
    fi->type        = type;
    fi->deleted     = 1;
    fi->modified_s  = when;
    fi->permissions = 0644;
    fi->sequence    = seq;
    fi->version.num_counters      = 1;
    fi->version.counters[0].id    = short_id;
    fi->version.counters[0].value = (uint64_t)when;
}

void sync_bump_version(BepVector *out, const BepVector *prev,
                       uint64_t short_id, uint64_t value)
{
    int i;

    if (prev && prev != out)
        *out = *prev;
    else if (!prev)
        out->num_counters = 0;

    for (i = 0; i < out->num_counters; i++)
        if (out->counters[i].id == short_id)
            break;

    if (i < out->num_counters) {
        if (value <= out->counters[i].value)
            value = out->counters[i].value + 1;       /* strictly increase ours */
        out->counters[i].value = value;
    } else if (out->num_counters < BEP_MAX_COUNTERS) {
        out->counters[out->num_counters].id    = short_id;
        out->counters[out->num_counters].value = value;
        out->num_counters++;
    }
    /* Vector full and ours absent: the bump is dropped deliberately. Our edit
     * then announces under an unchanged vector and will not dominate - the
     * alternative (evicting someone else's counter) loses more. */
}

/* Counter value for 'id' in 'v', 0 if absent (absent == never modified). */
static uint64_t vec_counter(const BepVector *v, uint64_t id)
{
    int i;
    for (i = 0; i < v->num_counters; i++)
        if (v->counters[i].id == id)
            return v->counters[i].value;
    return 0;
}

int sync_version_has(const BepVector *v, uint64_t id)
{
    return v && vec_counter(v, id) != 0;
}

SyncVerRel sync_version_compare(const BepVector *ours, const BepVector *theirs)
{
    int i, ours_gt = 0, theirs_gt = 0;

    for (i = 0; i < ours->num_counters; i++) {
        uint64_t a = ours->counters[i].value;
        uint64_t b = vec_counter(theirs, ours->counters[i].id);
        if (a > b) ours_gt = 1;
        else if (b > a) theirs_gt = 1;
    }
    for (i = 0; i < theirs->num_counters; i++)
        if (theirs->counters[i].value > vec_counter(ours, theirs->counters[i].id))
            theirs_gt = 1;

    if (ours_gt && theirs_gt) return SYNC_V_CONCURRENT;
    if (ours_gt)              return SYNC_V_OURS;
    if (theirs_gt)            return SYNC_V_THEIRS;
    return SYNC_V_EQUAL;
}

/* Resolve a concurrent edit between two LIVE copies, Syncthing-style: the
 * newer modification wins; ties break on modified_ns, then on the larger
 * content_hash. Returns SYNC_CONFLICT when the peer's copy wins (caller
 * preserves ours first), SYNC_IGNORE when ours does (the peer runs the same
 * deterministic rule on its side and preserves its copy). */
static SyncAction resolve_conflict(const SyncMeta *have, const BepFileInfo *peer)
{
    if (peer->modified_s != have->modified_s)
        return peer->modified_s > have->modified_s ? SYNC_CONFLICT : SYNC_IGNORE;
    if (peer->modified_ns != have->modified_ns)
        return peer->modified_ns > have->modified_ns ? SYNC_CONFLICT : SYNC_IGNORE;
    if (have->has_content_hash && peer->has_content_hash) {
        int c = memcmp(peer->content_hash, have->content_hash, BEP_HASH_LEN);
        if (c != 0)
            return c > 0 ? SYNC_CONFLICT : SYNC_IGNORE;
    }
    return SYNC_IGNORE;              /* indistinguishable: keep ours */
}

SyncAction sync_classify_incoming(const SyncMeta *have, FolderMode mode,
                                  const BepFileInfo *peer)
{
    int have_vectors;

    if (mode == FOLDER_SENDONLY)
        return SYNC_IGNORE;                         /* we never pull here */

    /* Vectors decide only when both sides carry one; rows without (records
     * predating version tracking) fall back to the last-writer mtime rule. */
    have_vectors = have && have->version.num_counters > 0 &&
                   peer->version.num_counters > 0;

    if (peer->deleted) {
        if (!have || have->deleted)
            return SYNC_IGNORE;                     /* nothing to remove */
        if (have_vectors) {
            /* Only a dominating deletion removes our copy: a concurrent
             * delete-vs-edit resolves in favour of the data (Syncthing rule) -
             * our re-announce then propagates the file back. */
            return sync_version_compare(&have->version, &peer->version)
                       == SYNC_V_THEIRS ? SYNC_DELETE : SYNC_IGNORE;
        }
        if (peer->modified_s < have->modified_s)
            return SYNC_IGNORE;                     /* our copy is newer */
        return SYNC_DELETE;
    }

    /* A live peer file. Whether we can actually address/buffer its blocks
     * (block size, block count) is checked by the worker before it enqueues a
     * fetch; this pure decision is only about version/content/last-writer. */
    if (have) {
        int same = !have->deleted && sync_content_same(have, peer);
        if (have_vectors) {
            switch (sync_version_compare(&have->version, &peer->version)) {
            case SYNC_V_THEIRS:
                /* Identical content under a dominating vector happens when
                 * an index is rebuilt from disk (folder remove/re-add): our
                 * fresh counters lose to the peer's history. Adopt its
                 * version - a metadata-only catch-up, no transfer. */
                return same ? SYNC_ADOPT : SYNC_FETCH;
            case SYNC_V_OURS:    return SYNC_IGNORE;
            case SYNC_V_EQUAL:
                /* Same version must mean the same record, metadata
                 * included: Syncthing counts us as HAVING an item only
                 * when our announced record matches its copy, so an
                 * equal-vector row with a differing mtime reads as "out
                 * of sync" forever (rows damaged by the early adopt that
                 * kept local mtime under the peer's vector). Take the
                 * peer's metadata - the version stays, so the corrected
                 * re-announce settles it without any bump war. */
                if (same && (have->modified_s  != peer->modified_s ||
                             have->modified_ns != peer->modified_ns ||
                             have->permissions != peer->permissions))
                    return SYNC_ADOPT;
                return SYNC_IGNORE;
            case SYNC_V_CONCURRENT:
                if (same)
                    /* Identical content on both sides of a concurrent pair
                     * (typical after a folder remove/re-add, or any index
                     * rebuilt from disk: our fresh {us:n} against the peer's
                     * {peer:m}). There is no copy worth preserving, so take
                     * the peer's record and be done.
                     *
                     * This used to defer to resolve_conflict and keep ours
                     * whenever that could not separate them - which is
                     * exactly the case that matters, because after a rebuild
                     * the mtime, the nanoseconds and the content hash all
                     * MATCH. "Indistinguishable" then meant nobody yielded:
                     * both sides announced concurrent versions for a file
                     * they held byte-identically, forever. Seen twice now,
                     * five files each time, and the second time the peer sat
                     * at 51% over 43 MB it already had.
                     *
                     * Adopting is free when nothing but the version differs,
                     * and it ends the disagreement in one pass: taking their
                     * vector makes ours EQUAL to it rather than concurrent
                     * with it. Only the tie is treated this way. Where our
                     * mtime is genuinely newer we still keep ours, because
                     * the peer applies the same last-writer rule from its
                     * side and will take ours - yielding there would only
                     * move a user's timestamp backwards. */
                    return (have->modified_s  == peer->modified_s &&
                            have->modified_ns == peer->modified_ns)
                               ? SYNC_ADOPT
                               : (resolve_conflict(have, peer) == SYNC_CONFLICT
                                      ? SYNC_ADOPT : SYNC_IGNORE);
                if (have->deleted)
                    return SYNC_FETCH;    /* their edit beats our tombstone */
                return resolve_conflict(have, peer);
            }
        }
        if (same)
            return SYNC_IGNORE;                     /* already up to date */
        if (peer->modified_s < have->modified_s)
            return SYNC_IGNORE;                     /* ours (or our delete) wins */
    }
    return SYNC_FETCH;
}

/* Civil date (UTC) from unix seconds, via the days-from-epoch algorithm. */
static void civil_from_unix(int64_t t, int *y, int *mo, int *d,
                            int *h, int *mi, int *s)
{
    int64_t days = t / 86400;
    int     rem  = (int)(t % 86400);
    int64_t era;
    unsigned doe, yoe, doy, mp;

    if (rem < 0) { rem += 86400; days--; }
    *h  = rem / 3600;
    *mi = (rem % 3600) / 60;
    *s  = rem % 60;

    days += 719468;                                /* epoch -> civil offset */
    era = (days >= 0 ? days : days - 146096) / 146097;
    doe = (unsigned)(days - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp  = (5 * doy + 2) / 153;
    *d  = (int)(doy - (153 * mp + 2) / 5 + 1);
    *mo = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y  = (int)(yoe + era * 400 + (*mo <= 2));
}

int sync_make_conflict_name(char *out, int cap, const char *name,
                            int64_t now_s, const char *tag, int compact)
{
    char        suffix[48];
    const char *base, *dot;
    int         y, mo, d, h, mi, s, stem, nlen, slen;

    civil_from_unix(now_s, &y, &mo, &d, &h, &mi, &s);
    if (compact)
        sprintf(suffix, ".cnfl-%02d%02d%02d", h, mi, s);
    else
        sprintf(suffix, ".sync-conflict-%04d%02d%02d-%02d%02d%02d-%.7s",
                y, mo, d, h, mi, s, tag);

    /* Insert before the extension of the final path component. */
    base = strrchr(name, '/');
    base = base ? base + 1 : name;
    dot  = strrchr(base, '.');
    nlen = (int)strlen(name);
    stem = dot ? (int)(dot - name) : nlen;
    slen = (int)strlen(suffix);
    if (nlen + slen >= cap)
        return 0;
    memcpy(out, name, stem);
    memcpy(out + stem, suffix, slen);
    memcpy(out + stem + slen, name + stem, nlen - stem + 1);  /* incl. NUL */
    return 1;
}

int sync_want_push(SyncModel *m, int folder_idx, const BepFileInfo *meta,
                   const unsigned char (*hashes)[BEP_HASH_LEN], int num_blocks,
                   int conflict)
{
    return sync_want_push_again(m, folder_idx, meta, hashes, num_blocks,
                                conflict, 0);
}

int sync_want_push_again(SyncModel *m, int folder_idx, const BepFileInfo *meta,
                         const unsigned char (*hashes)[BEP_HASH_LEN],
                         int num_blocks, int conflict, int attempts)
{
    WantFile *t;

    if (m->num_want >= SYNC_MAX_WANT)
        return 0;
    /* Subtract rather than add: num_blocks is peer-derived, and a hostile
     * value large enough to wrap 'hash_used + num_blocks' would pass an
     * addition-shaped check and run the memcpy below off want_hashes. */
    if (num_blocks < 0 || num_blocks > SYNC_HASH_POOL - m->hash_used)
        return 0;                              /* pool full: defer this file */

    t = &m->want[m->num_want];
    t->folder_idx = folder_idx;
    meta_from_fi(&t->fi, meta);
    t->hash_off   = m->hash_used;
    t->num_blocks = num_blocks;
    t->conflict   = conflict;
    t->attempts   = attempts;
    if (num_blocks > 0)
        memcpy(m->want_hashes[m->hash_used], hashes,
               (size_t)num_blocks * BEP_HASH_LEN);
    m->hash_used += num_blocks;
    m->num_want++;
    return 1;
}

int sync_want_has(const SyncModel *m, int folder_idx, const char *name)
{
    int i;
    for (i = 0; i < m->num_want; i++)
        if (m->want[i].folder_idx == folder_idx &&
            strcmp(m->want[i].fi.name, name) == 0)
            return 1;
    return 0;
}

int sync_want_peek(const SyncModel *m, int *folder_idx, char *name, int cap)
{
    const WantFile *t;

    if (m->num_want == 0)
        return 0;
    t = &m->want[m->num_want - 1];
    if (folder_idx)
        *folder_idx = t->folder_idx;
    if (name && cap > 0) {
        strncpy(name, t->fi.name, (size_t)cap - 1);
        name[cap - 1] = '\0';
    }
    return 1;
}

int sync_want_pop(SyncModel *m, WantFile *out,
                  unsigned char (*hashes_out)[BEP_HASH_LEN], int cap)
{
    WantFile *t;
    int       ncopy;

    if (m->num_want == 0)
        return 0;
    t     = &m->want[--m->num_want];
    *out  = *t;
    ncopy = t->num_blocks < cap ? t->num_blocks : cap;
    if (ncopy > 0 && hashes_out)
        memcpy(hashes_out, m->want_hashes[t->hash_off],
               (size_t)ncopy * BEP_HASH_LEN);
    m->hash_used = t->hash_off;                 /* LIFO: free from the top */
    return 1;
}
