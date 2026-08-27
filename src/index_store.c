/* index_store.c - on-disk codec for a folder's shared index
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See index_store.h. Pure pbuf encode/decode over caller buffers, host-tested.
 */

#include <string.h>

#include "index_store.h"
#include "pbuf.h"
#include "bep.h"        /* BepVector, BEP_MAX_COUNTERS, BEP_HASH_LEN */

#define IDX_MAGIC   0x414D5358u   /* "AMSX" */
/* Bumped to 2 when F_END became required: a format-1 file has no end marker,
 * so it cannot be told apart from a truncated one, and accepting it would
 * leave the hole this version exists to close. The cost is one full rescan per
 * folder on upgrade - the index is a cache, and re-hashing it is exactly what
 * it is designed to survive. */
#define IDX_FORMAT  2u

/* Header fields. */
#define F_MAGIC      1
#define F_FORMAT     2
#define F_FOLDER_ID  3
#define F_SHORT_ID   4
#define F_HIGH_SEQ   5
/* End-of-stream marker, carrying the record count. Written LAST, after every
 * record, and required: it is what tells a complete file from one that simply
 * stops. A count in the HEADER would not do it - the header can be cut too,
 * and a blob cut in the middle of the final record still has the right number
 * of records. Its arrival proves every byte before it was written. */
#define F_END        6

/* Record fields (a record begins each time F_NAME recurs). */
#define F_NAME         20
#define F_TYPE         21
#define F_SIZE         22
#define F_MODIFIED_S   23
#define F_MODIFIED_NS  24
#define F_DELETED      25
#define F_CONTENT_HASH 26
#define F_VERSION      27
#define F_SEQUENCE     28
#define F_BLOCK_HASHES 29
#define F_PERMISSIONS  30
#define F_BLOCK_SIZE   31
#define F_INVALID      32
#define F_MODIFIED_BY  33   /* added 2026-07-30; older files simply lack it
                             * (0) and older readers skip it - the tagged
                             * format needs no version bump for this */

/* ---- encode --------------------------------------------------------- */

static void encode_vector(PbufWriter *w, const BepVector *v)
{
    unsigned char scratch[BEP_MAX_COUNTERS * 24 + 16];
    PbufWriter    vw;
    int           i;

    pbuf_writer_init(&vw, scratch, sizeof(scratch));
    for (i = 0; i < v->num_counters; i++) {
        unsigned char cscr[32];
        PbufWriter    cw;
        pbuf_writer_init(&cw, cscr, sizeof(cscr));
        pbuf_write_uint64(&cw, 1, v->counters[i].id);
        pbuf_write_uint64(&cw, 2, v->counters[i].value);
        pbuf_write_message(&vw, 1, &cw);          /* Vector.counters = 1 */
    }
    pbuf_write_message(w, F_VERSION, &vw);
}

/* Per-record byte budget for the SCALAR fields of the size estimate. Worst
 * case, with the 2-byte tags field numbers 20-33 take:
 *   size 10+2, modified_s 10+2, modified_ns 10+2, sequence 10+2,
 *   permissions 5+2, block_size 10+2, modified_by 10+2,
 *   type/deleted/invalid 3x(1+2), content_hash 32+2+1 = 124 of the 128.
 * The four 10s are the ones that bite: pbuf_write_int64 sign-extends, so any
 * negative size/mtime/block_size - which a peer can put in a FileInfo, and
 * which meta_from_fileinfo copies through unclamped - costs a full-width
 * varint rather than the 5 or 9 bytes a sane value takes.
 * ADDING A FIELD MEANS RE-TALLYING THIS: index_store_encode returns 0 on
 * overflow, so a too-small estimate shows up as a silently unsaved index. */
#define IDX_REC_BUDGET  128

/* ...and the framing of each LENGTH-DELIMITED field, which the payload sizes
 * added below do not include: a 2-byte tag plus a length varint. The largest
 * is F_BLOCK_HASHES at FOLDER_MAX_BLOCKS*32 = 65536, whose length takes three
 * bytes; F_NAME and F_VERSION need two. Counted per field rather than folded
 * into the budget above so that adding a field means adding a term here,
 * visibly, instead of quietly eating someone else's slack - which is what
 * went wrong: the budget's 4 spare bytes were covering 13 bytes of framing. */
#define IDX_LEN_FRAME  5

size_t index_store_size(const FolderState *fs)
{
    size_t total = 96;                            /* header + slack */
    int    i;
    for (i = 0; i < fs->num_files; i++)
        total += IDX_REC_BUDGET
               + IDX_LEN_FRAME + strlen(foldstate_name(fs, &fs->files[i]))
                                                          /* F_NAME */
               + IDX_LEN_FRAME + (size_t)fs->nblocks[i] * BEP_HASH_LEN
                                                          /* F_BLOCK_HASHES */
               + IDX_LEN_FRAME
               + (size_t)foldstate_version_count(&fs->files[i]) * 24;
                                                          /* F_VERSION       */
    return total;
}

int index_store_encode(const FolderState *fs, void *buf, size_t cap)
{
    PbufWriter w;
    int        i;

    pbuf_writer_init(&w, buf, cap);
    pbuf_write_uint64(&w, F_MAGIC,     IDX_MAGIC);
    pbuf_write_uint64(&w, F_FORMAT,    IDX_FORMAT);
    pbuf_write_string(&w, F_FOLDER_ID, fs->folder_id);
    pbuf_write_uint64(&w, F_SHORT_ID,  fs->short_id);
    pbuf_write_uint64(&w, F_HIGH_SEQ,  (uint64_t)fs->sequence);

    for (i = 0; i < fs->num_files; i++) {
        const FolderRec *m = &fs->files[i];

        pbuf_write_string(&w, F_NAME,        foldstate_name(fs, m));
        pbuf_write_uint64(&w, F_TYPE,        (uint64_t)m->type);
        pbuf_write_uint64(&w, F_SIZE,        (uint64_t)m->size);
        pbuf_write_int64 (&w, F_MODIFIED_S,  m->modified_s);
        pbuf_write_int64 (&w, F_MODIFIED_NS, m->modified_ns);
        pbuf_write_bool  (&w, F_DELETED,     m->deleted);
        if (m->has_content_hash)
            pbuf_write_bytes(&w, F_CONTENT_HASH, m->content_hash, BEP_HASH_LEN);
        {
            BepVector v;
            encode_vector(&w, foldstate_version(fs, m, &v));
        }
        pbuf_write_int64 (&w, F_SEQUENCE,    m->sequence);
        if (fs->blocks[i] && fs->nblocks[i] > 0)
            pbuf_write_bytes(&w, F_BLOCK_HASHES, fs->blocks[i],
                             (size_t)fs->nblocks[i] * BEP_HASH_LEN);
        pbuf_write_uint64(&w, F_PERMISSIONS, m->permissions);
        pbuf_write_int64 (&w, F_BLOCK_SIZE,  m->block_size);
        pbuf_write_bool  (&w, F_INVALID,     m->invalid);
        if (m->modified_by)
            pbuf_write_uint64(&w, F_MODIFIED_BY, m->modified_by);
    }

    pbuf_write_uint64(&w, F_END, (uint64_t)fs->num_files);   /* see F_END */

    return w.error ? 0 : (int)w.len;
}

/* ---- decode --------------------------------------------------------- */

/* One Vector.counters submessage; mirrors encode_vector's inner writer.
 * Lenient like its caller: a malformed counter just stops early. */
static void decode_counter(const unsigned char *buf, size_t len, BepCounter *c)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    c->id = c->value = 0;
    pbuf_reader_init(&r, buf, len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t v;
        if (field == 1 && wt == PBUF_WT_VARINT && pbuf_read_varint(&r, &v))
            c->id = v;
        else if (field == 2 && wt == PBUF_WT_VARINT && pbuf_read_varint(&r, &v))
            c->value = v;
        else if (!pbuf_skip(&r, wt))
            return;
    }
}

static void decode_vector(const unsigned char *buf, size_t len, BepVector *v)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(v, 0, sizeof(*v));
    pbuf_reader_init(&r, buf, len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {            /* Vector.counters */
            if (!pbuf_read_bytes(&r, &p, &n)) return;
            if (v->num_counters < BEP_MAX_COUNTERS)
                decode_counter(p, n, &v->counters[v->num_counters++]);
        } else if (!pbuf_skip(&r, wt)) {
            return;
        }
    }
}

/* Release any contents of 'fs' so decode can fill it fresh (keeps the semaphore
 * and the folder_id/short_id init'd by the caller). */
static void reset_records(FolderState *fs)
{
    foldstate_free(fs);                    /* frees the block arrays and the
                                            * record table; leaves these two */
    fs->sequence  = 0;
    fs->dirty     = 0;
}

/* Is the decoded header ours? A mismatch means the file belongs to another
 * folder, another device, or another format version. */
/* The wire type each known field must carry, or -1 for one we do not know.
 * A tag whose type disagrees with the field it names is a corrupt file, not a
 * future extension: taken at face value, a varint read as a length prefix
 * consumes the following record's bytes as its payload and the reader carries
 * on reinterpreting them as tags, yielding a plausible-looking but wrong index
 * instead of a rejection. Unknown fields still skip-and-continue, which is
 * what forward compatibility actually needs. */
static int expected_wt(uint32_t field)
{
    switch (field) {
    case F_MAGIC: case F_FORMAT: case F_SHORT_ID: case F_HIGH_SEQ:
    case F_END: case F_TYPE: case F_SIZE: case F_MODIFIED_S:
    case F_MODIFIED_NS: case F_DELETED: case F_SEQUENCE:
    case F_PERMISSIONS: case F_BLOCK_SIZE: case F_INVALID:
    case F_MODIFIED_BY:
        return PBUF_WT_VARINT;
    case F_FOLDER_ID: case F_NAME: case F_CONTENT_HASH:
    case F_VERSION: case F_BLOCK_HASHES:
        return PBUF_WT_LEN;
    default:
        return -1;
    }
}

static int header_matches(const FolderState *fs, uint64_t magic, uint64_t format,
                          uint64_t short_id, const char *folder)
{
    return magic == IDX_MAGIC && format == IDX_FORMAT &&
           short_id == fs->short_id &&
           strcmp(folder, fs->folder_id) == 0;
}

/* Commit one decoded record. The upsert return is deliberately dropped: it
 * fails only at FOLDSTATE_MAX_FILES, and a partially loaded index just costs
 * the scanner some re-hashing - better than refusing the whole file. */
static void commit_record(FolderState *fs, const SyncMeta *m,
                          const unsigned char *blocks, int n)
{
    foldstate_upsert(fs, m, (const unsigned char (*)[BEP_HASH_LEN])blocks, n);
}

int index_store_decode(FolderState *fs, const void *data, size_t len)
{
    PbufReader    r;
    uint32_t      field;
    int           wt;
    uint64_t      magic = 0, format = 0, short_id = 0, high_seq = 0;
    char          hdr_folder[BEP_FOLDER_ID_MAX];
    int           header_ok = -1;          /* -1 = not checked yet */
    int64_t       count     = -1;          /* -1 = no F_END seen (truncated) */

    /* Current record being assembled. block_ptr points into 'data' (zero copy). */
    SyncMeta             cur;
    const unsigned char *block_ptr = NULL;
    int                  block_n   = 0;
    int                  in_record = 0;

    reset_records(fs);
    hdr_folder[0] = '\0';

    pbuf_reader_init(&r, data, len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        uint64_t             v;
        int                  want = expected_wt(field);

        if (want >= 0 && wt != want)
            goto bad;

        /* Header (fields < F_NAME). */
        if (field < F_NAME) {
            switch (field) {
            case F_MAGIC:     if (pbuf_read_varint(&r, &v)) magic = v;   else goto bad; break;
            case F_FORMAT:    if (pbuf_read_varint(&r, &v)) format = v;  else goto bad; break;
            case F_SHORT_ID:  if (pbuf_read_varint(&r, &v)) short_id = v;else goto bad; break;
            case F_HIGH_SEQ:  if (pbuf_read_varint(&r, &v)) high_seq = v;else goto bad; break;
            case F_END:
                if (!pbuf_read_varint(&r, &v))
                    goto bad;
                count = (int64_t)v;
                break;
            case F_FOLDER_ID:
                if (!pbuf_read_bytes(&r, &p, &n)) goto bad;
                if (n >= sizeof(hdr_folder)) n = sizeof(hdr_folder) - 1;
                memcpy(hdr_folder, p, n); hdr_folder[n] = '\0';
                break;
            default:
                if (!pbuf_skip(&r, wt)) goto bad;
            }
            continue;
        }

        /* First record field: the whole header is in, so validate it once. A
         * mismatch means this isn't our index - bail before committing anything. */
        if (header_ok < 0) {
            header_ok = header_matches(fs, magic, format, short_id, hdr_folder);
            if (!header_ok) goto bad;
        }

        if (field == F_NAME) {                 /* a new record begins */
            if (in_record)
                commit_record(fs, &cur, block_ptr, block_n);
            memset(&cur, 0, sizeof(cur));
            block_ptr = NULL;
            block_n   = 0;
            in_record = 1;
            if (!pbuf_read_bytes(&r, &p, &n)) goto bad;
            if (n >= BEP_PATH_MAX) n = BEP_PATH_MAX - 1;
            memcpy(cur.name, p, n); cur.name[n] = '\0';
            continue;
        }

        switch (field) {
        case F_TYPE:        if (pbuf_read_varint(&r, &v)) cur.type = (unsigned char)v; else goto bad; break;
        case F_SIZE:        if (pbuf_read_varint(&r, &v)) cur.size = (int64_t)v;    else goto bad; break;
        case F_MODIFIED_S:  if (pbuf_read_varint(&r, &v)) cur.modified_s = (int64_t)v; else goto bad; break;
        case F_MODIFIED_NS: if (pbuf_read_varint(&r, &v)) cur.modified_ns = (int32_t)v; else goto bad; break;
        case F_DELETED:     if (pbuf_read_varint(&r, &v)) cur.deleted = (int)v;     else goto bad; break;
        case F_SEQUENCE:    if (pbuf_read_varint(&r, &v)) cur.sequence = (int64_t)v;else goto bad; break;
        case F_PERMISSIONS: if (pbuf_read_varint(&r, &v)) cur.permissions = (uint32_t)v; else goto bad; break;
        case F_BLOCK_SIZE:  if (pbuf_read_varint(&r, &v)) cur.block_size = (int32_t)v;   else goto bad; break;
        case F_INVALID:     if (pbuf_read_varint(&r, &v)) cur.invalid = (int)v;     else goto bad; break;
        case F_MODIFIED_BY: if (pbuf_read_varint(&r, &v)) cur.modified_by = v;      else goto bad; break;
        case F_CONTENT_HASH:
            if (!pbuf_read_bytes(&r, &p, &n)) goto bad;
            if (n == BEP_HASH_LEN) { memcpy(cur.content_hash, p, BEP_HASH_LEN); cur.has_content_hash = 1; }
            break;
        case F_VERSION:
            if (!pbuf_read_bytes(&r, &p, &n)) goto bad;
            decode_vector(p, n, &cur.version);
            break;
        case F_BLOCK_HASHES:
            if (!pbuf_read_bytes(&r, &p, &n)) goto bad;
            block_ptr = p;
            block_n   = (int)(n / BEP_HASH_LEN);
            break;
        default:
            if (!pbuf_skip(&r, wt)) goto bad;
        }
    }

    if (r.error)
        goto bad;
    if (header_ok < 0) {                        /* header-only file: validate now */
        header_ok = header_matches(fs, magic, format, short_id, hdr_folder);
        if (!header_ok) goto bad;
    }
    if (in_record)                              /* commit the final record */
        commit_record(fs, &cur, block_ptr, block_n);

    /* A blob that stops at a field boundary reads as a CLEAN end: pbuf_read_tag
     * returns 0 with no error set, so a truncated file used to decode as a
     * valid one, committing whatever half a record had been assembled with the
     * missing fields left at their memset defaults. Not theoretical - cut in
     * the right place a tombstone reloads as a LIVE record, or a real file
     * reloads with block_size 0, which the announce path then turns into a
     * malformed Index (one-byte blocks) for the peer. F_END is the proof the
     * writer reached the end; the count it carries then confirms we read back
     * everything that was written. */
    if (count < 0 || (int64_t)fs->num_files != count)
        goto bad;

    fs->sequence = (int64_t)high_seq;
    fs->dirty    = 0;
    return 1;

bad:
    reset_records(fs);
    return 0;
}
