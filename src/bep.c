/* bep.c - Block Exchange Protocol framing + handshake for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See bep.h. The pure encode/decode functions are exercised on the build host
 * in tests/test_bep.c; the framed transport functions are driven there through
 * an in-memory BepTransport. Field numbers follow the BEP v1 spec
 * (docs.syncthing.net/specs/bep-v1.html); unknown fields are skipped on decode
 * so we interoperate with newer Syncthing message layouts.
 */

#include <string.h>

#include "bep.h"
#include "pbuf.h"
#include "lz4.h"

/* Scratch buffers use AllocVec on the Amiga and malloc under the host unit test
 * (tests/test_bep.c is compiled with -DBEP_HOST_TEST), mirroring foldstate.c. */
#ifdef BEP_HOST_TEST
#include <stdlib.h>
#define BEP_ALLOC(n)  malloc((size_t)(n))
#define BEP_FREE(p)   free(p)
#else
#include <exec/memory.h>
#include <proto/exec.h>
#define BEP_ALLOC(n)  AllocVec((ULONG)(n), MEMF_ANY)
#define BEP_FREE(p)   FreeVec(p)
#endif

/* Diagnostic logging. On for the Amiga debug build (-DDEBUG), and also
 * switchable into a release build with -DBEP_DIAG so the read path can be
 * traced at -O2 without the confound of changing the optimisation level.
 * The host unit tests build bep.c with neither, so they need no log_printf. */
#if defined(DEBUG) || defined(BEP_DIAG)
#include "log.h"
#define BEPLOG(...) log_printf(LOG_WARN, __VA_ARGS__)
#else
#define BEPLOG(...) ((void)0)
#endif

/* ---- big-endian helpers --------------------------------------------- */

static void put_be16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static uint16_t get_be16(const unsigned char *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Copy a length-delimited protobuf value into a fixed NUL-terminated field. */
static void copy_str(char *dst, int cap, const unsigned char *src, size_t n)
{
    if ((int)n > cap - 1)
        n = (size_t)(cap - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ---- Hello ----------------------------------------------------------- */

int bep_encode_hello(const BepHello *h, void *buf, int cap, int *outlen)
{
    PbufWriter w;

    pbuf_writer_init(&w, buf, (size_t)cap);
    pbuf_write_string(&w, 1, h->device_name);
    pbuf_write_string(&w, 2, h->client_name);
    pbuf_write_string(&w, 3, h->client_version);
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

int bep_decode_hello(const void *buf, int len, BepHello *h)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(h, 0, sizeof(*h));
    pbuf_reader_init(&r, buf, (size_t)len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        if (wt == PBUF_WT_LEN && (field == 1 || field == 2 || field == 3)) {
            const unsigned char *d;
            size_t               n;
            if (!pbuf_read_bytes(&r, &d, &n))
                return 0;
            if (field == 1) copy_str(h->device_name, BEP_NAME_MAX, d, n);
            else if (field == 2) copy_str(h->client_name, BEP_NAME_MAX, d, n);
            else copy_str(h->client_version, BEP_VERSION_MAX, d, n);
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

/* ---- Header ---------------------------------------------------------- */

int bep_encode_header(const BepHeader *hdr, void *buf, int cap, int *outlen)
{
    PbufWriter w;

    pbuf_writer_init(&w, buf, (size_t)cap);
    /* Always emit the type (its default, 0, is a valid type: CLUSTER_CONFIG). */
    pbuf_write_enum(&w, 1, hdr->type);
    if (hdr->compression != BEP_COMPRESS_NONE)
        pbuf_write_enum(&w, 2, hdr->compression);
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

int bep_decode_header(const void *buf, int len, BepHeader *hdr)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    hdr->type        = BEP_CLUSTER_CONFIG;   /* proto3 defaults */
    hdr->compression = BEP_COMPRESS_NONE;
    pbuf_reader_init(&r, buf, (size_t)len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        if (field == 1 && wt == PBUF_WT_VARINT) {
            uint64_t v;
            if (!pbuf_read_varint(&r, &v)) return 0;
            hdr->type = (int)v;
        } else if (field == 2 && wt == PBUF_WT_VARINT) {
            uint64_t v;
            if (!pbuf_read_varint(&r, &v)) return 0;
            hdr->compression = (int)v;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

/* ---- ClusterConfig --------------------------------------------------- */

/* Worst-case wire sizes, sized from the caps in bep.h so they track them (the
 * lesson encode_vector already learned). A full Device is the 32-byte id, a
 * 63-char name and two 10-byte varints, each tagged and length-prefixed: 121
 * bytes. A full Folder is a 63-char id, a 63-char label, the type enum and
 * BEP_MAX_DEVICES devices, each wrapped in field 16's 2-byte tag plus a
 * length: 2120 bytes, which a fixed 2048 did not hold. Overflow is graceful
 * (sticky error, no ClusterConfig) but silent, so it showed up only as a
 * fully-populated folder with long names never connecting. */
#define DEVICE_WIRE_MAX  (BEP_DEVICE_KEY_LEN + BEP_NAME_MAX + 32)
#define FOLDER_WIRE_MAX  (BEP_FOLDER_ID_MAX + BEP_NAME_MAX + 16 + \
                          BEP_MAX_DEVICES * (DEVICE_WIRE_MAX + 4))

static int encode_device(PbufWriter *folder, const BepDevice *d)
{
    unsigned char scratch[DEVICE_WIRE_MAX];
    PbufWriter    dw;

    pbuf_writer_init(&dw, scratch, sizeof(scratch));
    pbuf_write_bytes(&dw, 1, d->id, BEP_DEVICE_KEY_LEN);   /* Device.id */
    if (d->name[0])
        pbuf_write_string(&dw, 2, d->name);               /* Device.name */
    if (d->max_sequence)
        pbuf_write_uint64(&dw, 6, (uint64_t)d->max_sequence);
    if (d->index_id)
        pbuf_write_uint64(&dw, 8, d->index_id);
    return pbuf_write_message(folder, 16, &dw);           /* Folder.devices = 16 */
}

static int encode_folder(PbufWriter *cc, const BepFolder *f)
{
    unsigned char scratch[FOLDER_WIRE_MAX];
    PbufWriter    fw;
    int           i;

    pbuf_writer_init(&fw, scratch, sizeof(scratch));
    pbuf_write_string(&fw, 1, f->id);                     /* Folder.id */
    if (f->label[0])
        pbuf_write_string(&fw, 2, f->label);              /* Folder.label */
    if (f->type != BEP_FOLDER_SEND_RECEIVE)
        pbuf_write_enum(&fw, 3, f->type);                 /* Folder.type */
    for (i = 0; i < f->num_devices; i++)
        encode_device(&fw, &f->devices[i]);
    return pbuf_write_message(cc, 1, &fw);                /* ClusterConfig.folders = 1 */
}

int bep_encode_cluster_config(const BepClusterConfig *cc, void *buf, int cap,
                              int *outlen)
{
    PbufWriter w;
    int        i;

    pbuf_writer_init(&w, buf, (size_t)cap);
    for (i = 0; i < cc->num_folders; i++)
        encode_folder(&w, &cc->folders[i]);
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

static int decode_device(const unsigned char *buf, size_t len, BepDevice *d)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(d, 0, sizeof(*d));
    pbuf_reader_init(&r, buf, len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {            /* Device.id */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (n == BEP_DEVICE_KEY_LEN) memcpy(d->id, p, n);
        } else if (field == 2 && wt == PBUF_WT_LEN) {     /* Device.name */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(d->name, BEP_NAME_MAX, p, n);
        } else if (field == 6 && wt == PBUF_WT_VARINT) {  /* max_sequence */
            uint64_t v;
            if (!pbuf_read_varint(&r, &v)) return 0;
            d->max_sequence = (int64_t)v;
        } else if (field == 8 && wt == PBUF_WT_VARINT) {  /* index_id */
            uint64_t v;
            if (!pbuf_read_varint(&r, &v)) return 0;
            d->index_id = v;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

static int decode_folder(const unsigned char *buf, size_t len, BepFolder *f)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(f, 0, sizeof(*f));
    pbuf_reader_init(&r, buf, len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {            /* Folder.id */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(f->id, BEP_FOLDER_ID_MAX, p, n);
        } else if (field == 2 && wt == PBUF_WT_LEN) {     /* Folder.label */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(f->label, BEP_NAME_MAX, p, n);
        } else if (field == 3 && wt == PBUF_WT_VARINT) {  /* Folder.type */
            uint64_t v;
            if (!pbuf_read_varint(&r, &v)) return 0;
            f->type = (int)v;
        } else if (field == 16 && wt == PBUF_WT_LEN) {    /* Folder.devices */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (f->num_devices < BEP_MAX_DEVICES) {
                if (!decode_device(p, n, &f->devices[f->num_devices]))
                    return 0;
                f->num_devices++;
            }
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

int bep_decode_cluster_config(const void *buf, int len, BepClusterConfig *cc)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(cc, 0, sizeof(*cc));
    pbuf_reader_init(&r, buf, (size_t)len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {            /* ClusterConfig.folders */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (cc->num_folders < BEP_MAX_FOLDERS) {
                if (!decode_folder(p, n, &cc->folders[cc->num_folders]))
                    return 0;
                cc->num_folders++;
            }
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

/* ---- FileInfo / Index / Request / Response -------------------------- */

static int encode_block(PbufWriter *fi, const BepBlockInfo *b)
{
    unsigned char scratch[64];
    PbufWriter    bw;

    pbuf_writer_init(&bw, scratch, sizeof(scratch));
    pbuf_write_uint64(&bw, 1, (uint64_t)b->offset);            /* BlockInfo.offset */
    pbuf_write_uint64(&bw, 2, (uint64_t)(uint32_t)b->size);    /* BlockInfo.size   */
    if (b->has_hash)
        pbuf_write_bytes(&bw, 3, b->hash, BEP_HASH_LEN);       /* BlockInfo.hash   */
    return pbuf_write_message(fi, 16, &bw);                    /* FileInfo.Blocks=16 */
}

static int encode_vector(PbufWriter *fi, const BepVector *v)
{
    /* Room for BEP_MAX_COUNTERS counters, each up to ~24 bytes on the wire
     * (two tagged 64-bit varints + message framing). Sized from the macro so
     * it tracks the counter cap - a fixed 128 bytes overflowed past ~5. */
    unsigned char scratch[BEP_MAX_COUNTERS * 24 + 16];
    PbufWriter    vw;
    int           i;

    pbuf_writer_init(&vw, scratch, sizeof(scratch));
    for (i = 0; i < v->num_counters; i++) {
        unsigned char cscr[32];
        PbufWriter    cw;
        pbuf_writer_init(&cw, cscr, sizeof(cscr));
        pbuf_write_uint64(&cw, 1, v->counters[i].id);          /* Counter.id    */
        pbuf_write_uint64(&cw, 2, v->counters[i].value);       /* Counter.value */
        pbuf_write_message(&vw, 1, &cw);                       /* Vector.counters=1 */
    }
    return pbuf_write_message(fi, 9, &vw);                     /* FileInfo.version=9 */
}

/* Write a FileInfo's fields into 'w'. Blocks come either from fi->blocks (when
 * ext_hashes is NULL) or from an external hash list with geometry derived from
 * fi->block_size and fi->size (when ext_hashes != NULL, ext_n entries). */
static void encode_file_info_body(PbufWriter *w, const BepFileInfo *fi,
                                  const unsigned char (*ext_hashes)[BEP_HASH_LEN],
                                  int ext_n)
{
    int i;

    pbuf_write_string(w, 1, fi->name);                         /* name        */
    if (fi->type)
        pbuf_write_enum(w, 2, fi->type);                       /* type        */
    pbuf_write_uint64(w, 3, (uint64_t)fi->size);               /* size        */
    if (fi->permissions)
        pbuf_write_uint64(w, 4, fi->permissions);              /* permissions */
    pbuf_write_uint64(w, 5, (uint64_t)fi->modified_s);         /* modified_s  */
    if (fi->modified_ns)
        pbuf_write_uint64(w, 11, (uint64_t)(uint32_t)fi->modified_ns);
    if (fi->modified_by)
        pbuf_write_uint64(w, 12, fi->modified_by);             /* modified_by */
    if (fi->deleted)
        pbuf_write_bool(w, 6, 1);                              /* deleted     */
    if (fi->invalid)
        pbuf_write_bool(w, 7, 1);                              /* invalid     */
    encode_vector(w, &fi->version);                            /* version     */
    pbuf_write_uint64(w, 10, (uint64_t)fi->sequence);          /* sequence    */
    if (fi->block_size)
        pbuf_write_uint64(w, 13, (uint64_t)(uint32_t)fi->block_size);

    if (ext_hashes) {
        int64_t bs = fi->block_size ? fi->block_size : 1;
        for (i = 0; i < ext_n; i++) {
            BepBlockInfo b;
            int64_t      off  = (int64_t)i * bs;
            int64_t      left = fi->size - off;
            b.offset   = off;
            b.size     = (int32_t)(left > bs ? bs : left);
            memcpy(b.hash, ext_hashes[i], BEP_HASH_LEN);
            b.has_hash = 1;
            encode_block(w, &b);                               /* Blocks      */
        }
    } else {
        for (i = 0; i < fi->num_blocks; i++)
            encode_block(w, &fi->blocks[i]);                   /* Blocks      */
    }
}

int bep_encode_file_info(const BepFileInfo *fi, void *buf, int cap, int *outlen)
{
    PbufWriter w;

    pbuf_writer_init(&w, buf, (size_t)cap);
    encode_file_info_body(&w, fi, NULL, 0);
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

static int decode_block(const unsigned char *buf, size_t len, BepBlockInfo *b)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(b, 0, sizeof(*b));
    pbuf_reader_init(&r, buf, len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t             v;
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            b->offset = (int64_t)v;
        } else if (field == 2 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            b->size = (int32_t)v;
        } else if (field == 3 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (n == BEP_HASH_LEN) { memcpy(b->hash, p, n); b->has_hash = 1; }
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

static int decode_counter(const unsigned char *buf, size_t len, BepCounter *c)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    c->id = c->value = 0;
    pbuf_reader_init(&r, buf, len);

    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t v;
        if (field == 1 && wt == PBUF_WT_VARINT) {              /* Counter.id */
            if (!pbuf_read_varint(&r, &v)) return 0;
            c->id = v;
        } else if (field == 2 && wt == PBUF_WT_VARINT) {       /* Counter.value */
            if (!pbuf_read_varint(&r, &v)) return 0;
            c->value = v;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

static int decode_vector(const unsigned char *buf, size_t len, BepVector *v)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(v, 0, sizeof(*v));
    pbuf_reader_init(&r, buf, len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {                 /* Vector.counters */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (v->num_counters < BEP_MAX_COUNTERS) {
                if (!decode_counter(p, n, &v->counters[v->num_counters]))
                    return 0;
                v->num_counters++;
            }
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

int bep_decode_file_info_cb(const void *buf, int len, BepFileInfo *fi,
                            BepBlockFn cb, void *ctx)
{
    PbufReader r;
    uint32_t   field;
    int        wt;
    int        count = 0;

    memset(fi, 0, sizeof(*fi));
    pbuf_reader_init(&r, buf, (size_t)len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t             v;
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(fi->name, BEP_PATH_MAX, p, n);
        } else if (field == 2 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->type = (int)v;
        } else if (field == 3 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->size = (int64_t)v;
        } else if (field == 4 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->permissions = (uint32_t)v;
        } else if (field == 5 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->modified_s = (int64_t)v;
        } else if (field == 11 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->modified_ns = (int32_t)v;
        } else if (field == 12 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->modified_by = v;
        } else if (field == 6 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->deleted = (int)v;
        } else if (field == 7 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->invalid = (int)v;
        } else if (field == 9 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (!decode_vector(p, n, &fi->version)) return 0;
        } else if (field == 10 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->sequence = (int64_t)v;
        } else if (field == 13 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            fi->block_size = (int32_t)v;
        } else if (field == 16 && wt == PBUF_WT_LEN) {
            BepBlockInfo blk;
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (!decode_block(p, n, &blk)) return 0;
            if (cb && !cb(ctx, count, &blk)) return 0;
            count++;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    fi->num_blocks = count;
    return !r.error;
}

/* Block callback that materializes into fi->blocks, capped at BEP_MAX_BLOCKS. */
static int array_block_cb(void *ctx, int index, const BepBlockInfo *blk)
{
    BepFileInfo *fi = (BepFileInfo *)ctx;
    if (index < BEP_MAX_BLOCKS)
        fi->blocks[index] = *blk;
    return 1;
}

int bep_decode_file_info(const void *buf, int len, BepFileInfo *fi)
{
    int rc = bep_decode_file_info_cb(buf, len, fi, array_block_cb, fi);
    if (fi->num_blocks > BEP_MAX_BLOCKS)
        fi->num_blocks = BEP_MAX_BLOCKS;       /* blocks[] holds only the first */
    return rc;
}

int bep_encode_request(const BepRequest *rq, void *buf, int cap, int *outlen)
{
    PbufWriter w;

    pbuf_writer_init(&w, buf, (size_t)cap);
    pbuf_write_uint64(&w, 1, (uint64_t)(uint32_t)rq->id);      /* id     */
    pbuf_write_string(&w, 2, rq->folder);                     /* folder */
    pbuf_write_string(&w, 3, rq->name);                       /* name   */
    pbuf_write_uint64(&w, 4, (uint64_t)rq->offset);           /* offset */
    pbuf_write_uint64(&w, 5, (uint64_t)(uint32_t)rq->size);   /* size   */
    if (rq->has_hash)
        pbuf_write_bytes(&w, 6, rq->hash, BEP_HASH_LEN);      /* hash   */
    if (rq->from_temporary)
        pbuf_write_bool(&w, 7, 1);                            /* from_temporary */
    if (rq->block_no)
        pbuf_write_uint64(&w, 9, (uint64_t)(uint32_t)rq->block_no);
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

int bep_decode_request(const void *buf, int len, BepRequest *rq)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(rq, 0, sizeof(*rq));
    pbuf_reader_init(&r, buf, (size_t)len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t             v;
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rq->id = (int32_t)v;
        } else if (field == 2 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(rq->folder, BEP_FOLDER_ID_MAX, p, n);
        } else if (field == 3 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(rq->name, BEP_PATH_MAX, p, n);
        } else if (field == 4 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rq->offset = (int64_t)v;
        } else if (field == 5 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rq->size = (int32_t)v;
        } else if (field == 6 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            if (n == BEP_HASH_LEN) { memcpy(rq->hash, p, n); rq->has_hash = 1; }
        } else if (field == 7 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rq->from_temporary = (int)v;
        } else if (field == 9 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rq->block_no = (int32_t)v;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

int bep_encode_response(const BepResponse *rs, void *buf, int cap, int *outlen)
{
    PbufWriter w;

    pbuf_writer_init(&w, buf, (size_t)cap);
    pbuf_write_uint64(&w, 1, (uint64_t)(uint32_t)rs->id);      /* id   */
    if (rs->data_len > 0)
        pbuf_write_bytes(&w, 2, rs->data, (size_t)rs->data_len);  /* data */
    if (rs->code != BEP_ERR_NONE)
        pbuf_write_enum(&w, 3, rs->code);                     /* code */
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

int bep_decode_response(const void *buf, int len, BepResponse *rs)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    memset(rs, 0, sizeof(*rs));
    pbuf_reader_init(&r, buf, (size_t)len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        uint64_t             v;
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rs->id = (int32_t)v;
        } else if (field == 2 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            rs->data = p; rs->data_len = (int)n;              /* into source buf */
        } else if (field == 3 && wt == PBUF_WT_VARINT) {
            if (!pbuf_read_varint(&r, &v)) return 0;
            rs->code = (int)v;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

int bep_index_summary(const void *buf, int len,
                      char folder[BEP_FOLDER_ID_MAX], int *num_files)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    folder[0]  = '\0';
    *num_files = 0;
    pbuf_reader_init(&r, buf, (size_t)len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {                /* Index.folder */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;
            copy_str(folder, BEP_FOLDER_ID_MAX, p, n);
        } else if (field == 2 && wt == PBUF_WT_LEN) {         /* Index.files  */
            if (!pbuf_read_bytes(&r, &p, &n)) return 0;       /* consume + count */
            (*num_files)++;
        } else if (!pbuf_skip(&r, wt)) {
            return 0;
        }
    }
    return !r.error;
}

int bep_encode_index(const char *folder, const BepFileInfo *files, int n,
                     void *buf, int cap, int *outlen)
{
    PbufWriter w;
    int        i;

    pbuf_writer_init(&w, buf, (size_t)cap);
    pbuf_write_string(&w, 1, folder);                     /* Index.folder = 1 */
    for (i = 0; i < n; i++) {
        unsigned char scratch[4096];                      /* one FileInfo     */
        int           flen;
        if (!bep_encode_file_info(&files[i], scratch, sizeof(scratch), &flen))
            return 0;
        pbuf_write_bytes(&w, 2, scratch, (size_t)flen);   /* Index.files = 2  */
    }
    if (w.error)
        return 0;
    *outlen = (int)w.len;
    return 1;
}

int bep_encode_index_file(const char *folder, const BepFileInfo *meta,
                          const unsigned char (*hashes)[BEP_HASH_LEN],
                          int num_blocks, void *buf, int cap, int *outlen)
{
    unsigned char *base = (unsigned char *)buf;
    PbufWriter     w, fw, pw;
    unsigned char  prefix[8];
    size_t         used, plen;

    /* A big file's FileInfo (tens of KiB of block hashes) won't fit a small
     * stack scratch, so we encode its body directly into the tail of the
     * caller's output buffer, then prepend the Index.files (field 2) tag+length
     * in place, shifting the body right to make room. */
    pbuf_writer_init(&w, buf, (size_t)cap);
    pbuf_write_string(&w, 1, folder);                     /* Index.folder = 1 */
    if (w.error)
        return 0;
    used = w.len;

    pbuf_writer_init(&fw, base + used, (size_t)cap - used);
    encode_file_info_body(&fw, meta, hashes, num_blocks);
    if (fw.error)
        return 0;

    pbuf_writer_init(&pw, prefix, sizeof(prefix));
    pbuf_write_tag(&pw, 2, PBUF_WT_LEN);                  /* Index.files = 2  */
    pbuf_write_varint(&pw, (uint64_t)fw.len);
    if (pw.error)
        return 0;
    plen = pw.len;

    if (used + plen + fw.len > (size_t)cap)
        return 0;
    memmove(base + used + plen, base + used, fw.len);
    memcpy(base + used, prefix, plen);

    *outlen = (int)(used + plen + fw.len);
    return 1;
}

/* ---- batched Index/IndexUpdate (see bep.h) --------------------------- */

void bep_index_batch_begin(BepConn *c, BepIndexBatch *b, const char *folder)
{
    PbufWriter w;

    b->buf   = c->out;
    b->cap   = c->out_cap;
    b->len   = 0;
    b->num   = 0;
    b->error = 0;

    pbuf_writer_init(&w, b->buf, (size_t)b->cap);
    pbuf_write_string(&w, 1, folder);                     /* Index.folder = 1 */
    if (w.error) {
        b->error = 1;
        return;
    }
    b->len = (int)w.len;
}

int bep_index_batch_add(BepIndexBatch *b, const BepFileInfo *meta,
                        const unsigned char (*hashes)[BEP_HASH_LEN],
                        int num_blocks)
{
    PbufWriter    fw, pw;
    unsigned char prefix[8];
    size_t        plen;

    if (b->error)
        return 0;

    /* Encode the FileInfo body into the free tail, then shift it right to make
     * room for its own tag+length - the same trick bep_encode_index_file uses,
     * and for the same reason: a FileInfo carrying tens of KiB of block hashes
     * has no business on the stack. Nothing below advances b->len until the
     * whole entry is known to fit, so a refusal leaves the batch untouched and
     * the bytes scribbled past b->len are simply overwritten next time. */
    pbuf_writer_init(&fw, b->buf + b->len, (size_t)(b->cap - b->len));
    encode_file_info_body(&fw, meta, hashes, num_blocks);
    if (fw.error)
        return 0;                        /* did not fit: batch unchanged */

    pbuf_writer_init(&pw, prefix, sizeof(prefix));
    pbuf_write_tag(&pw, 2, PBUF_WT_LEN);                  /* Index.files = 2  */
    pbuf_write_varint(&pw, (uint64_t)fw.len);
    if (pw.error)
        return 0;
    plen = pw.len;

    if ((size_t)b->len + plen + fw.len > (size_t)b->cap)
        return 0;                        /* prefix would not fit either */

    memmove(b->buf + b->len + plen, b->buf + b->len, fw.len);
    memcpy(b->buf + b->len, prefix, plen);

    b->len += (int)(plen + fw.len);
    b->num++;
    return 1;
}

int bep_send_index_batch(BepConn *c, int type, BepIndexBatch *b)
{
    if (b->error)
        return 0;
    if (b->num == 0)
        return 1;                        /* nothing accumulated */
    return bep_send_message(c, type, b->buf, b->len);
}

void bep_index_iter_begin(BepIndexIter *it, const void *buf, int len,
                          char folder[BEP_FOLDER_ID_MAX])
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    folder[0] = '\0';
    pbuf_reader_init(&r, buf, (size_t)len);
    while (pbuf_read_tag(&r, &field, &wt)) {              /* find Index.folder */
        const unsigned char *p;
        size_t               n;
        if (field == 1 && wt == PBUF_WT_LEN) {
            if (!pbuf_read_bytes(&r, &p, &n)) break;
            copy_str(folder, BEP_FOLDER_ID_MAX, p, n);
            /* First wins, not proto3's last-wins: stopping here saves a
             * second tag-walk of every FileInfo in a bulk Index, and a
             * duplicated folder id is malformed input Syncthing never sends. */
            break;
        } else if (!pbuf_skip(&r, wt)) {
            break;
        }
    }

    it->p     = (const unsigned char *)buf;
    it->end   = (const unsigned char *)buf + len;
    it->error = 0;
}

int bep_index_iter_next_cb(BepIndexIter *it, BepFileInfo *fi,
                           BepBlockFn cb, void *ctx)
{
    PbufReader r;
    uint32_t   field;
    int        wt;

    if (it->error || it->p >= it->end)
        return 0;

    pbuf_reader_init(&r, it->p, (size_t)(it->end - it->p));
    while (pbuf_read_tag(&r, &field, &wt)) {
        const unsigned char *p;
        size_t               n;
        if (field == 2 && wt == PBUF_WT_LEN) {           /* Index.files entry */
            if (!pbuf_read_bytes(&r, &p, &n)) { it->error = 1; return 0; }
            it->p = r.p;                                 /* resume after it   */
            if (!bep_decode_file_info_cb(p, (int)n, fi, cb, ctx)) {
                it->error = 1; return 0;
            }
            return 1;
        } else if (!pbuf_skip(&r, wt)) {                 /* folder / unknown  */
            it->error = 1;
            return 0;
        } else {
            it->p = r.p;
        }
    }
    it->p = it->end;
    return 0;
}

int bep_index_iter_next(BepIndexIter *it, BepFileInfo *fi)
{
    int rc = bep_index_iter_next_cb(it, fi, array_block_cb, fi);
    if (rc && fi->num_blocks > BEP_MAX_BLOCKS)
        fi->num_blocks = BEP_MAX_BLOCKS;
    return rc;
}

/* ---- scratch-buffer lifecycle --------------------------------------- */

int bep_conn_init(BepConn *c)
{
    c->wire_cap  = BEP_WIRE_INIT;
    c->plain_cap = BEP_PLAIN_INIT;
    c->out_cap   = BEP_OUT_INIT;
    c->wire  = BEP_ALLOC(c->wire_cap);
    c->plain = BEP_ALLOC(c->plain_cap);
    c->out   = BEP_ALLOC(c->out_cap);
    if (!c->wire || !c->plain || !c->out) {
        bep_conn_free(c);
        return 0;
    }
    return 1;
}

void bep_conn_free(BepConn *c)
{
    BEP_FREE(c->wire);
    BEP_FREE(c->plain);
    BEP_FREE(c->out);
    c->wire = c->plain = c->out = NULL;
    c->wire_cap = c->plain_cap = c->out_cap = 0;
}

/* Ensure each scratch buffer holds at least 'need' bytes, growing in 128 KiB
 * steps up to the BEP_MSG_MAX ceiling. Old contents are preserved, so this is
 * safe to call after part of a message is already buffered (e.g. raising 'plain'
 * for a decompressed body once the compressed body sits in 'wire'). Returns 1,
 * 0 if 'need' exceeds BEP_MSG_MAX or an allocation fails (the connection's
 * buffers are left intact on failure). */
/* Grow one buffer to hold at least 'need' bytes, preserving what is in it -
 * a decompression can raise 'plain' while the compressed body still sits in
 * 'wire', and an announce can raise 'out' between records. Steps of 128 KiB so
 * a connection that sees one large message does not then realloc per message.
 * Returns 1, or 0 if 'need' exceeds BEP_MSG_MAX or the allocation fails, in
 * which case the buffer is left exactly as it was. */
static int grow_buf(unsigned char **buf, int32_t *cap, int need, const char *what)
{
    unsigned char *nb;
    int32_t        newcap;

    if (need <= *cap)
        return 1;
    if (need > BEP_MSG_MAX)
        return 0;

    newcap = *cap;
    while (newcap < need)
        newcap += (128 * 1024);
    if (newcap > BEP_MSG_MAX)
        newcap = BEP_MSG_MAX;

    nb = BEP_ALLOC(newcap);
    if (!nb) {
        BEPLOG("grow_buf(%s): alloc failed (need=%d newcap=%d)",
               what, need, (int)newcap);
        return 0;
    }
    if (*buf && *cap > 0)
        memcpy(nb, *buf, (size_t)*cap);
    if (*buf)
        BEP_FREE(*buf);
    *buf = nb;
    *cap = newcap;
    return 1;
}

static int ensure_wire(BepConn *c, int need)
{
    return grow_buf(&c->wire, &c->wire_cap, need, "wire");
}

static int ensure_plain(BepConn *c, int need)
{
    return grow_buf(&c->plain, &c->plain_cap, need, "plain");
}

static int ensure_out(BepConn *c, int need)
{
    return grow_buf(&c->out, &c->out_cap, need, "out");
}

/* Raise 'out' by one step, for the encode-and-retry senders below: an encoder
 * reports only "did not fit", not how much it wanted. Returns 0 once 'out' is
 * already at BEP_MSG_MAX, which ends the retry loop. */
static int grow_out_step(BepConn *c)
{
    if (c->out_cap >= BEP_MSG_MAX)
        return 0;
    return ensure_out(c, c->out_cap + 1);
}


/* ---- framed transport ----------------------------------------------- */

/* Read exactly 'len' bytes. Returns 1 if all arrived, 0 on clean EOF before
 * any/partway (treated as a closed connection), -1 on error. */
static int read_full(BepConn *c, void *buf, int len)
{
    unsigned char *p   = (unsigned char *)buf;
    int            got = 0;

    while (got < len) {
        int n = c->t.read(c->t.ctx, p + got, len - got);
        if (n > 0)      got += n;
        else if (n == 0) return 0;     /* peer closed */
        else            return -1;
    }
    return 1;
}

static int write_full(BepConn *c, const void *buf, int len)
{
    const unsigned char *p    = (const unsigned char *)buf;
    int                  sent = 0;

    while (sent < len) {
        int n = c->t.write(c->t.ctx, p + sent, len - sent);
        if (n > 0) sent += n;
        else       return 0;
    }
    return 1;
}

int bep_send_hello(BepConn *c, const BepHello *local)
{
    unsigned char hdr[6];
    unsigned char body[256];
    int           bodylen;

    if (!bep_encode_hello(local, body, sizeof(body), &bodylen))
        return 0;

    put_be32(hdr, BEP_MAGIC);
    put_be16(hdr + 4, (uint16_t)bodylen);
    if (bodylen <= BEP_COALESCE_MAX) {        /* always, for a Hello */
        memcpy(c->frame, hdr, sizeof(hdr));
        memcpy(c->frame + sizeof(hdr), body, (size_t)bodylen);
        return write_full(c, c->frame, (int)sizeof(hdr) + bodylen);
    }
    return write_full(c, hdr, sizeof(hdr)) && write_full(c, body, bodylen);
}

int bep_read_hello(BepConn *c, BepHello *remote)
{
    unsigned char hdr[6];
    int           len;

    if (read_full(c, hdr, sizeof(hdr)) != 1)
        return 0;
    if (get_be32(hdr) != BEP_MAGIC)
        return 0;
    len = get_be16(hdr + 4);
    if (len < 0 || len > BEP_MSG_MAX || !ensure_wire(c, len))
        return 0;
    if (read_full(c, c->wire, len) != 1)
        return 0;
    return bep_decode_hello(c->wire, len, remote);
}

/* Don't bother compressing bodies below this: the LZ4 + 4-byte-size overhead and
 * the CPU cost aren't worth it for small control messages. */
#define BEP_COMPRESS_MIN  1024

int bep_send_message(BepConn *c, int type, const void *msg, int msglen)
{
    unsigned char hbuf[16];
    BepHeader     hdr;
    int           hlen, flen;
    const void   *body       = msg;
    int           bodylen    = msglen;
    int           compressed = 0;

    /* Policy lives in bep.h; the wire detail is here. Syncthing's framing is
     * [uint32 BE uncompressed size][lz4 block], and compression is per-message
     * (the peer decompresses on the Header's flag, as bep_read_message does),
     * so no Hello negotiation is needed. c->plain is the scratch - idle on the
     * send path, since a worker never sends and reads at the same time. */
    if (msglen >= BEP_COMPRESS_MIN && type != BEP_RESPONSE &&
        ensure_plain(c, msglen + 4)) {
        /* Worst case LZ4 does not shrink at all, so the scratch must hold the
         * whole body; if it cannot be grown we simply send uncompressed. */
        int clen = LZ4_compress_default((const char *)msg, (char *)c->plain + 4,
                                        msglen, c->plain_cap - 4);
        if (clen > 0 && clen + 4 < msglen) {
            put_be32(c->plain, (uint32_t)msglen);    /* uncompressed-size prefix */
            body       = c->plain;
            bodylen    = clen + 4;
            compressed = 1;
        }
    }

    hdr.type        = type;
    hdr.compression = compressed ? BEP_COMPRESS_LZ4 : BEP_COMPRESS_NONE;
    if (!bep_encode_header(&hdr, hbuf, sizeof(hbuf), &hlen))
        return 0;

    /* One frame, one write where we can - see BEP_COALESCE_MAX in bep.h. */
    put_be16(c->frame, (uint16_t)hlen);
    memcpy(c->frame + 2, hbuf, (size_t)hlen);
    put_be32(c->frame + 2 + hlen, (uint32_t)bodylen);
    flen = 2 + hlen + 4;

    if (bodylen == 0)
        return write_full(c, c->frame, flen);
    if (bodylen <= BEP_COALESCE_MAX) {
        memcpy(c->frame + flen, body, (size_t)bodylen);
        return write_full(c, c->frame, flen + bodylen);
    }
    return write_full(c, c->frame, flen) && write_full(c, body, bodylen);
}

int bep_send_cluster_config(BepConn *c, const BepClusterConfig *cc)
{
    int len;
    /* Encode-and-grow: an encoder reports only that it did not fit, so retry a
     * step larger until it does or 'out' is at BEP_MSG_MAX. Before the buffers
     * were sized separately this could not arise - 'out' started at a full
     * block - and encoders simply failed the connection instead. */
    while (!bep_encode_cluster_config(cc, c->out, c->out_cap, &len))
        if (!grow_out_step(c))
            return 0;
    return bep_send_message(c, BEP_CLUSTER_CONFIG, c->out, len);
}

int bep_send_ping(BepConn *c)
{
    return bep_send_message(c, BEP_PING, NULL, 0);   /* Ping has an empty body */
}

int bep_send_request(BepConn *c, const BepRequest *rq)
{
    int len;
    while (!bep_encode_request(rq, c->out, c->out_cap, &len))
        if (!grow_out_step(c))
            return 0;
    return bep_send_message(c, BEP_REQUEST, c->out, len);
}

int bep_send_response(BepConn *c, const BepResponse *rs)
{
    int len;
    /* A Response carries one block, which may be larger than the buffers' initial
     * size (up to a 1 MiB block for a near-2 GiB file). Grow 'out' to fit the
     * block plus protobuf framing before encoding. */
    if (!ensure_out(c, rs->data_len + 64))
        return 0;
    if (!bep_encode_response(rs, c->out, c->out_cap, &len))
        return 0;
    return bep_send_message(c, BEP_RESPONSE, c->out, len);
}

int bep_send_index(BepConn *c, int type, const char *folder,
                   const BepFileInfo *files, int n)
{
    int len;
    while (!bep_encode_index(folder, files, n, c->out, c->out_cap, &len))
        if (!grow_out_step(c))
            return 0;
    return bep_send_message(c, type, c->out, len);
}

int bep_send_index_file(BepConn *c, int type, const char *folder,
                        const BepFileInfo *meta,
                        const unsigned char (*hashes)[BEP_HASH_LEN],
                        int num_blocks)
{
    int len;
    /* The one that made this necessary: a FileInfo carrying up to
     * FOLDER_MAX_BLOCKS hashes is tens of KB on its own, well past what 'out'
     * starts at. */
    while (!bep_encode_index_file(folder, meta, hashes, num_blocks,
                                  c->out, c->out_cap, &len))
        if (!grow_out_step(c))
            return 0;
    return bep_send_message(c, type, c->out, len);
}

int bep_send_close(BepConn *c, const char *reason)
{
    unsigned char body[256];
    PbufWriter    w;

    pbuf_writer_init(&w, body, sizeof(body));
    if (reason && reason[0])
        pbuf_write_string(&w, 1, reason);            /* Close.reason = 1 */
    if (w.error)
        return 0;
    return bep_send_message(c, BEP_CLOSE, body, (int)w.len);
}

/* The mirror image of bep_send_message - and deliberately NOT coalesced the way
 * that one is, which looks like an oversight until you price the two sides.
 *
 * A write COSTS what it is split into: SSL_write emits a TLS record per call,
 * each with its own header, AEAD pass, auth tag and socket send, so four small
 * writes were four of everything (measured: coalescing them cut an announce
 * from 199 s to 74 s). A read costs nothing of the kind. Record boundaries are
 * chosen by the SENDER; SSL_read decrypts whole records as they arrive and
 * hands back bytes from its own plaintext buffer, so the four reads below are
 * four memcpys, not four decryptions, and no extra byte crosses the network.
 *
 * Coalescing them would also be the harder change: the body length is not known
 * until the header has been parsed, so it needs a read-ahead buffer that keeps
 * whatever it over-read for the next message. Real risk, no measurable prize.
 * Left alone on purpose. */
int bep_read_message(BepConn *c, BepHeader *hdr,
                     const unsigned char **body, int *bodylen)
{
    unsigned char lenbuf[4];
    int           hlen, mlen, rc;

    /* headerLen + Header */
    rc = read_full(c, lenbuf, 2);
    if (rc != 1) {
        if (rc < 0)
            BEPLOG("bep_read_message: read error on header length (transport)");
        return rc;                       /* 0 = clean close, -1 = error */
    }
    hlen = get_be16(lenbuf);
    /* hlen==0 is valid: a proto3 Header whose fields are all defaults
     * (type=CLUSTER_CONFIG, compression=NONE) serializes to zero bytes, which
     * is exactly what real Syncthing sends for its first ClusterConfig. We emit
     * the type explicitly ourselves, but must accept the omitted form here. */
    if (hlen < 0 || hlen > BEP_MSG_MAX || !ensure_wire(c, hlen)) {
        BEPLOG("bep_read_message: bad hlen=%d (max %d)", hlen, BEP_MSG_MAX);
        return -1;
    }
    if (hlen > 0 && read_full(c, c->wire, hlen) != 1) {
        BEPLOG("bep_read_message: short read of header (%d bytes)", hlen);
        return -1;
    }
    if (!bep_decode_header(c->wire, hlen, hdr)) {
        BEPLOG("bep_read_message: header decode failed (hlen=%d)", hlen);
        return -1;
    }

    /* messageLen + message body */
    if (read_full(c, lenbuf, 4) != 1) {
        BEPLOG("bep_read_message: short read of message length");
        return -1;
    }
    mlen = (int)get_be32(lenbuf);
    if (mlen < 0 || mlen > BEP_MSG_MAX || !ensure_wire(c, mlen)) {
        BEPLOG("bep_read_message: bad mlen=%d (max %d, type=%d compr=%d)",
               mlen, BEP_MSG_MAX, hdr->type, hdr->compression);
        return -1;
    }
    if (mlen > 0 && read_full(c, c->wire, mlen) != 1) {
        BEPLOG("bep_read_message: short read of body (mlen=%d)", mlen);
        return -1;
    }

    if (hdr->compression == BEP_COMPRESS_LZ4) {
        /* Syncthing frames LZ4 as [uint32 BE uncompressed size][lz4 block]. */
        int usize, dec;
        if (mlen < 4) {
            BEPLOG("bep_read_message: LZ4 mlen=%d < 4", mlen);
            return -1;
        }
        usize = (int)get_be32(c->wire);
        /* Grow 'plain' to hold the decompressed body; the compressed body sits in
         * 'wire' and bep_ensure_cap preserves it across the grow. */
        if (usize < 0 || usize > BEP_MSG_MAX || !ensure_plain(c, usize)) {
            BEPLOG("bep_read_message: LZ4 bad usize=%d (max %d)",
                   usize, BEP_MSG_MAX);
            return -1;
        }
        dec = LZ4_decompress_safe((const char *)c->wire + 4,
                                  (char *)c->plain, mlen - 4, usize);
        if (dec != usize) {
            BEPLOG("bep_read_message: LZ4 decode dec=%d != usize=%d (mlen=%d)",
                   dec, usize, mlen);
            return -1;
        }
        *body    = c->plain;
        *bodylen = usize;
    } else {
        *body    = c->wire;
        *bodylen = mlen;
    }
    return 1;
}

int bep_handshake(BepConn *c, const BepHello *local, BepHello *remote,
                  const BepClusterConfig *cc)
{
    /* Both sides send Hello immediately, then read the peer's. */
    if (!bep_send_hello(c, local))
        return 0;
    if (!bep_read_hello(c, remote))
        return 0;
    /* Our ClusterConfig is the first post-Hello message we send; the peer's is
     * read by the caller's message loop. */
    if (!bep_send_cluster_config(c, cc))
        return 0;
    return 1;
}
