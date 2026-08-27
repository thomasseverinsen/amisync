/* pbuf.c - minimal protobuf wire codec for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See pbuf.h for the rationale. The implementation is deliberately small and
 * branch-simple; every read validates against the buffer end and every write
 * validates against the remaining capacity, setting the sticky error flag
 * rather than ever reading or writing out of bounds.
 */

#include <string.h>

#include "pbuf.h"

/* ---- reader ---------------------------------------------------------- */

void pbuf_reader_init(PbufReader *r, const void *data, size_t len)
{
    r->p     = (const unsigned char *)data;
    r->end   = r->p + len;
    r->error = 0;
}

int pbuf_eof(const PbufReader *r)
{
    return !r->error && r->p >= r->end;
}

int pbuf_read_varint(PbufReader *r, uint64_t *out)
{
    uint64_t value = 0;
    int      shift = 0;

    if (r->error)
        return 0;

    /* 64 bits / 7 bits per byte -> at most 10 bytes; shift runs 0..63. */
    while (shift < 64) {
        unsigned char b;
        if (r->p >= r->end) {
            r->error = 1;
            return 0;
        }
        b = *r->p++;
        value |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *out = value;
            return 1;
        }
        shift += 7;
    }
    r->error = 1;   /* overlong varint */
    return 0;
}

int pbuf_read_tag(PbufReader *r, uint32_t *field, int *wiretype)
{
    uint64_t tag;

    if (r->error || r->p >= r->end)
        return 0;                 /* clean EOF (error stays clear) */

    if (!pbuf_read_varint(r, &tag))
        return 0;

    *field    = (uint32_t)(tag >> 3);
    *wiretype = (int)(tag & 0x07);
    return 1;
}

int pbuf_read_bytes(PbufReader *r, const unsigned char **data, size_t *len)
{
    uint64_t n;

    if (!pbuf_read_varint(r, &n))
        return 0;
    if (n > (uint64_t)(r->end - r->p)) {
        r->error = 1;
        return 0;
    }
    *data = r->p;
    *len  = (size_t)n;
    r->p += n;
    return 1;
}

static int pbuf_read_fixed32(PbufReader *r, uint32_t *out)
{
    if (r->error)
        return 0;
    if (r->end - r->p < 4) {
        r->error = 1;
        return 0;
    }
    /* protobuf fixed fields are little-endian on the wire */
    *out = (uint32_t)r->p[0]        | (uint32_t)r->p[1] << 8 |
           (uint32_t)r->p[2] << 16  | (uint32_t)r->p[3] << 24;
    r->p += 4;
    return 1;
}

static int pbuf_read_fixed64(PbufReader *r, uint64_t *out)
{
    if (r->error)
        return 0;
    if (r->end - r->p < 8) {
        r->error = 1;
        return 0;
    }
    *out = (uint64_t)r->p[0]       | (uint64_t)r->p[1] << 8  |
           (uint64_t)r->p[2] << 16 | (uint64_t)r->p[3] << 24 |
           (uint64_t)r->p[4] << 32 | (uint64_t)r->p[5] << 40 |
           (uint64_t)r->p[6] << 48 | (uint64_t)r->p[7] << 56;
    r->p += 8;
    return 1;
}

int pbuf_skip(PbufReader *r, int wiretype)
{
    uint64_t dummy;
    const unsigned char *d;
    size_t   n;
    uint32_t d32;

    switch (wiretype) {
    case PBUF_WT_VARINT: return pbuf_read_varint(r, &dummy);
    case PBUF_WT_I64:    return pbuf_read_fixed64(r, &dummy);
    case PBUF_WT_LEN:    return pbuf_read_bytes(r, &d, &n);
    case PBUF_WT_I32:    return pbuf_read_fixed32(r, &d32);
    default:
        r->error = 1;   /* unknown wire type: cannot continue safely */
        return 0;
    }
}

/* ---- writer ---------------------------------------------------------- */

void pbuf_writer_init(PbufWriter *w, void *buf, size_t cap)
{
    w->buf   = (unsigned char *)buf;
    w->cap   = cap;
    w->len   = 0;
    w->error = 0;
}

static int put_byte(PbufWriter *w, unsigned char b)
{
    if (w->error)
        return 0;
    if (w->len >= w->cap) {
        w->error = 1;
        return 0;
    }
    w->buf[w->len++] = b;
    return 1;
}

static int put_raw(PbufWriter *w, const void *data, size_t len)
{
    if (w->error)
        return 0;
    if (len > w->cap - w->len) {
        w->error = 1;
        return 0;
    }
    if (len)                            /* memcpy(dst, NULL, 0) is still UB, and
                                         * an empty bytes field is a real case */
        memcpy(w->buf + w->len, data, len);
    w->len += len;
    return 1;
}

int pbuf_write_varint(PbufWriter *w, uint64_t v)
{
    do {
        unsigned char b = (unsigned char)(v & 0x7f);
        v >>= 7;
        if (v)
            b |= 0x80;
        if (!put_byte(w, b))
            return 0;
    } while (v);
    return 1;
}

int pbuf_write_tag(PbufWriter *w, uint32_t field, int wiretype)
{
    return pbuf_write_varint(w, ((uint64_t)field << 3) | (uint32_t)wiretype);
}

int pbuf_write_uint64(PbufWriter *w, uint32_t field, uint64_t v)
{
    return pbuf_write_tag(w, field, PBUF_WT_VARINT) &&
           pbuf_write_varint(w, v);
}

int pbuf_write_int64(PbufWriter *w, uint32_t field, int64_t v)
{
    /* protobuf encodes negative int64 as a full-width (sign-extended) varint */
    return pbuf_write_tag(w, field, PBUF_WT_VARINT) &&
           pbuf_write_varint(w, (uint64_t)v);
}

int pbuf_write_bool(PbufWriter *w, uint32_t field, int v)
{
    return pbuf_write_uint64(w, field, v ? 1 : 0);
}

/* BEP's enums are all non-negative, so this truncates to 32 bits rather than
 * sign-extending the way pbuf_write_int64 does - a negative enum would encode
 * as 5 bytes here where proto3 wants 10. */
int pbuf_write_enum(PbufWriter *w, uint32_t field, int v)
{
    return pbuf_write_uint64(w, field, (uint64_t)(uint32_t)v);
}

int pbuf_write_bytes(PbufWriter *w, uint32_t field, const void *data, size_t len)
{
    return pbuf_write_tag(w, field, PBUF_WT_LEN) &&
           pbuf_write_varint(w, (uint64_t)len) &&
           put_raw(w, data, len);
}

int pbuf_write_string(PbufWriter *w, uint32_t field, const char *s)
{
    return pbuf_write_bytes(w, field, s, strlen(s));
}

int pbuf_write_message(PbufWriter *w, uint32_t field, const PbufWriter *msg)
{
    if (msg->error) {           /* propagate a failed sub-encode */
        w->error = 1;
        return 0;
    }
    return pbuf_write_bytes(w, field, msg->buf, msg->len);
}
