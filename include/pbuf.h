/* pbuf.h - minimal protobuf wire codec for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * BEP messages are protobuf. Rather than pull in a generator and a host-side
 * build step, amisync hand-rolls the handful of wire primitives it needs
 * (varints and length-delimited fields; fixed32/64 only far enough to skip
 * them) and writes the specific BEP messages
 * by hand in the bep module. The surface is small and stable, and fixed-buffer
 * encode/decode (no malloc churn) suits a 68k daemon.
 *
 * Everything works over caller-provided fixed buffers. Readers never allocate;
 * length-delimited fields are returned as pointers into the source buffer.
 * Both reader and writer carry a sticky 'error' flag: once set (truncation on
 * read, overflow on write) every further call is a no-op, so callers can do a
 * sequence of operations and check the flag once at the end.
 *
 * This module is pure (no AmiSSL, no sockets) and is unit-checked on the build
 * host in tests/test_pbuf.c.
 */

#ifndef AMISYNC_PBUF_H
#define AMISYNC_PBUF_H

#include <stddef.h>
#include <stdint.h>

/* Protobuf wire types. */
#define PBUF_WT_VARINT  0   /* int32/64, uint32/64, bool, enum            */
#define PBUF_WT_I64     1   /* fixed64, sfixed64, double                  */
#define PBUF_WT_LEN     2   /* string, bytes, embedded message, packed    */
#define PBUF_WT_I32     5   /* fixed32, sfixed32, float                   */

/* ---- reader ---------------------------------------------------------- */

typedef struct {
    const unsigned char *p;     /* next byte to read   */
    const unsigned char *end;   /* one past the buffer */
    int                  error; /* sticky: set on truncation/garbage */
} PbufReader;

void pbuf_reader_init(PbufReader *r, const void *data, size_t len);

/* 1 if the buffer is fully consumed (and no error), else 0. */
int  pbuf_eof(const PbufReader *r);

/* Read a base-128 varint. Returns 1 on success, 0 (and sets error) if the
 * buffer ends mid-varint or the value exceeds 10 bytes. */
int  pbuf_read_varint(PbufReader *r, uint64_t *out);

/* Read a field tag, splitting it into field number and wire type. Returns 1
 * on success, 0 at clean EOF or on error (check r->error to tell them apart). */
int  pbuf_read_tag(PbufReader *r, uint32_t *field, int *wiretype);

/* Read a length-delimited field, returning a pointer into the source buffer
 * (no copy) and its length. Valid only while the source buffer lives. */
int  pbuf_read_bytes(PbufReader *r, const unsigned char **data, size_t *len);


/* Skip the value of a field of the given wire type (for unknown fields, which
 * is how we stay forward-compatible with newer Syncthing). Returns 1 on
 * success, 0 on error. */
int  pbuf_skip(PbufReader *r, int wiretype);

/* ---- writer ---------------------------------------------------------- */

typedef struct {
    unsigned char *buf;   /* destination               */
    size_t         cap;   /* capacity                  */
    size_t         len;   /* bytes written so far      */
    int            error; /* sticky: set on overflow   */
} PbufWriter;

void pbuf_writer_init(PbufWriter *w, void *buf, size_t cap);

/* Low-level primitives. */
int  pbuf_write_varint(PbufWriter *w, uint64_t v);
int  pbuf_write_tag(PbufWriter *w, uint32_t field, int wiretype);

/* Field writers (tag + value). A varint field whose value is 0 / empty is
 * still emitted; callers that want proto3 "omit default" semantics simply
 * don't call these. */
int  pbuf_write_uint64(PbufWriter *w, uint32_t field, uint64_t v);
int  pbuf_write_int64(PbufWriter *w, uint32_t field, int64_t v);
int  pbuf_write_bool(PbufWriter *w, uint32_t field, int v);
int  pbuf_write_enum(PbufWriter *w, uint32_t field, int v);

/* Length-delimited field writers. 'bytes' writes raw data; 'string' takes a
 * NUL-terminated string; 'message' writes the contents of a finished writer as
 * an embedded message (a sub-writer with its error flag set poisons 'w', so an
 * overflowed sub-encode cannot slip through as a truncated embedded message). */
int  pbuf_write_bytes(PbufWriter *w, uint32_t field, const void *data, size_t len);
int  pbuf_write_string(PbufWriter *w, uint32_t field, const char *s);
int  pbuf_write_message(PbufWriter *w, uint32_t field, const PbufWriter *msg);

#endif /* AMISYNC_PBUF_H */
