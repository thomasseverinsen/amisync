/* test_pbuf.c - host unit check for the protobuf wire codec
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host with plain cc (see `make test-pbuf`), NOT
 * cross-compiled. pbuf is pure, so it links directly. We check varint edge
 * cases, a full field round-trip, unknown-field skipping (forward compat),
 * embedded messages, and that overflow/truncation set the sticky error flags
 * instead of running off the buffer.
 */

#include "../src/pbuf.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) {
        printf("ok   %s\n", what);
    } else {
        printf("FAIL %s\n", what);
        failures++;
    }
}

/* varint values that exercise 1, 2, 5 and 10 byte encodings. */
static void test_varint(void)
{
    static const uint64_t vals[] = {
        0, 1, 127, 128, 300, 16383, 16384, 0xFFFFFFFFu, 0xFFFFFFFFFFFFFFFFull
    };
    size_t i;

    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        unsigned char buf[16];
        PbufWriter w;
        PbufReader r;
        uint64_t   got = 0;

        pbuf_writer_init(&w, buf, sizeof(buf));
        pbuf_write_varint(&w, vals[i]);
        ok("varint write ok", !w.error);

        pbuf_reader_init(&r, buf, w.len);
        ok("varint read ok", pbuf_read_varint(&r, &got));
        ok("varint round-trips", got == vals[i]);
        ok("varint fully consumed", pbuf_eof(&r));
    }
}

/* Encode a small "message" by hand and decode it field by field, including a
 * field the decoder doesn't know (which it must skip). */
static void test_message_roundtrip(void)
{
    unsigned char buf[128];
    PbufWriter w;
    PbufReader r;
    uint32_t   field;
    int        wt;
    int        saw_1 = 0, saw_3 = 0, saw_msg = 0;

    pbuf_writer_init(&w, buf, sizeof(buf));
    pbuf_write_string(&w, 1, "amisync");      /* field 1: string  */
    pbuf_write_uint64(&w, 2, 0xDEADBEEFu);    /* field 2: unknown to reader */
    pbuf_write_bool(&w, 3, 1);                /* field 3: bool    */
    {
        unsigned char sub[32];
        PbufWriter sw;
        pbuf_writer_init(&sw, sub, sizeof(sub));
        pbuf_write_uint64(&sw, 1, 42);
        pbuf_write_message(&w, 5, &sw);       /* field 5: embedded message */
    }
    ok("message encode ok", !w.error);

    pbuf_reader_init(&r, buf, w.len);
    while (pbuf_read_tag(&r, &field, &wt)) {
        if (field == 1 && wt == PBUF_WT_LEN) {
            const unsigned char *d; size_t n;
            pbuf_read_bytes(&r, &d, &n);
            ok("field 1 string value", n == 7 && memcmp(d, "amisync", 7) == 0);
            saw_1 = 1;
        } else if (field == 3 && wt == PBUF_WT_VARINT) {
            uint64_t v; pbuf_read_varint(&r, &v);
            ok("field 3 bool value", v == 1);
            saw_3 = 1;
        } else if (field == 5 && wt == PBUF_WT_LEN) {
            const unsigned char *d; size_t n;
            PbufReader sr; uint32_t sf; int sw_;
            pbuf_read_bytes(&r, &d, &n);
            pbuf_reader_init(&sr, d, n);
            if (pbuf_read_tag(&sr, &sf, &sw_)) {
                uint64_t v; pbuf_read_varint(&sr, &v);
                ok("embedded message field", sf == 1 && v == 42);
            }
            saw_msg = 1;
        } else {
            ok("skip unknown field", pbuf_skip(&r, wt));
        }
    }
    ok("no decode error", !r.error);
    ok("saw fields 1, 3 and embedded", saw_1 && saw_3 && saw_msg);
}

/* A writer that overflows its buffer must set error, not scribble past it. */
static void test_overflow(void)
{
    unsigned char buf[4];
    PbufWriter w;

    pbuf_writer_init(&w, buf, sizeof(buf));
    pbuf_write_string(&w, 1, "way too long for four bytes");
    ok("overflow sets error", w.error);
    ok("overflow never exceeds cap", w.len <= w.cap);
}

/* A reader handed a truncated length-delimited field must error, not overread. */
static void test_truncation(void)
{
    /* tag for field 1 / LEN, length 10, but only 2 bytes follow */
    static const unsigned char buf[] = { 0x0A, 0x0A, 'h', 'i' };
    PbufReader r;
    uint32_t   field;
    int        wt;
    const unsigned char *d;
    size_t     n;

    pbuf_reader_init(&r, buf, sizeof(buf));
    pbuf_read_tag(&r, &field, &wt);
    ok("truncated bytes read fails", !pbuf_read_bytes(&r, &d, &n));
    ok("truncation sets error", r.error);
}

int main(void)
{
    test_varint();
    test_message_roundtrip();
    test_overflow();
    test_truncation();

    if (failures) {
        printf("\n%d pbuf check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall pbuf checks passed\n");
    return 0;
}
