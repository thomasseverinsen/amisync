/* test_bep.c - host unit check for BEP framing + message codecs
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host (see `make test-bep`). It checks the pure
 * encode/decode round-trips for Hello, Header and ClusterConfig, then drives
 * the framed transport over an in-memory pipe - including a hand-framed
 * LZ4-compressed message to exercise the decompress path on receive.
 */

#include "bep.h"
#include "pbuf.h"
#include "lz4.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

/* ---- in-memory transport -------------------------------------------- */

typedef struct {
    unsigned char buf[256 * 1024];
    int           len;     /* bytes written */
    int           rpos;    /* bytes read    */
} MemPipe;

static int mem_write(void *ctx, const void *b, int n)
{
    MemPipe *m = ctx;
    if (m->len + n > (int)sizeof(m->buf)) return -1;
    memcpy(m->buf + m->len, b, n);
    m->len += n;
    return n;
}

static int mem_read(void *ctx, void *b, int n)
{
    MemPipe *m = ctx;
    int avail = m->len - m->rpos;
    if (avail <= 0) return 0;
    if (n > avail) n = avail;
    memcpy(b, m->buf + m->rpos, n);
    m->rpos += n;
    return n;
}

static void put_be16(unsigned char *p, unsigned v){ p[0]=v>>8; p[1]=v; }
static void put_be32(unsigned char *p, unsigned v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

static void test_hello_roundtrip(void)
{
    BepHello a, b;
    unsigned char buf[256];
    int len;

    memset(&a, 0, sizeof(a));
    strcpy(a.device_name, "amiga4000");
    strcpy(a.client_name, "amisync");
    strcpy(a.client_version, "0.2");

    ok("hello encode", bep_encode_hello(&a, buf, sizeof(buf), &len));
    ok("hello decode", bep_decode_hello(buf, len, &b));
    ok("hello device_name", strcmp(b.device_name, "amiga4000") == 0);
    ok("hello client_name", strcmp(b.client_name, "amisync") == 0);
    ok("hello client_version", strcmp(b.client_version, "0.2") == 0);
}

static void test_header_roundtrip(void)
{
    BepHeader h, g;
    unsigned char buf[16];
    int len;

    h.type = BEP_PING; h.compression = BEP_COMPRESS_LZ4;
    ok("header encode", bep_encode_header(&h, buf, sizeof(buf), &len));
    ok("header decode", bep_decode_header(buf, len, &g));
    ok("header type", g.type == BEP_PING);
    ok("header compression", g.compression == BEP_COMPRESS_LZ4);

    /* default type (CLUSTER_CONFIG=0) + no compression */
    h.type = BEP_CLUSTER_CONFIG; h.compression = BEP_COMPRESS_NONE;
    bep_encode_header(&h, buf, sizeof(buf), &len);
    bep_decode_header(buf, len, &g);
    ok("header default type", g.type == BEP_CLUSTER_CONFIG);
    ok("header default compression", g.compression == BEP_COMPRESS_NONE);
}

static void test_cluster_config_roundtrip(void)
{
    BepClusterConfig a, b;
    unsigned char buf[4096];
    int len, i;

    memset(&a, 0, sizeof(a));
    a.num_folders = 1;
    strcpy(a.folders[0].id, "default");
    strcpy(a.folders[0].label, "Default Folder");
    a.folders[0].type = BEP_FOLDER_RECEIVE_ONLY;
    a.folders[0].num_devices = 2;
    for (i = 0; i < BEP_DEVICE_KEY_LEN; i++) {
        a.folders[0].devices[0].id[i] = (unsigned char)i;
        a.folders[0].devices[1].id[i] = (unsigned char)(0xFF - i);
    }
    strcpy(a.folders[0].devices[0].name, "self");
    strcpy(a.folders[0].devices[1].name, "peer");

    ok("cc encode", bep_encode_cluster_config(&a, buf, sizeof(buf), &len));
    ok("cc decode", bep_decode_cluster_config(buf, len, &b));
    ok("cc folder count", b.num_folders == 1);
    ok("cc folder id", strcmp(b.folders[0].id, "default") == 0);
    ok("cc folder label", strcmp(b.folders[0].label, "Default Folder") == 0);
    ok("cc folder type", b.folders[0].type == BEP_FOLDER_RECEIVE_ONLY);
    ok("cc device count", b.folders[0].num_devices == 2);
    ok("cc device0 key", memcmp(b.folders[0].devices[0].id,
                                a.folders[0].devices[0].id, BEP_DEVICE_KEY_LEN) == 0);
    ok("cc device1 name", strcmp(b.folders[0].devices[1].name, "peer") == 0);

    /* empty ClusterConfig must also round-trip (zero folders) */
    memset(&a, 0, sizeof(a));
    ok("cc empty encode", bep_encode_cluster_config(&a, buf, sizeof(buf), &len));
    ok("cc empty decode", bep_decode_cluster_config(buf, len, &b) && b.num_folders == 0);
}

static void test_phase3_messages(void)
{
    unsigned char buf[1024];
    int           len;

    /* Request round-trip */
    {
        BepRequest a, b;
        int i;
        memset(&a, 0, sizeof(a));
        a.id = 4242;
        strcpy(a.folder, "photos");
        strcpy(a.name, "2026/cat.jpg");
        a.offset = 1 << 20;
        a.size   = 128 * 1024;
        a.block_no = 8;
        a.has_hash = 1;
        for (i = 0; i < BEP_HASH_LEN; i++) a.hash[i] = (unsigned char)(i + 3);

        ok("request encode", bep_encode_request(&a, buf, sizeof(buf), &len));
        ok("request decode", bep_decode_request(buf, len, &b));
        ok("request id", b.id == 4242);
        ok("request folder", strcmp(b.folder, "photos") == 0);
        ok("request name", strcmp(b.name, "2026/cat.jpg") == 0);
        ok("request offset", b.offset == (1 << 20));
        ok("request size", b.size == 128 * 1024);
        ok("request block_no", b.block_no == 8);
        ok("request hash", b.has_hash && memcmp(b.hash, a.hash, BEP_HASH_LEN) == 0);
    }

    /* Response round-trip */
    {
        BepResponse a, b;
        unsigned char data[] = { 1, 2, 3, 4, 5 };
        memset(&a, 0, sizeof(a));
        a.id = 4242; a.data = data; a.data_len = sizeof(data); a.code = BEP_ERR_NONE;
        ok("response encode", bep_encode_response(&a, buf, sizeof(buf), &len));
        ok("response decode", bep_decode_response(buf, len, &b));
        ok("response id", b.id == 4242);
        ok("response data", b.data_len == 5 && memcmp(b.data, data, 5) == 0);

        /* error response carries no data */
        memset(&a, 0, sizeof(a));
        a.id = 7; a.code = BEP_ERR_NO_SUCH_FILE;
        bep_encode_response(&a, buf, sizeof(buf), &len);
        bep_decode_response(buf, len, &b);
        ok("response error code", b.code == BEP_ERR_NO_SUCH_FILE && b.data_len == 0);
    }

    /* FileInfo round-trip (name/type/size/version/blocks) */
    {
        BepFileInfo a, b;
        int i;
        memset(&a, 0, sizeof(a));
        strcpy(a.name, "dir/file.txt");
        a.type = BEP_FILE_FILE;
        a.size = 3000;
        a.modified_s = 1700000000;
        a.modified_by = 0x3A5F00D5ULL;
        a.block_size = 1024;
        a.sequence = 99;
        a.version.num_counters = 1;
        a.version.counters[0].id = 0xABCD;
        a.version.counters[0].value = 5;
        a.num_blocks = 2;
        a.blocks[0].offset = 0;    a.blocks[0].size = 1024; a.blocks[0].has_hash = 1;
        a.blocks[1].offset = 1024; a.blocks[1].size = 1024; a.blocks[1].has_hash = 1;
        for (i = 0; i < BEP_HASH_LEN; i++) {
            a.blocks[0].hash[i] = (unsigned char)i;
            a.blocks[1].hash[i] = (unsigned char)(i + 100);
        }

        ok("fileinfo encode", bep_encode_file_info(&a, buf, sizeof(buf), &len));
        ok("fileinfo decode", bep_decode_file_info(buf, len, &b));
        ok("fileinfo name", strcmp(b.name, "dir/file.txt") == 0);
        ok("fileinfo size", b.size == 3000);
        ok("fileinfo modified_s", b.modified_s == 1700000000);
        ok("fileinfo modified_by", b.modified_by == 0x3A5F00D5ULL);
        ok("fileinfo version", b.version.num_counters == 1 &&
                               b.version.counters[0].id == 0xABCD &&
                               b.version.counters[0].value == 5);
        ok("fileinfo blocks", b.num_blocks == 2 &&
                              b.blocks[1].offset == 1024 &&
                              memcmp(b.blocks[0].hash, a.blocks[0].hash, BEP_HASH_LEN) == 0);
    }

    /* Index summary: folder name + file count, hand-built */
    {
        PbufWriter w;
        BepFileInfo fi;
        unsigned char fbuf[256];
        int flen;
        char folder[BEP_FOLDER_ID_MAX];
        int  nfiles;

        memset(&fi, 0, sizeof(fi));
        strcpy(fi.name, "a"); fi.size = 1;
        bep_encode_file_info(&fi, fbuf, sizeof(fbuf), &flen);

        pbuf_writer_init(&w, buf, sizeof(buf));
        pbuf_write_string(&w, 1, "music");          /* Index.folder */
        pbuf_write_bytes(&w, 2, fbuf, flen);         /* Index.files[0] */
        pbuf_write_bytes(&w, 2, fbuf, flen);         /* Index.files[1] */

        ok("index summary", bep_index_summary(buf, (int)w.len, folder, &nfiles));
        ok("index folder", strcmp(folder, "music") == 0);
        ok("index file count", nfiles == 2);
    }

    /* Index encode + iterate round-trip: build an Index of two files, then
     * walk it back out FileInfo by FileInfo. */
    {
        BepFileInfo files[2], got;
        BepIndexIter it;
        char folder[BEP_FOLDER_ID_MAX];
        int  i, n;

        memset(files, 0, sizeof(files));
        strcpy(files[0].name, "alpha.txt"); files[0].size = 10;
        files[0].num_blocks = 1; files[0].blocks[0].size = 10;
        files[0].blocks[0].has_hash = 1;
        files[0].version.num_counters = 1;
        files[0].version.counters[0].id = 0x1111; files[0].version.counters[0].value = 7;
        strcpy(files[1].name, "beta.txt"); files[1].size = 20;
        files[1].num_blocks = 1; files[1].blocks[0].offset = 0; files[1].blocks[0].size = 20;
        for (i = 0; i < BEP_HASH_LEN; i++) files[1].blocks[0].hash[i] = (unsigned char)i;
        files[1].blocks[0].has_hash = 1;

        ok("index encode", bep_encode_index("docs", files, 2, buf, sizeof(buf), &len));

        bep_index_iter_begin(&it, buf, len, folder);
        ok("index iter folder", strcmp(folder, "docs") == 0);

        n = 0;
        while (bep_index_iter_next(&it, &got)) {
            if (n == 0) ok("index iter file 0", strcmp(got.name, "alpha.txt") == 0 &&
                                                got.size == 10 &&
                                                got.version.counters[0].value == 7);
            if (n == 1) ok("index iter file 1", strcmp(got.name, "beta.txt") == 0 &&
                                                got.num_blocks == 1 &&
                                                memcmp(got.blocks[0].hash,
                                                       files[1].blocks[0].hash,
                                                       BEP_HASH_LEN) == 0);
            n++;
        }
        ok("index iter count", n == 2 && !it.error);
    }
}

static void test_framed_transport(void)
{
    MemPipe  *pipe = calloc(1, sizeof(MemPipe));
    BepConn  *tx   = calloc(1, sizeof(BepConn));
    BepConn  *rx   = calloc(1, sizeof(BepConn));
    BepHello  local, remote;
    BepHeader hdr;
    const unsigned char *body;
    int       bodylen;

    tx->t.ctx = pipe; tx->t.read = mem_read; tx->t.write = mem_write;
    rx->t.ctx = pipe; rx->t.read = mem_read; rx->t.write = mem_write;
    ok("conn init tx", bep_conn_init(tx));
    ok("conn init rx", bep_conn_init(rx));

    memset(&local, 0, sizeof(local));
    strcpy(local.device_name, "node-a");
    strcpy(local.client_name, "amisync");
    strcpy(local.client_version, "0.2");

    /* Hello frame across the pipe. */
    ok("send hello", bep_send_hello(tx, &local));
    ok("read hello", bep_read_hello(rx, &remote));
    ok("hello name across wire", strcmp(remote.device_name, "node-a") == 0);

    /* A ping (empty body) and an uncompressed cluster config. */
    ok("send ping", bep_send_ping(tx));
    {
        BepClusterConfig cc;
        memset(&cc, 0, sizeof(cc));
        cc.num_folders = 1;
        strcpy(cc.folders[0].id, "photos");
        ok("send cluster config", bep_send_cluster_config(tx, &cc));
    }

    ok("read ping frame", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
    ok("ping is PING/empty", hdr.type == BEP_PING && bodylen == 0);

    ok("read cc frame", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
    ok("cc frame type", hdr.type == BEP_CLUSTER_CONFIG && hdr.compression == BEP_COMPRESS_NONE);
    {
        BepClusterConfig cc;
        ok("cc frame decodes", bep_decode_cluster_config(body, bodylen, &cc) &&
                               cc.num_folders == 1 &&
                               strcmp(cc.folders[0].id, "photos") == 0);
    }

    /* Real Syncthing (proto3) omits zero-valued Header fields, so a ClusterConfig
     * with no compression arrives with headerLen==0. Hand-frame that and confirm
     * we decode it as the all-defaults Header instead of treating it as junk. */
    {
        BepClusterConfig cc;
        unsigned char    ccbuf[256], frame[8];
        int              cclen;

        memset(&cc, 0, sizeof(cc));
        cc.num_folders = 1;
        strcpy(cc.folders[0].id, "music");
        ok("encode cc body", bep_encode_cluster_config(&cc, ccbuf, sizeof(ccbuf), &cclen));

        put_be16(frame, 0);                            /* headerLen = 0 (omitted) */
        mem_write(pipe, frame, 2);
        put_be32(frame, cclen);                        /* messageLen */
        mem_write(pipe, frame, 4);
        mem_write(pipe, ccbuf, cclen);                 /* ClusterConfig body */

        ok("read zero-header frame", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
        ok("zero-header defaults to CLUSTER_CONFIG/NONE",
           hdr.type == BEP_CLUSTER_CONFIG && hdr.compression == BEP_COMPRESS_NONE);
        ok("zero-header body decodes",
           bep_decode_cluster_config(body, bodylen, &cc) && cc.num_folders == 1 &&
           strcmp(cc.folders[0].id, "music") == 0);
    }

    /* Hand-frame an LZ4-compressed message to exercise the decode path. */
    {
        unsigned char plain[1024];
        char          comp[1200];
        unsigned char fh[16];
        int           hlen, clen, j;
        BepHeader     ch;

        for (j = 0; j < (int)sizeof(plain); j++) plain[j] = (unsigned char)(j & 0x1F);
        clen = LZ4_compress_default((char *)plain, comp, sizeof(plain), sizeof(comp));
        ok("lz4 compresses", clen > 0);

        ch.type = BEP_INDEX; ch.compression = BEP_COMPRESS_LZ4;
        bep_encode_header(&ch, fh + 2, sizeof(fh) - 2, &hlen);
        put_be16(fh, hlen);
        mem_write(pipe, fh, 2 + hlen);                 /* headerLen + Header */
        {
            unsigned char mlbuf[8];
            put_be32(mlbuf, 4 + clen);                 /* messageLen */
            mem_write(pipe, mlbuf, 4);
            put_be32(mlbuf, sizeof(plain));            /* uncompressed size prefix */
            mem_write(pipe, mlbuf, 4);
        }
        mem_write(pipe, comp, clen);                   /* lz4 block */

        ok("read lz4 frame", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
        ok("lz4 frame type", hdr.type == BEP_INDEX);
        ok("lz4 decompressed size", bodylen == (int)sizeof(plain));
        ok("lz4 decompressed bytes", memcmp(body, plain, sizeof(plain)) == 0);
    }

    /* Outbound compression: a large, highly-compressible body sent via
     * bep_send_message must go out LZ4-flagged and round-trip intact; a small
     * body stays uncompressed (below BEP_COMPRESS_MIN). */
    {
        unsigned char big[8192];
        int           j;
        for (j = 0; j < (int)sizeof(big); j++) big[j] = (unsigned char)(j & 7);

        ok("send big body", bep_send_message(tx, BEP_INDEX, big, sizeof(big)));
        ok("read big body", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
        ok("big body compressed", hdr.compression == BEP_COMPRESS_LZ4);
        ok("big body round-trips",
           bodylen == (int)sizeof(big) && memcmp(body, big, sizeof(big)) == 0);

        ok("send small body", bep_send_message(tx, BEP_INDEX, big, 16));
        ok("read small body", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
        ok("small body uncompressed", hdr.compression == BEP_COMPRESS_NONE);
        ok("small body round-trips", bodylen == 16 && memcmp(body, big, 16) == 0);
    }

    bep_conn_free(tx); bep_conn_free(rx);
    free(pipe); free(tx); free(rx);
}

/* The large-file path: encode an Index entry from an external block-hash list
 * (too many blocks to fit BepFileInfo.blocks) and stream it back out via the
 * callback decoder, checking the derived geometry and the block hashes. */
typedef struct { BepBlockInfo b[300]; int n; } BlockCollect;

static int collect_cb(void *ctx, int index, const BepBlockInfo *blk)
{
    BlockCollect *c = (BlockCollect *)ctx;
    if (index < 300)
        c->b[index] = *blk;
    c->n = index + 1;
    return 1;
}

static void test_large_file_stream(void)
{
    unsigned char  buf[64 * 1024];
    unsigned char  hashes[200][BEP_HASH_LEN];
    BepFileInfo    meta, got;
    BepIndexIter   it;
    char           folder[BEP_FOLDER_ID_MAX];
    BlockCollect   col;
    int            len, i, j, geo_ok = 1, hash_ok = 1;
    int64_t        bs   = 128 * 1024;
    int            nblk = 200;                       /* > BEP_MAX_BLOCKS */
    int64_t        size = (int64_t)(nblk - 1) * bs + 777;  /* partial last block */

    memset(&meta, 0, sizeof(meta));
    strcpy(meta.name, "big.bin");
    meta.type       = BEP_FILE_FILE;
    meta.size       = size;
    meta.block_size = (int32_t)bs;
    meta.version.num_counters    = 1;
    meta.version.counters[0].id  = 0x9;
    meta.version.counters[0].value = 5;
    for (i = 0; i < nblk; i++)
        for (j = 0; j < BEP_HASH_LEN; j++)
            hashes[i][j] = (unsigned char)((i * 31 + j) & 0xFF);

    ok("ext index encode",
       bep_encode_index_file("vol", &meta, hashes, nblk, buf, sizeof(buf), &len));

    bep_index_iter_begin(&it, buf, len, folder);
    ok("ext iter folder", strcmp(folder, "vol") == 0);

    col.n = 0;
    ok("ext iter next", bep_index_iter_next_cb(&it, &got, collect_cb, &col));
    ok("ext meta", strcmp(got.name, "big.bin") == 0 && got.size == size &&
                   got.block_size == bs && got.num_blocks == nblk &&
                   got.version.counters[0].value == 5);
    for (i = 0; i < nblk; i++) {
        int64_t off  = (int64_t)i * bs;
        int64_t left = size - off;
        int32_t esz  = (int32_t)(left > bs ? bs : left);
        if (col.b[i].offset != off || col.b[i].size != esz)        geo_ok = 0;
        if (memcmp(col.b[i].hash, hashes[i], BEP_HASH_LEN) != 0)    hash_ok = 0;
    }
    ok("ext block geometry derived", geo_ok && col.n == nblk);
    ok("ext block hashes round-trip", hash_ok);
    ok("ext iter end", !bep_index_iter_next_cb(&it, &got, collect_cb, &col) &&
                       !it.error);
}

/* The buffers start at BEP_MSG_INIT and must grow (up to BEP_MSG_MAX) for a
 * message larger than that. Exercise both grow paths: a compressible body grows
 * the receiver's 'plain' on decompress (the path that must preserve the already-
 * buffered compressed 'wire' across the realloc), and an incompressible body
 * grows 'wire' on the raw read. */
/* Batched Index: the path that turns one message per file into one per few
 * hundred. It is also the path where a malformed body makes Syncthing hang up,
 * so the round trip is checked here rather than discovered on the wire.
 *
 * Covers the three things the announce loop depends on: every entry comes back
 * in order, a refused add leaves the batch intact (so the caller can flush and
 * retry that entry), and a batch that was refused still decodes cleanly - i.e.
 * the bytes the failed attempt scribbled past the end did not corrupt it. */
static void test_index_batch(void)
{
    BepConn       c;
    BepIndexBatch b;
    BepFileInfo   fi, got;
    BepIndexIter  it;
    unsigned char hash[BEP_HASH_LEN];
    char          folder[BEP_FOLDER_ID_MAX];
    int           i, n, seen, order_ok = 1, refused_at;

    memset(&c, 0, sizeof(c));
    ok("batch conn init", bep_conn_init(&c));
    memset(hash, 0xC3, sizeof(hash));

    bep_index_batch_begin(&c, &b, "fold-1");
    ok("batch begins empty", b.num == 0 && b.len > 0 && !b.error);

    for (n = 0; n < 500; n++) {
        memset(&fi, 0, sizeof(fi));
        sprintf(fi.name, "dir/file%03d.bin", n);
        fi.type       = BEP_FILE_FILE;
        fi.size       = 1234 + n;
        fi.block_size = 128 * 1024;
        fi.version.num_counters      = 1;
        fi.version.counters[0].id    = 0xAB;
        fi.version.counters[0].value = (uint64_t)(n + 1);
        if (!bep_index_batch_add(&b, &fi, (const unsigned char (*)[BEP_HASH_LEN])hash, 1))
            break;
    }
    ok("batch took many entries", n >= 100 && b.num == n);

    /* A refusal must not disturb what is already packed. */
    refused_at = b.len;
    memset(&fi, 0, sizeof(fi));
    strcpy(fi.name, "one/more.bin");
    fi.type = BEP_FILE_FILE;
    fi.size = 1;
    fi.block_size = 128 * 1024;
    while (bep_index_batch_add(&b, &fi,
                               (const unsigned char (*)[BEP_HASH_LEN])hash, 1))
        refused_at = b.len;              /* fill to the brim, then one too many */
    ok("refusal leaves batch length alone", b.len == refused_at);

    /* Everything packed decodes back, in order, unharmed by the refusal. */
    bep_index_iter_begin(&it, b.buf, b.len, folder);
    ok("batch folder", strcmp(folder, "fold-1") == 0);
    seen = 0;
    while (bep_index_iter_next(&it, &got)) {
        if (seen < n) {
            char want[64];
            sprintf(want, "dir/file%03d.bin", seen);
            if (strcmp(got.name, want) != 0 || got.size != 1234 + seen ||
                got.version.counters[0].value != (uint64_t)(seen + 1))
                order_ok = 0;
        }
        seen++;
    }
    ok("batch decodes every entry", seen == b.num);
    ok("batch preserves order and fields", order_ok);

    /* An empty batch is a no-op, not a malformed message. */
    bep_index_batch_begin(&c, &b, "fold-2");
    ok("empty batch has no entries", b.num == 0);
    bep_index_iter_begin(&it, b.buf, b.len, folder);
    ok("empty batch folder still readable", strcmp(folder, "fold-2") == 0);
    ok("empty batch yields nothing", !bep_index_iter_next(&it, &got));

    /* Single entry, to be sure the batch form matches the one-shot encoder. */
    memset(&fi, 0, sizeof(fi));
    strcpy(fi.name, "solo.txt");
    fi.type = BEP_FILE_FILE;
    fi.size = 42;
    fi.block_size = 128 * 1024;
    ok("batch single add",
       bep_index_batch_add(&b, &fi,
                           (const unsigned char (*)[BEP_HASH_LEN])hash, 1));
    bep_index_iter_begin(&it, b.buf, b.len, folder);
    ok("batch single decodes",
       bep_index_iter_next(&it, &got) && strcmp(got.name, "solo.txt") == 0 &&
       got.size == 42 && !bep_index_iter_next(&it, &got));

    (void)i;
    bep_conn_free(&c);
}

#define FOLDER_MAX_BLOCKS_TEST 2048

static void test_buffer_growth(void)
{
    const int big = BEP_MSG_INIT + 40 * 1024;   /* > init, < 256 KiB pipe */
    MemPipe  *pipe = calloc(1, sizeof(MemPipe));
    BepConn  *tx   = calloc(1, sizeof(BepConn));
    BepConn  *rx   = calloc(1, sizeof(BepConn));
    unsigned char *src = malloc(big);
    BepHeader hdr;
    const unsigned char *body;
    int       bodylen, j;

    tx->t.ctx = pipe; tx->t.read = mem_read; tx->t.write = mem_write;
    rx->t.ctx = pipe; rx->t.read = mem_read; rx->t.write = mem_write;
    ok("growth: conn init tx", bep_conn_init(tx));
    ok("growth: conn init rx", bep_conn_init(rx));
    /* Each buffer starts at what it is for, not at the largest of the three. */
    ok("growth: buffers start at their own sizes",
       tx->wire_cap == BEP_WIRE_INIT && tx->plain_cap == BEP_PLAIN_INIT &&
       tx->out_cap  == BEP_OUT_INIT  && rx->wire_cap  == BEP_WIRE_INIT);

    /* Highly compressible: small on the wire, large once decompressed. */
    for (j = 0; j < big; j++) src[j] = (unsigned char)(j & 3);
    ok("growth: send compressible >init", bep_send_message(tx, BEP_INDEX, src, big));
    ok("growth: read compressible >init", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
    ok("growth: compressible was LZ4", hdr.compression == BEP_COMPRESS_LZ4);
    ok("growth: compressible round-trips",
       bodylen == big && memcmp(body, src, big) == 0);
    /* Compressible: the body arrives small and is inflated, so only 'plain'
     * needs the room - 'wire' holds the compressed bytes and stays put. This is
     * the whole point of sizing them separately. */
    ok("growth: rx 'plain' grew", rx->plain_cap >= big);
    ok("growth: rx 'wire' did not have to", rx->wire_cap < big);

    /* Incompressible (xorshift32 noise): stays raw, so the receiver's 'wire'
     * must grow instead of 'plain'. */
    {
        unsigned x = 0x9e3779b9u;
        for (j = 0; j < big; j++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            src[j] = (unsigned char)x;
        }
    }
    ok("growth: send incompressible >init", bep_send_message(tx, BEP_INDEX, src, big));
    ok("growth: read incompressible >init", bep_read_message(rx, &hdr, &body, &bodylen) == 1);
    ok("growth: incompressible was raw", hdr.compression == BEP_COMPRESS_NONE);
    ok("growth: incompressible round-trips",
       bodylen == big && memcmp(body, src, big) == 0);
    /* Raw this time, so it is 'wire' that had to grow. */
    ok("growth: rx 'wire' grew for a raw body", rx->wire_cap >= big);

    /* A FileInfo with a full block list is tens of KB - past what 'out' starts
     * at - so the sender must grow rather than fail. That path did not exist
     * while every buffer began at a full block. */
    {
        BepFileInfo  meta;
        unsigned char (*hashes)[BEP_HASH_LEN] =
            calloc(FOLDER_MAX_BLOCKS_TEST, BEP_HASH_LEN);
        int k;
        memset(&meta, 0, sizeof(meta));
        strcpy(meta.name, "huge.bin");
        meta.type       = BEP_FILE_FILE;
        meta.block_size = 128 * 1024;
        meta.size       = (int64_t)FOLDER_MAX_BLOCKS_TEST * meta.block_size;
        for (k = 0; k < FOLDER_MAX_BLOCKS_TEST; k++)
            hashes[k][0] = (unsigned char)k;
        ok("growth: a full block list still encodes",
           bep_send_index_file(tx, BEP_INDEX, "f", &meta, hashes,
                               FOLDER_MAX_BLOCKS_TEST));
        ok("growth: big FileInfo reads back",
           bep_read_message(rx, &hdr, &body, &bodylen) == 1 && bodylen > 0);
        free(hashes);
    }

    /* 'out' does have to grow for a Response carrying a block larger than it
     * starts at - the path bep_send_response takes explicitly, and the one that
     * would have failed the connection before the send side could grow at all. */
    {
        BepResponse big_rs;
        int32_t     before_cap = tx->out_cap;
        /* Reset the 256 KiB pipe: the messages above have nearly filled it, and
         * this one is deliberately large. */
        pipe->len = pipe->rpos = 0;
        int         want = BEP_OUT_INIT + 64 * 1024;
        unsigned char *blk = calloc((size_t)want, 1);

        memset(&big_rs, 0, sizeof(big_rs));
        big_rs.id       = 7;
        big_rs.data     = blk;
        big_rs.data_len = want;
        ok("growth: oversized Response sends",
           bep_send_response(tx, &big_rs));
        ok("growth: out grew to carry it", tx->out_cap > before_cap);
        ok("growth: oversized Response reads back",
           bep_read_message(rx, &hdr, &body, &bodylen) == 1 && bodylen > 0);
        free(blk);
    }

    bep_conn_free(tx); bep_conn_free(rx);
    free(src); free(pipe); free(tx); free(rx);
}

int main(void)
{
    test_hello_roundtrip();
    test_header_roundtrip();
    test_cluster_config_roundtrip();
    test_phase3_messages();
    test_large_file_stream();
    test_framed_transport();
    test_index_batch();
    test_buffer_growth();

    if (failures) {
        printf("\n%d bep check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall bep checks passed\n");
    return 0;
}
