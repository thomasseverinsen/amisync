/* fuzz_all.c - mutation fuzzer for amisync's untrusted-input decoders
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host under ASan/UBSan (see `make fuzz`). Seeds a
 * corpus with valid encodes of every message type (plus a captured framed
 * transport stream and a hand-framed LZ4-compressed message), then mutates
 * them and feeds every decoder each iteration:
 *
 *   bep_decode_{hello,header,cluster_config,file_info[,_cb],request,response}
 *   bep_index_summary / bep_index_iter_next[_cb]
 *   bep_read_hello / bep_read_message   (framing + LZ4 decompress)
 *   index_store_decode
 *   disco_parse_announce / disco_parse_tcp_addr
 *
 * Usage: fuzz_all [iterations] [rng-seed]. Any memory-safety defect aborts
 * with a sanitizer report; a clean run exits 0. Baseline: a 5M-iteration
 * campaign across two seeds has run clean.
 */

#define DISCO_HOST_TEST
#include "../src/disco.c"

#include "bep.h"
#include "pbuf.h"
#include "lz4.h"
#include "foldstate.h"
#include "index_store.h"
#include "syncmodel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- RNG (xorshift64) ---- */
static uint64_t rng_state;
static uint64_t rnd64(void)
{
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return rng_state = x;
}
static uint32_t rnd(uint32_t n) { return n ? (uint32_t)(rnd64() % n) : 0; }

/* ---- seed corpus ---- */
#define MAX_SEEDS 16
#define FUZZ_CAP  (300 * 1024)
static unsigned char *seeds[MAX_SEEDS];
static int seedlen[MAX_SEEDS];
static int nseeds;

static void add_seed(const void *p, int len)
{
    if (nseeds >= MAX_SEEDS || len <= 0) return;
    seeds[nseeds] = malloc(len);
    memcpy(seeds[nseeds], p, len);
    seedlen[nseeds++] = len;
}

/* In-memory pipe: captures valid frames on the write side, replays mutants on
 * the read side. */
typedef struct { unsigned char *buf; int cap, len, off; } MemPipe;
static int mp_read(void *ctx, void *buf, int len)
{
    MemPipe *m = ctx;
    int n = m->len - m->off;
    if (n <= 0) return 0;
    if (n > len) n = len;
    memcpy(buf, m->buf + m->off, n);
    m->off += n;
    return n;
}
static int mp_write(void *ctx, const void *buf, int len)
{
    MemPipe *m = ctx;
    if (m->len + len > m->cap) return -1;
    memcpy(m->buf + m->len, buf, len);
    m->len += len;
    return len;
}

static BepFileInfo mkfile(const char *name, int nblocks)
{
    BepFileInfo fi;
    int i;
    memset(&fi, 0, sizeof(fi));
    snprintf(fi.name, sizeof(fi.name), "%s", name);
    fi.type = 0;
    fi.size = (int64_t)nblocks * 131072;
    fi.permissions = 0644;
    fi.modified_s = 1234567890;
    fi.block_size = 131072;
    fi.num_blocks = nblocks;
    for (i = 0; i < nblocks && i < BEP_MAX_BLOCKS; i++) {
        fi.blocks[i].offset = (int64_t)i * 131072;
        fi.blocks[i].size = 131072;
        memset(fi.blocks[i].hash, 0xA0 + i, BEP_HASH_LEN);
        fi.blocks[i].has_hash = 1;
    }
    fi.version.num_counters = 2;
    fi.version.counters[0].id = 0x1122334455667788ULL;
    fi.version.counters[0].value = 7;
    fi.version.counters[1].id = 0x99AABBCCDDEEFF00ULL;
    fi.version.counters[1].value = 9;
    fi.sequence = 42;
    memset(fi.content_hash, 0xCC, BEP_HASH_LEN);
    fi.has_content_hash = 1;
    return fi;
}

static uint64_t fuzz_sid;

static void build_seeds(void)
{
    unsigned char buf[64 * 1024];
    int len;

    { BepHello h; memset(&h, 0, sizeof(h));
      strcpy(h.device_name, "amiga4000");
      strcpy(h.client_name, "amisync");
      strcpy(h.client_version, "v1.0");
      if (bep_encode_hello(&h, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { BepHeader hd; hd.type = BEP_INDEX; hd.compression = BEP_COMPRESS_LZ4;
      if (bep_encode_header(&hd, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { BepClusterConfig cc; int i, j; memset(&cc, 0, sizeof(cc));
      cc.num_folders = BEP_MAX_FOLDERS;
      for (i = 0; i < cc.num_folders; i++) {
          snprintf(cc.folders[i].id, sizeof(cc.folders[i].id), "folder-%d", i);
          snprintf(cc.folders[i].label, sizeof(cc.folders[i].label), "label-%d", i);
          cc.folders[i].num_devices = BEP_MAX_DEVICES;
          for (j = 0; j < BEP_MAX_DEVICES; j++) {
              memset(cc.folders[i].devices[j].id, j, BEP_DEVICE_KEY_LEN);
              snprintf(cc.folders[i].devices[j].name,
                       sizeof(cc.folders[i].devices[j].name), "dev-%d", j);
          }
      }
      if (bep_encode_cluster_config(&cc, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { BepFileInfo fi = mkfile("dir/sub/some-long-file-name.bin", 8);
      if (bep_encode_file_info(&fi, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { BepRequest rq; memset(&rq, 0, sizeof(rq));
      rq.id = 77; strcpy(rq.folder, "fuzzfolder"); strcpy(rq.name, "a/b/c.dat");
      rq.offset = 131072; rq.size = 131072; rq.block_no = 1;
      memset(rq.hash, 0xEE, BEP_HASH_LEN); rq.has_hash = 1;
      if (bep_encode_request(&rq, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { static unsigned char data[4096]; BepResponse rs; memset(&rs, 0, sizeof(rs));
      rs.id = 77; rs.data = data; rs.data_len = sizeof(data); rs.code = 0;
      if (bep_encode_response(&rs, buf, sizeof(buf), &len)) add_seed(buf, len); }

    { BepFileInfo files[3];
      files[0] = mkfile("f0.bin", 4);
      files[1] = mkfile("d1", 0); files[1].type = 1;
      files[2] = mkfile("f2.bin", 1); files[2].deleted = 1; files[2].num_blocks = 0;
      if (bep_encode_index("fuzzfolder", files, 3, buf, sizeof(buf), &len))
          add_seed(buf, len); }

    { FolderState *fs = malloc(sizeof(FolderState)); int i, n;
      unsigned char (*hashes)[BEP_HASH_LEN] = malloc(8 * BEP_HASH_LEN);
      foldstate_init(fs, "fuzzfolder", fuzz_sid);
      for (i = 0; i < 40; i++) {
          SyncMeta m; memset(&m, 0, sizeof(m));
          snprintf(m.name, sizeof(m.name), "dir%d/file-%d.dat", i % 4, i);
          m.size = 131072 * (i % 7); m.modified_s = 1000000 + i;
          m.version.num_counters = 1;
          m.version.counters[0].id = fuzz_sid; m.version.counters[0].value = i;
          m.sequence = i + 1;
          memset(m.content_hash, i, 32); m.has_content_hash = 1;
          for (n = 0; n < 8; n++) memset(hashes[n], n ^ i, BEP_HASH_LEN);
          foldstate_upsert(fs, &m, hashes, i % 7 ? (i % 8) : 0);
      }
      n = index_store_encode(fs, buf, sizeof(buf));
      if (n > 0) add_seed(buf, n);
      foldstate_free(fs); free(fs); free(hashes); }

    { unsigned char id[32]; const char *addrs[2] =
          { "tcp://192.168.1.77:22000", "tcp://0.0.0.0:22000" };
      memset(id, 0x5A, sizeof(id));
      len = disco_build_announce(buf, sizeof(buf), id, addrs, 2, 0x1122334455ll);
      if (len > 0) add_seed(buf, len); }

    /* Framed transport stream: hello + cluster config + ping + request +
     * response + index_file, then a hand-framed LZ4 message (the send side
     * never compresses small bodies, so frame one by hand to keep the
     * decompress path in the corpus). */
    { static unsigned char cap_buf[128 * 1024];
      MemPipe mp = { cap_buf, sizeof(cap_buf), 0, 0 };
      BepConn c; memset(&c, 0, sizeof(c));
      c.t.ctx = &mp; c.t.read = mp_read; c.t.write = mp_write;
      if (bep_conn_init(&c)) {
          BepHello h; BepClusterConfig cc; BepRequest rq; BepFileInfo meta;
          static unsigned char rdata[2048];
          static unsigned char bh[8][BEP_HASH_LEN];
          BepResponse rs;
          memset(&h, 0, sizeof(h)); strcpy(h.device_name, "amiga4000");
          strcpy(h.client_name, "amisync"); strcpy(h.client_version, "v1.0");
          memset(&cc, 0, sizeof(cc)); cc.num_folders = 1;
          strcpy(cc.folders[0].id, "fuzzfolder");
          cc.folders[0].num_devices = 1;
          memset(cc.folders[0].devices[0].id, 3, BEP_DEVICE_KEY_LEN);
          memset(&rq, 0, sizeof(rq)); rq.id = 5; strcpy(rq.folder, "fuzzfolder");
          strcpy(rq.name, "x.dat"); rq.size = 1024;
          memset(&rs, 0, sizeof(rs)); rs.id = 5; rs.data = rdata;
          rs.data_len = sizeof(rdata);
          meta = mkfile("framed.bin", 8);
          memset(bh, 0x42, sizeof(bh));

          bep_send_hello(&c, &h);
          bep_send_cluster_config(&c, &cc);
          bep_send_ping(&c);
          bep_send_request(&c, &rq);
          bep_send_response(&c, &rs);
          bep_send_index_file(&c, BEP_INDEX, "fuzzfolder", &meta, bh, 8);
          bep_send_close(&c, "fuzz over");

          /* [hlen][header compression=LZ4][mlen][uint32 usize][lz4 block] */
          { unsigned char body[4096], comp[8192], hdr[16], frame[16];
            int blen, hl, cl;
            BepHeader bh2;
            bep_encode_hello(&h, body, sizeof(body), &blen);
            cl = LZ4_compress_default((const char *)body, (char *)comp + 4,
                                      blen, sizeof(comp) - 4);
            comp[0] = (unsigned char)((blen >> 24) & 0xFF);
            comp[1] = (unsigned char)((blen >> 16) & 0xFF);
            comp[2] = (unsigned char)((blen >> 8) & 0xFF);
            comp[3] = (unsigned char)(blen & 0xFF);
            bh2.type = BEP_CLUSTER_CONFIG; bh2.compression = BEP_COMPRESS_LZ4;
            bep_encode_header(&bh2, hdr, sizeof(hdr), &hl);
            frame[0] = (unsigned char)((hl >> 8) & 0xFF);
            frame[1] = (unsigned char)(hl & 0xFF);
            mp_write(&mp, frame, 2);
            mp_write(&mp, hdr, hl);
            frame[0] = (unsigned char)(((cl + 4) >> 24) & 0xFF);
            frame[1] = (unsigned char)(((cl + 4) >> 16) & 0xFF);
            frame[2] = (unsigned char)(((cl + 4) >> 8) & 0xFF);
            frame[3] = (unsigned char)((cl + 4) & 0xFF);
            mp_write(&mp, frame, 4);
            mp_write(&mp, comp, cl + 4);
          }
          bep_conn_free(&c);
          add_seed(cap_buf, mp.len);
      }
    }

    { const char *u = "tcp://192.168.001.077:22000"; add_seed(u, strlen(u) + 1); }
}

/* ---- mutation ---- */
static int mutate(unsigned char *buf, int len, int cap)
{
    int nmut = 1 + rnd(16), i;
    for (i = 0; i < nmut; i++) {
        switch (rnd(9)) {
        case 0: if (len) buf[rnd(len)] = (unsigned char)rnd64(); break;
        case 1: if (len) buf[rnd(len)] ^= (unsigned char)(1u << rnd(8)); break;
        case 2: if (len > 1) len = 1 + rnd(len - 1); break;      /* truncate */
        case 3: { int add = 1 + rnd(64);                          /* grow */
                  if (len + add > cap) add = cap - len;
                  while (add-- > 0)
                      buf[len++] = (unsigned char)rnd64();
                  break; }
        case 4: { int s = rnd(nseeds);                            /* splice */
                  int off = len ? rnd(len) : 0;
                  int n = seedlen[s]; if (off + n > cap) n = cap - off;
                  if (n > 0) { memcpy(buf + off, seeds[s], n);
                               if (off + n > len) len = off + n; } break; }
        case 5: if (len) { int off = rnd(len), n = 1 + rnd(len - off);
                  memset(buf + off, 0, n); } break;
        case 6: if (len) { int off = rnd(len), n = 1 + rnd(len - off);
                  memset(buf + off, 0xFF, n); } break;
        case 7: if (len >= 4) {                    /* plausible length field */
                  int off = rnd(len - 3);
                  uint32_t v = (uint32_t)rnd64() & (rnd(2) ? 0xFFFFu : 0xFFFFFFFFu);
                  buf[off] = v >> 24; buf[off+1] = v >> 16;
                  buf[off+2] = v >> 8; buf[off+3] = v; } break;
        case 8: if (len) { int a = rnd(len), b = rnd(len);
                  unsigned char t = buf[a]; buf[a] = buf[b]; buf[b] = t; } break;
        }
    }
    return len;
}

/* ---- dispatch ---- */
static unsigned cb_count;
static int block_cb(void *ctx, int index, const BepBlockInfo *blk)
{
    (void)ctx; (void)index;
    cb_count += (unsigned)blk->size;
    return (cb_count & 0x3FFF) != 7;   /* occasionally abort mid-stream */
}

static void run_decoders(const unsigned char *buf, int len, FolderState *fs)
{
    { BepHello h; bep_decode_hello(buf, len, &h); }
    { BepHeader h; bep_decode_header(buf, len, &h); }
    { static BepClusterConfig cc; bep_decode_cluster_config(buf, len, &cc); }
    { static BepFileInfo fi; bep_decode_file_info(buf, len, &fi); }
    { static BepFileInfo fi; bep_decode_file_info_cb(buf, len, &fi, block_cb, NULL); }
    { BepRequest rq; bep_decode_request(buf, len, &rq); }
    { BepResponse rs; bep_decode_response(buf, len, &rs); }
    { char folder[BEP_FOLDER_ID_MAX]; int nf;
      bep_index_summary(buf, len, folder, &nf); }
    { BepIndexIter it; static BepFileInfo fi;
      char folder[BEP_FOLDER_ID_MAX];
      bep_index_iter_begin(&it, buf, len, folder);
      while (bep_index_iter_next(&it, &fi)) {}
      bep_index_iter_begin(&it, buf, len, folder);
      while (bep_index_iter_next_cb(&it, &fi, block_cb, NULL)) {} }

    index_store_decode(fs, buf, (size_t)len);

    { unsigned char id[32]; char addr[128];
      disco_parse_announce(buf, len, id, addr, sizeof(addr)); }

    { char z[512]; char host[64]; unsigned short port;
      int n = len < (int)sizeof(z) - 1 ? len : (int)sizeof(z) - 1;
      memcpy(z, buf, n); z[n] = '\0';
      disco_parse_tcp_addr(z, host, sizeof(host), &port); }

    /* framed reader over the mutant */
    { MemPipe mp = { (unsigned char *)buf, len, len, 0 };
      BepConn c; memset(&c, 0, sizeof(c));
      c.t.ctx = &mp; c.t.read = mp_read; c.t.write = mp_write;
      if (bep_conn_init(&c)) {
          BepHello h; BepHeader hdr; const unsigned char *body; int blen;
          if (rnd(2)) bep_read_hello(&c, &h);
          while (bep_read_message(&c, &hdr, &body, &blen) == 1) {
              if (blen > 0) { volatile unsigned char sink = 0; int i;
                  for (i = 0; i < blen; i += 997) sink ^= body[i]; (void)sink; }
          }
          bep_conn_free(&c);
      }
    }
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 100000;
    unsigned char *buf = malloc(FUZZ_CAP);
    FolderState *fs = malloc(sizeof(FolderState));
    long it;
    int i;

    rng_state = argc > 2 ? strtoull(argv[2], NULL, 0) : 0x1234ABCD5678EF90ULL;
    fuzz_sid = 0x5EADBEEFCAFEF00DULL;
    build_seeds();
    fprintf(stderr, "fuzz_all: %d seeds, %ld iters, rng=%llx\n",
            nseeds, iters, (unsigned long long)rng_state);

    foldstate_init(fs, "fuzzfolder", fuzz_sid);

    for (it = 0; it < iters; it++) {
        int len;
        if (rnd(8) == 0) {                       /* pure random buffer */
            len = 1 + rnd(4096);
            for (i = 0; i < len; i++) buf[i] = (unsigned char)rnd64();
        } else {
            int s = rnd(nseeds);
            len = seedlen[s];
            memcpy(buf, seeds[s], len);
            len = mutate(buf, len, FUZZ_CAP);
        }
        run_decoders(buf, len, fs);
        if ((it & 0x3FFF) == 0) {                /* reset index state sometimes */
            foldstate_free(fs);
            foldstate_init(fs, "fuzzfolder", fuzz_sid);
        }
        if ((it % 500000) == 0 && it)
            fprintf(stderr, "  ...%ld\n", it);
    }
    foldstate_free(fs);
    free(fs); free(buf);
    for (i = 0; i < nseeds; i++) free(seeds[i]);
    fprintf(stderr, "fuzz_all: done (%ld iters)\n", iters);
    return 0;
}
