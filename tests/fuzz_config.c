/* fuzz_config.c - mutation fuzzer for config_load (the INI parser)
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host under ASan/UBSan (see `make fuzz`).
 * config.c reads through fopen, so each iteration writes the mutant to a
 * temp file (tmpfs when available) and loads it over fresh defaults.
 *
 * Usage: fuzz_config [iterations] [rng-seed]. Baseline: a 300k-iteration
 * campaign has run clean.
 */

#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* config.c warns through log_printf; the fuzzer wants silence. */
void log_printf(LogLevel level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

static uint64_t rng_state = 0xBEEF1234CAFE5678ULL;
static uint64_t rnd64(void)
{
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return rng_state = x;
}
static uint32_t rnd(uint32_t n) { return n ? (uint32_t)(rnd64() % n) : 0; }

static const char seed[] =
    "; amisync config\n"
    "logfile    = T:amisync.log\n"
    "loglevel   = debug\n"
    "seriallog  = yes\n"
    "rexxport   = AMISYNC\n"
    "certfile   = ENVARC:Amisync/cert.pem\n"
    "keyfile    = ENVARC:Amisync/key.pem\n"
    "devicename = amiga4000\n"
    "statedir   = ENVARC:Amisync/state\n"
    "keepdeletes = 180\n"
    "listenport = 22000\n"
    "discovery  = yes\n"
    "peer = P56IOI7-MZJNU2Y-IQGDREY-DM2MGTI-MGL3BXN-PQ6W5BM-TBBZ4TJ-XZWICQ2"
    " 192.168.1.10 22000\n"
    "folder = docs SYS:Docs sendreceive\n"
    "folder = pics Work:Pics sendonly\n"
    "[future-section]\n"
    "unknownkey = whatever\n";

int main(int argc, char **argv)
{
    long        iters = argc > 1 ? atol(argv[1]) : 50000;
    const char *path  = "/dev/shm/amisync_fuzz.conf";
    char        buf[8192];
    Config     *cfg = malloc(sizeof(Config));
    FILE       *probe;
    long        it;

    if (argc > 2) rng_state = strtoull(argv[2], NULL, 0);

    /* prefer tmpfs; fall back to the build dir */
    probe = fopen(path, "wb");
    if (!probe) path = "build/amisync_fuzz.conf";
    else fclose(probe);

    for (it = 0; it < iters; it++) {
        FILE *f;
        int   len;
        if (rnd(8) == 0) {                     /* pure random */
            len = rnd(2048);
            for (int i = 0; i < len; i++) buf[i] = (char)rnd64();
        } else {                               /* mutate the seed */
            len = (int)sizeof(seed) - 1;
            memcpy(buf, seed, len);
            int nm = 1 + rnd(12);
            while (nm--) {
                switch (rnd(6)) {
                case 0: buf[rnd(len)] = (char)rnd64(); break;
                case 1: buf[rnd(len)] ^= (char)(1 << rnd(8)); break;
                case 2: if (len > 1) len = 1 + rnd(len - 1); break;
                case 3: { int add = rnd(700);
                          while (add-- > 0 && len < (int)sizeof(buf) - 1)
                              buf[len++] = (char)rnd64();
                          break; }
                case 4: { int off = rnd(len), n = 1 + rnd(len - off);
                          memset(buf + off, rnd(2) ? ' ' : '=', n); break; }
                case 5: { int n = 300 + rnd(2000);   /* very long line */
                          if (len + n < (int)sizeof(buf)) {
                              memset(buf + len, 'A' + rnd(26), n);
                              len += n; buf[len++] = '\n';
                          }
                          break; }
                }
            }
        }
        f = fopen(path, "wb");
        if (!f) { fprintf(stderr, "fuzz_config: cannot write %s\n", path); return 1; }
        fwrite(buf, 1, len, f);
        fclose(f);
        config_defaults(cfg);
        config_load(path, cfg);
        if ((it % 100000) == 0 && it) fprintf(stderr, "  ...%ld\n", it);
    }
    free(cfg);
    remove(path);
    fprintf(stderr, "fuzz_config: done (%ld iters)\n", iters);
    return 0;
}
