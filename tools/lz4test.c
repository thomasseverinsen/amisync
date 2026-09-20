/* lz4test.c - round-trip LZ4 with no network, to isolate a compressor hang
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Prints a line before every step and flushes it, so the last line on screen
 * names what was running if the machine stops. Build with
 * -DLZ4_FORCE_SW_BITCOUNT for a variant without the 68020 BFFFO instruction.
 */

#include <stdio.h>
#include <string.h>

#include <exec/memory.h>
#include <proto/exec.h>

#include "lz4.h"

#define ROUNDS 20

static const char ver[] = "$VER: lz4test 1.0 (18.09.2026)";

int main(void)
{
    static const int lens[] = { 1500, 20000, 60000, 70000 };
    int   cap = 128 * 1024, r, i, k, bad = 0;
    char *src = AllocVec(cap, MEMF_ANY);
    char *cmp = AllocVec(cap, MEMF_ANY);
    char *out = AllocVec(cap, MEMF_ANY);

    if (!src || !cmp || !out) {
        printf("out of memory\n");
        return 20;
    }
#ifdef LZ4_FORCE_SW_BITCOUNT
    printf("lz4test (software bit count, no BFFFO)\n");
#else
    printf("lz4test (BFFFO)\n");
#endif
    printf("buffers at %p %p %p\n", (void *)src, (void *)cmp, (void *)out);
    fflush(stdout);

    for (r = 1; r <= ROUNDS && !bad; r++) {
        for (i = 0; i < 4 && !bad; i++) {
            int len = lens[i], c, d;

            for (k = 0; k < len; k++)
                src[k] = (char)((k * 7 + (k >> 5) + r) % 61);
            printf("round %2d: compress %5d ... ", r, len);
            fflush(stdout);
            c = LZ4_compress_default(src, cmp, len, cap);
            printf("%5d, decompress ... ", c);
            fflush(stdout);
            d = c > 0 ? LZ4_decompress_safe(cmp, out, c, cap) : -1;
            if (d != len || memcmp(src, out, len) != 0) {
                printf("MISMATCH (got %d)\n", d);
                bad = 1;
            } else {
                printf("ok\n");
            }
            fflush(stdout);
        }
    }
    printf(bad ? "FAILED\n" : "all %d rounds ok\n", ROUNDS);
    FreeVec(src); FreeVec(cmp); FreeVec(out);
    (void)ver;
    return bad ? 10 : 0;
}
