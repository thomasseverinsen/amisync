/* ssl_bench.c - price the symmetric crypto on the machine it runs on
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * amisync moves every byte through TLS, and on a 68k with no AES instructions
 * the cipher is a plausible reason a transfer is slower than the disk and the
 * network under it. That is a claim worth measuring rather than asserting, and
 * measuring it inside the daemon means separating it from round trips, block
 * writes and index traffic. So: a standalone timing of the primitives, on the
 * target, with nothing else in the way.
 *
 * Reports MB/s for AES-128-GCM and AES-256-GCM (what a peer typically selects
 * for us - in TLS 1.3 the SERVER chooses, and Go chooses by whether ITS OWN cpu
 * has AES instructions, so an Amiga dialling an x86 gets AES picked by the
 * machine that finds AES cheap), ChaCha20-Poly1305 (the usual answer for a cpu
 * without AES), and SHA-256.
 *
 * SHA-256 is the calibration line, not filler: amisync verifies every arriving
 * block against the peer's hash, and that cost was measured in situ on the
 * A4000 at about 930 KB/s. If this tool disagrees wildly with that, distrust
 * the tool before the daemon.
 *
 *   ssl_bench [megabytes]        (default 4)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

#include "ssl.h"

const char stack_size[] = "$STACK:32768";

#define CHUNK  (64L * 1024L)      /* one pass unit; keeps buffers modest */

/* Milliseconds since midnight, from DateStamp's 1/50s ticks. Wraps at midnight;
 * a run that straddles it reports nonsense rather than lying subtly - the
 * elapsed value goes negative and is reported as such. */
static long now_ms(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return ds.ds_Minute * 60000L + (ds.ds_Tick * 1000L) / TICKS_PER_SECOND;
}

static void report(const char *what, long ms, long bytes)
{
    long kb = bytes / 1024;
    if (ms <= 0) {
        printf("  %-22s %ld KB in %ld ms (too fast to time)\n", what, kb, ms);
        return;
    }
    /* KB/s without floating point: kb * 1000 / ms. */
    printf("  %-22s %ld KB in %ld ms = %ld KB/s\n", what, kb, ms, (kb * 1000L) / ms);
}

static void bench_cipher(const char *name, const EVP_CIPHER *c,
                         unsigned char *buf, unsigned char *out, long passes)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char   key[32], iv[12];
    long            i, t0, t1;
    int             outl;

    if (!c) {
        printf("  %-22s not available in this AmiSSL\n", name);
        return;
    }
    memset(key, 0x5a, sizeof(key));
    memset(iv,  0x21, sizeof(iv));

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("  %-22s EVP_CIPHER_CTX_new failed\n", name);
        return;
    }

    t0 = now_ms();
    for (i = 0; i < passes; i++) {
        /* Re-init per pass: that is what a TLS record does too, so the setup
         * cost belongs in the number rather than being amortised away. */
        if (!EVP_EncryptInit_ex(ctx, c, NULL, key, iv) ||
            !EVP_EncryptUpdate(ctx, out, &outl, buf, (int)CHUNK)) {
            printf("  %-22s EVP failed on pass %ld\n", name, i);
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
    }
    t1 = now_ms();

    EVP_CIPHER_CTX_free(ctx);
    report(name, t1 - t0, passes * CHUNK);
}

static void bench_sha256(unsigned char *buf, long passes)
{
    unsigned char md[32];
    unsigned int  mdlen;
    long          i, t0, t1;
    EVP_MD_CTX   *ctx;

    t0 = now_ms();
    for (i = 0; i < passes; i++) {
        if (!(ctx = EVP_MD_CTX_new()))
            break;
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, buf, (size_t)CHUNK);
        EVP_DigestFinal_ex(ctx, md, &mdlen);
        EVP_MD_CTX_free(ctx);
    }
    t1 = now_ms();
    report("SHA-256", t1 - t0, passes * CHUNK);
}

int main(int argc, char **argv)
{
    unsigned char *buf, *out;
    long           mb = 4, passes;

    if (argc > 1) {
        mb = atol(argv[1]);
        if (mb < 1 || mb > 64)
            mb = 4;
    }
    passes = (mb * 1024L * 1024L) / CHUNK;

    if (!ssl_open()) {
        printf("ssl_open() failed (AmiSSL/bsdsocket not available?)\n");
        ssl_close();
        return RETURN_ERROR;
    }

    buf = malloc(CHUNK);
    out = malloc(CHUNK + 64);          /* room for any block-cipher slack */
    if (!buf || !out) {
        printf("out of memory\n");
        free(buf); free(out);
        ssl_close();
        return RETURN_ERROR;
    }
    memset(buf, 0xa5, CHUNK);

    printf("ssl_bench: %ld MB per primitive, %ld KiB chunks\n\n", mb, CHUNK / 1024);

    bench_cipher("AES-128-GCM", EVP_aes_128_gcm(), buf, out, passes);
    bench_cipher("AES-256-GCM", EVP_aes_256_gcm(), buf, out, passes);
    bench_cipher("ChaCha20-Poly1305", EVP_chacha20_poly1305(), buf, out, passes);
    bench_sha256(buf, passes);

    printf("\nFor scale: amisync's per-block SHA-256 verify was measured in\n"
           "situ on the A4000 at about 930 KB/s. A cipher line far above the\n"
           "observed transfer rate means the cipher is not what you are\n"
           "waiting on.\n");

    free(buf);
    free(out);
    ssl_close();
    return RETURN_OK;
}
