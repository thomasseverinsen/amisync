/* ssl_selftest.c - M2 runtime check for the ssl bring-up
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A tiny standalone program for the Amiga/UAE target: it opens AmiSSL and
 * bsdsocket via the ssl module, creates an SSL_CTX, makes and frees an SSL
 * object from it, then tears everything down. Run it on the target with the
 * AmiSSL/bsdsocket stack installed; a clean exit (RETURN_OK) means the
 * per-process bring-up works end to end. This cannot be validated on the
 * cross-compiler - only that it links.
 *
 *   ssl_selftest
 */

#include <errno.h>
#include <stdio.h>

#include <dos/dos.h>
#include <exec/memory.h>
#include <proto/exec.h>

#include "ssl.h"

const char stack_size[] = "$STACK:16384";

/* What TLS costs, stage by stage. amisync's own footprint on an A4000 measured
 * 6.3 MB with two folders and two peers, of which only about a third was the
 * index - the rest had to be found before deciding whether shrinking any
 * structure is worth doing. Printing the free-RAM delta around each bring-up
 * step is the cheapest way to find out, and this program already performs
 * exactly those steps in order.
 *
 * AvailMem(MEMF_FAST) rather than total: chip RAM is untouched here, and on a
 * machine with no fast RAM at all the answer is "does not apply" anyway.
 * LARGEST is printed alongside because a big free total made of small holes is
 * not the same thing on AmigaOS - an allocation this size wants one run. */
static ULONG mem_free(void)
{
    return AvailMem(MEMF_FAST);
}

static ULONG mem_largest(void)
{
    return AvailMem(MEMF_FAST | MEMF_LARGEST);
}

static void mem_report(const char *what, ULONG before)
{
    ULONG now = mem_free();
    long  used = (long)before - (long)now;

    printf("  %-24s %+8ld bytes   (free %lu, largest %lu)\n",
           what, used, (unsigned long)now, (unsigned long)mem_largest());
}

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int rc = RETURN_ERROR;
    ULONG m0, m1, m2, m3;

    m0 = mem_free();
    printf("fast RAM free at start: %lu (largest %lu)\n\n",
           (unsigned long)m0, (unsigned long)mem_largest());

    if (!ssl_open()) {
        printf("ssl_open() failed (AmiSSL/bsdsocket not available?)\n");
        ssl_close();
        return RETURN_ERROR;
    }
    printf("ssl_open() ok; errno wired at %p (= %d)\n", (void *)&errno, errno);
    mem_report("ssl_open()", m0);
    m1 = mem_free();

    if (!(ctx = ssl_ctx_new())) {
        printf("ssl_ctx_new() failed\n");
        ssl_close();
        return RETURN_ERROR;
    }
    printf("ssl_ctx_new() ok (TLS 1.3, accept-any verify)\n");
    mem_report("ssl_ctx_new()", m1);
    m2 = mem_free();

    /* Prove the context is usable by spinning up and freeing one SSL object. */
    if ((ssl = SSL_new(ctx)) != NULL) {
        mem_report("SSL_new()", m2);
        m3 = mem_free();
        SSL_free(ssl);
        mem_report("SSL_free() returned", m3);
        printf("SSL_new()/SSL_free() ok\n");
        rc = RETURN_OK;
    } else {
        printf("SSL_new() failed\n");
    }

    ssl_ctx_free(ctx);
    ssl_close();
    printf("\nafter teardown: free %lu (largest %lu) - started at %lu\n",
           (unsigned long)mem_free(), (unsigned long)mem_largest(),
           (unsigned long)m0);

    printf(rc == RETURN_OK ? "ssl selftest passed\n" : "ssl selftest FAILED\n");
    return rc;
}
