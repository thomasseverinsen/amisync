/* ssl.c - AmiSSL bring-up and SSL_CTX for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * AmiSSL v5 supports the subprocess model the daemon needs: the parent opens
 * AmiSSL once with OpenAmiSSLTags() (the proven non-autoinit path from the
 * AmiSSL httpget example), and each subprocess that wants TLS calls InitAmiSSL()
 * before its first AmiSSL call and CleanupAmiSSL() before it exits. AmiSSL's
 * baserel environment then gives each task its own per-task state (its socket
 * base and errno) while sharing the one AmiSSLBase the parent opened. This is
 * what fixes the concurrency clobber of the old model, in which every process
 * ran its own OpenAmiSSLTags() over shared program globals. amisync targets
 * AmigaOS 3.x only, so the OS4 interface branches are omitted.
 *
 * AmiSSLBase / AmiSSLExtBase below are the globals the AmiSSL stub library
 * (link with -lamisslstubs) resolves against; the parent sets them once and all
 * subprocesses share them. The bsdsocket base, by contrast, IS per task and is
 * owned by the netbase module (see netbase.h) - we only borrow it here to hand
 * to AmiSSL.
 */

#include <errno.h>
#include <string.h>

#include <proto/exec.h>
#include <proto/amissl.h>
#include <proto/amisslmaster.h>

#include <amissl/amissl.h>
#include <libraries/amisslmaster.h>

#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include <SDI_compiler.h>

#define NETBASE_NO_BSDSOCKET_INLINE   /* ssl.c makes no raw socket calls */
#include "netbase.h"
#include "ssl.h"

/* Transport diagnostics, switchable into a release build with -DBEP_DIAG (or
 * the Amiga debug build) to trace exactly why a read failed. Off by default. */
#if defined(DEBUG) || defined(BEP_DIAG)
#include <openssl/err.h>
#include "log.h"
#define SSLDIAG(...) log_printf(LOG_WARN, __VA_ARGS__)
#else
#define SSLDIAG(...) ((void)0)
#endif

/* Bases referenced by the AmiSSL stubs. Shared across all subprocesses; the
 * parent (ssl_open) is the sole opener and closer. */
struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

int ssl_open(void)
{
    if (!netbase_open())
        return 0;

    if (!(AmiSSLMasterBase = OpenLibrary("amisslmaster.library",
                                         AMISSLMASTER_MIN_VERSION)))
        return 0;

    if (OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
                       AmiSSL_UsesOpenSSLStructs, FALSE,
                       AmiSSL_GetAmiSSLBase,    &AmiSSLBase,
                       AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                       AmiSSL_SocketBase,       (ULONG)netbase_get(),
                       AmiSSL_ErrNoPtr,         (ULONG)&errno,
                       TAG_DONE) != 0)
        return 0;

    /* Stop OpenSSL from registering its OPENSSL_cleanup() atexit handler. We
     * tear AmiSSL down ourselves in ssl_close() (CloseAmiSSL) during shutdown;
     * if OpenSSL's handler then also ran at C-runtime exit it would call into
     * the already-closed AmiSSL library and jump through freed state - observed
     * as a Line-A trap to low memory (PC ~0x3018, regs full of ABADF00D/D1D1
     * free-fill) immediately after "amisync exited (rc=0)". This must be the
     * first OpenSSL call so the NO_ATEXIT choice takes effect. */
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);

    /* Warm up OpenSSL's lazily-built global state here, single-threaded, in
     * the opener - BEFORE any subprocess is spawned. OpenSSL 3.x loads
     * providers and algorithm tables on first *use*, and AmiSSL guards that
     * with exec SignalSemaphores (openssl/crypto/threads_amissl.c), so
     * first-use init is safe but contended. This is a performance choice, not
     * a safety one: populating the digest and TLS provider tables once here
     * means the worker's first handshake and the scanner's first SHA-256 hit
     * warm caches instead of serialising during the busiest moment of
     * startup. Failures are non-fatal - the real users (ssl_ctx_new / SHA256)
     * report their own errors. */
    {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SSL_CTX      *warm;
        SHA256((const unsigned char *)"", 0, digest);   /* digest provider/tables */
        warm = SSL_CTX_new(TLS_method());               /* TLS + cipher providers */
        if (warm)
            SSL_CTX_free(warm);
    }

    return 1;
}

void ssl_close(void)
{
    /* CloseAmiSSL() is only valid once AmiSSL actually opened. Per the AmiSSL v5
     * SDK (README-SDK section 2) the opener's teardown is CloseAmiSSL() then
     * CloseLibrary(); we bracket it with the OpenSSL teardown the subprocess
     * model needs: OPENSSL_thread_stop() for this task's per-thread state (see
     * ssl_subtask_cleanup), then OPENSSL_cleanup() for the global state.
     *
     * OPENSSL_cleanup() is REQUIRED, not optional (A/B-tested on hardware:
     * removing it crashes the whole machine on the first run / at Ctrl-C). OpenSSL
     * 3.x builds a global default context (providers, algorithm/error tables) and
     * stores it in the resident amissl.library; its allocations come from THIS
     * process's heap, and with the atexit handler suppressed (OPENSSL_INIT_NO_ATEXIT
     * in ssl_open) this is the only thing that frees them before our heap is
     * reclaimed at exit. (A residual ~0x1078/run leak in the resident library and
     * an intermittent Guru remain - OpenSSL global state it does not fully reclaim
     * across runs - but those are far milder than running without it.) */
    if (AmiSSLBase) {
        OPENSSL_thread_stop();   /* release the opener task's own per-thread state */
        OPENSSL_cleanup();       /* then free OpenSSL's global state (required)    */
        CloseAmiSSL();
        AmiSSLBase = NULL;
        AmiSSLExtBase = NULL;
    }

    if (AmiSSLMasterBase) {
        CloseLibrary(AmiSSLMasterBase);
        AmiSSLMasterBase = NULL;
    }

    netbase_close();
}

int ssl_subtask_init(void)
{
    /* The parent must already have opened AmiSSL (ssl_open) so AmiSSLBase is
     * valid; without it the InitAmiSSL inline has no base to call through. */
    if (!AmiSSLBase)
        return 0;

    if (!netbase_open())
        return 0;

    /* Bind this task's own socket base and errno to the shared AmiSSL instance.
     * CleanupAmiSSL() in ssl_subtask_cleanup() is the per-task counterpart. */
    if (InitAmiSSL(AmiSSL_SocketBase, (ULONG)netbase_get(),
                   AmiSSL_ErrNoPtr,   (ULONG)&errno,
                   TAG_DONE) != 0) {
        netbase_close();
        return 0;
    }
    return 1;
}

void ssl_subtask_cleanup(void)
{
    /* Gate the per-task AmiSSL teardown on *this task's* own netbase
     * registration, not the shared global AmiSSLBase. AmiSSLBase is set once by
     * the parent (ssl_open) and is identical for every task, so it cannot tell
     * us whether this task ran InitAmiSSL. A successful ssl_subtask_init() opens
     * netbase immediately before InitAmiSSL and every init failure path leaves
     * netbase closed, so netbase_get() != NULL is the precise "this task has a
     * live InitAmiSSL context" predicate. Calling CleanupAmiSSL without a
     * matching InitAmiSSL tears down per-task state that was never set up - the
     * mismatch that corrupts the heap and faults a *subsequent* launch. */
    if (netbase_get()) {
        /* Release THIS task's OpenSSL per-thread state before tearing down its
         * AmiSSL context. Even though the pthread CRYPTO_THREAD_LOCAL typedefs
         * are compiled out on AmigaOS (OPENSSL_SYS_AMIGA), OpenSSL still keeps a
         * per-thread error queue / state entry in a global list that lives in the
         * shared (resident) amissl.library. If a worker exits without releasing
         * it, that entry dangles - referencing the worker's now-freed task/heap -
         * and a later allocation, OPENSSL_cleanup, or the next program launch
         * frees against freed memory: the intermittent illegal-instruction /
         * Line-F Guru on a *subsequent* launch. DO NOT REMOVE: the call looks
         * off-model (the pthread typedefs are compiled out), and because the
         * crash it prevents (#8000000B) surfaces only on a LATER launch after a
         * TLS session, its absence is easy to misattribute - it was once
         * removed on exactly that reasoning and cost a long Guru hunt. */
        OPENSSL_thread_stop();
        CleanupAmiSSL(TAG_DONE);
    }
    netbase_close();
}

/* X.509 verify callback. Syncthing does not validate certificates against a
 * CA: trust is decided after the handshake by matching the peer cert's derived
 * device ID against the configured peer list. So we accept any certificate at
 * this layer by always returning 1. SAVEDS STDARGS because AmiSSL calls back
 * across the library boundary. */
SAVEDS STDARGS static int accept_any_cert(int preverify_ok, X509_STORE_CTX *ctx)
{
    (void)preverify_ok;
    (void)ctx;
    return 1;
}

SSL_CTX *ssl_ctx_new(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());

    if (!ctx)
        return NULL;

    /* v1 forces TLS 1.3 (OQ-3: relax to 1.2 later only if a peer needs it). */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Prefer ChaCha20-Poly1305. This is a 68k program: the cpu has no AES
     * instructions, and measured on an A4000/68060 (tools/ssl_bench) AES-GCM
     * runs at ~220 KB/s against ChaCha20's ~382 KB/s - 1.7x, worth 20% off a
     * real transfer end to end (2 MB from Syncthing: 20s -> 16s).
     *
     * Ordering rather than restricting. In TLS 1.3 the SERVER picks the suite
     * and we are usually the one dialling, so a client-side preference looks
     * like it should be ignored - but the official Syncthing client honours
     * it. Measured against Syncthing v2.1.3: with the default list we were
     * given AES-128-GCM, and with this list we are given ChaCha20, same peer,
     * same build otherwise. Two amisync nodes agree on ChaCha too.
     *
     * (The likely mechanism, though this is inference and not something we
     * verified in its source: Syncthing is a Go program, and Go's TLS server
     * prefers AES-GCM only when its own cpu has AES instructions AND the
     * client also asked for AES-GCM first. A client that leads with ChaCha is
     * taken at its word. Either way the behaviour above is what we measured.)
     *
     * So expressing a preference is enough, and offering ONLY ChaCha is not
     * needed - that would lock out a peer that lacks it and would leave TLS
     * 1.3's one mandatory suite unoffered for a speed number. The AES suites
     * stay listed behind: such a peer still connects, just slower. */
    SSL_CTX_set_ciphersuites(ctx, "TLS_CHACHA20_POLY1305_SHA256:"
                                  "TLS_AES_128_GCM_SHA256:"
                                  "TLS_AES_256_GCM_SHA384");

    /* Request a peer cert and run our accept-any callback; the real identity
     * check (device-ID pinning) happens after the handshake. ALPN (bep/1.0)
     * and our own cert/key are attached by the handshake path below. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       accept_any_cert);

    return ctx;
}

void ssl_ctx_free(SSL_CTX *ctx)
{
    if (ctx)
        SSL_CTX_free(ctx);
}

/* ---- handshake path -------------------------------------------- */

/* The single ALPN protocol we speak, in TLS wire form: one length byte
 * followed by the protocol name. */
static const unsigned char ALPN_BEP[] = { 7, 'b', 'e', 'p', '/', '1', '.', '0' };

int ssl_ctx_use_identity(SSL_CTX *ctx, const char *cert_pem, const char *key_pem)
{
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
        return 0;
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
        return 0;
    if (SSL_CTX_check_private_key(ctx) != 1)
        return 0;
    return 1;
}

/* Server-side ALPN selection: pick "bep/1.0" if the client offered it, else
 * fail the handshake. SAVEDS STDARGS because AmiSSL calls back across the
 * library boundary. */
SAVEDS STDARGS static int alpn_select(SSL *ssl,
                                      const unsigned char **out, unsigned char *outlen,
                                      const unsigned char *in, unsigned int inlen,
                                      void *arg)
{
    (void)ssl;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              ALPN_BEP, sizeof(ALPN_BEP),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

int ssl_ctx_set_alpn_bep(SSL_CTX *ctx)
{
    /* Client side advertises the list (returns 0 on success - inverted). */
    if (SSL_CTX_set_alpn_protos(ctx, ALPN_BEP, sizeof(ALPN_BEP)) != 0)
        return 0;
    /* Server side selects from the client's list. */
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    return 1;
}

/* Shared handshake driver: wrap the socket and run accept/connect. */
static SSL *do_handshake(SSL_CTX *ctx, int sock, int server)
{
    SSL *ssl = SSL_new(ctx);
    int  rc;

    if (!ssl)
        return NULL;

    if (SSL_set_fd(ssl, sock) != 1) {
        SSL_free(ssl);
        return NULL;
    }

    /* On our blocking socket, let SSL_read transparently process records that
     * carry no application data - notably TLS 1.3 post-handshake messages
     * (NewSessionTicket, KeyUpdate) that Syncthing sends right after connect -
     * instead of bubbling SSL_ERROR_WANT_READ up to the caller as a spurious
     * read error. */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    rc = server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (rc != 1) {
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

SSL *ssl_client(SSL_CTX *ctx, int sock)
{
    return do_handshake(ctx, sock, 0);
}

SSL *ssl_server(SSL_CTX *ctx, int sock)
{
    return do_handshake(ctx, sock, 1);
}

int ssl_get_peer_cert_der(SSL *ssl, unsigned char *buf, int cap)
{
    X509          *cert = SSL_get_peer_certificate(ssl);
    unsigned char *der  = NULL;
    int            len;

    if (!cert)
        return 0;

    len = i2d_X509(cert, &der);
    if (len > 0 && len <= cap)
        memcpy(buf, der, len);
    else
        len = 0;

    OPENSSL_free(der);
    X509_free(cert);
    return len;
}

int ssl_get_alpn(SSL *ssl, char *buf, int cap)
{
    const unsigned char *proto = NULL;
    unsigned int         len   = 0;

    SSL_get0_alpn_selected(ssl, &proto, &len);
    if (!proto || len == 0 || (int)len >= cap)
        return 0;

    memcpy(buf, proto, len);
    buf[len] = '\0';
    return 1;
}

int ssl_buffered(SSL *ssl)
{
    /* SSL_has_pending: any buffered received data, processed or not;
     * SSL_pending: already-decrypted bytes. Either means a socket-level
     * select/WaitSelect would sleep through data we could read right now. */
    return SSL_has_pending(ssl) || SSL_pending(ssl) > 0;
}

int ssl_read(SSL *ssl, void *buf, int len)
{
    for (;;) {
        int n = SSL_read(ssl, buf, len);
        int e;
        if (n > 0)
            return n;
        e = SSL_get_error(ssl, n);
        switch (e) {
        case SSL_ERROR_ZERO_RETURN:        /* peer sent a clean close_notify */
            return 0;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            /* Two very different things arrive here. Normally the record
             * produced no application data yet (e.g. a TLS 1.3 post-handshake
             * message) and retrying is right: belt-and-suspenders alongside
             * SSL_MODE_AUTO_RETRY, and on our blocking socket the retry waits
             * for the next record rather than spinning.
             *
             * But netbase_open() sets SBTC_BREAKMASK to SIGBREAKF_CTRL_F
             * (== WORKER_SIG_STOP) precisely so a read parked in here aborts
             * on shutdown - and bsdsocket signals that abort by failing the
             * read with EINTR, which OpenSSL classifies as retryable and
             * reports as WANT_READ. Retrying it walks straight back into the
             * same blocking read and throws away the only mechanism that can
             * end it: either we spin at 100% CPU or the stop is swallowed and
             * the worker never exits, hanging the daemon's shutdown join.
             * Distinguish them by the signal, not the errno - SetSignal(0,0)
             * reads without consuming, so the worker's own loop still sees it. */
            if (SetSignal(0L, 0L) & SIGBREAKF_CTRL_F)
                return -1;
            continue;
        default:
            SSLDIAG("ssl_read: n=%d SSL_get_error=%d errno=%d ossl=0x%08lx",
                    n, e, errno, (unsigned long)ERR_peek_last_error());
            return -1;
        }
    }
}

int ssl_write(SSL *ssl, const void *buf, int len)
{
    int n = SSL_write(ssl, buf, len);
    if (n > 0)
        return n;
    SSLDIAG("ssl_write: n=%d SSL_get_error=%d errno=%d ossl=0x%08lx",
            n, SSL_get_error(ssl, n), errno,
            (unsigned long)ERR_peek_last_error());
    return -1;
}

void ssl_free(SSL *ssl)
{
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}
