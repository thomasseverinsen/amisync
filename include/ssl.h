/* ssl.h - AmiSSL bring-up and SSL_CTX for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * AmiSSL v5's subprocess model: the PARENT (the daemon's main process, or a
 * standalone tool that is its own only process) opens AmiSSL once with
 * ssl_open() and closes it with ssl_close(). Each SUBPROCESS that wants TLS
 * (a per-peer worker, the discovery broadcaster) instead calls ssl_subtask_init()
 * on entry and ssl_subtask_cleanup() on exit - it shares the parent's AmiSSL
 * instance but binds its own per-task socket base and errno. A subprocess that
 * needs sockets but not TLS (the listener) skips AmiSSL entirely and uses the
 * netbase module directly.
 *
 * The per-task bsdsocket base lives in the netbase module (netbase.h); this
 * module owns only the AmiSSL bases the stub library links against. Link this
 * module, netbase, and -lamisslstubs into any binary that opens AmiSSL.
 */

#ifndef AMISYNC_SSL_H
#define AMISYNC_SSL_H

#include <openssl/ssl.h>

/* PARENT/standalone: open this task's bsdsocket base and the shared AmiSSL
 * instance (amisslmaster + OpenAmiSSLTags), wiring AmiSSL to this task's errno.
 * Returns 1 on success, 0 on failure (ssl_close() is still safe afterwards).
 * Call exactly once, before any SSL/crypto use and before spawning subprocesses
 * that will share the AmiSSL instance. */
int ssl_open(void);

/* PARENT/standalone: close the shared AmiSSL instance and this task's bsdsocket
 * base. Safe even if ssl_open() failed or was never called; idempotent. Call
 * only after every subprocess sharing the instance has exited. */
void ssl_close(void);

/* SUBPROCESS: open this task's own bsdsocket base and bind it (plus this task's
 * errno) to the AmiSSL instance the parent already opened. Returns 1 on success,
 * 0 on failure (including if the parent has not opened AmiSSL). Call once on
 * entry, before any socket or SSL/crypto use. */
int ssl_subtask_init(void);

/* SUBPROCESS: unbind from the AmiSSL instance and close this task's bsdsocket
 * base. Safe to call even if ssl_subtask_init() failed; idempotent. */
void ssl_subtask_cleanup(void);

/* Create an SSL_CTX carrying the Syncthing trust model that is independent of
 * the local identity: TLS 1.3 floor and a verify callback that accepts any
 * presented certificate at the X.509 layer (device-ID pinning is done after
 * the handshake, not by the CA machinery). The peer's ALPN and our own
 * cert/key are attached later, by the handshake path. Returns NULL on failure.
 * Requires ssl_open() to have succeeded in this process. */
SSL_CTX *ssl_ctx_new(void);

/* Free an SSL_CTX from ssl_ctx_new(). NULL is ignored. */
void ssl_ctx_free(SSL_CTX *ctx);

/* ---- handshake path -------------------------------------------- */

/* Load this device's identity (cert.pem + key.pem, as written by
 * amisync-genid) into the context, and confirm the key matches the cert. In
 * Syncthing every node presents its own cert as both client and server, so the
 * same context is used in either direction. Returns 1 on success, 0 on
 * failure. */
int ssl_ctx_use_identity(SSL_CTX *ctx, const char *cert_pem, const char *key_pem);

/* Configure ALPN for BEP ("bep/1.0") on the context, for both roles: the
 * client-side advertised list and the server-side selection callback are both
 * set, so one context works whether we dial or accept. Returns 1 on success. */
int ssl_ctx_set_alpn_bep(SSL_CTX *ctx);

/* Run a TLS handshake over an already-connected socket (from the net module),
 * as the client (ssl_client) or the server (ssl_server). On success returns a
 * connected SSL object; on failure returns NULL (the caller still owns and
 * closes the socket). The socket should be in blocking mode. */
SSL *ssl_client(SSL_CTX *ctx, int sock);
SSL *ssl_server(SSL_CTX *ctx, int sock);

/* Copy the peer's certificate in DER form into 'buf' (capacity 'cap'),
 * returning its length, or 0 if there is no peer cert or it does not fit. The
 * caller derives the peer's device ID from this (device_id_from_cert_der) to
 * check it against the configured peer list - this module stays free of the
 * device_id dependency. */
int ssl_get_peer_cert_der(SSL *ssl, unsigned char *buf, int cap);

/* Copy the ALPN protocol the handshake negotiated into 'buf' (NUL-terminated,
 * capacity 'cap'). Returns 1 if a protocol was negotiated AND fits, 0
 * otherwise. */
int ssl_get_alpn(SSL *ssl, char *buf, int cap);

/* ---- session I/O ----------------------------------------------- */

/* Blocking read/write over the TLS session. ssl_read returns the number of
 * bytes read (>0), 0 on a clean peer shutdown, or -1 on error. ssl_write is
 * all-or-nothing (partial writes are not enabled): it returns 'len' or -1. */
int ssl_read(SSL *ssl, void *buf, int len);
int ssl_write(SSL *ssl, const void *buf, int len);

/* True if the TLS layer already holds received data (decrypted or raw) that a
 * socket-level select/WaitSelect cannot see. Check before blocking in a wait:
 * TLS records do not align with message boundaries, so a record's tail can
 * carry the start of the next message. */
int ssl_buffered(SSL *ssl);

/* Cleanly shut down and free an SSL object. NULL is ignored. The underlying
 * socket is not closed (the caller owns it). */
void ssl_free(SSL *ssl);

#endif /* AMISYNC_SSL_H */
