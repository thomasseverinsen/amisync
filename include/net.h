/* net.h - TCP socket helpers over bsdsocket for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Thin, blocking-by-default TCP helpers built on bsdsocket.library. Each
 * process that uses these must have opened bsdsocket first (ssl_open() does
 * that and binds this task's errno). The returned descriptors are bsdsocket
 * sockets: close them with net_close() (CloseSocket), never the DOS Close().
 *
 * The TLS path hands these sockets to AmiSSL via SSL_set_fd(); connect/accept
 * leave the socket in blocking mode so SSL_read/SSL_write behave simply, while
 * net_wait() lets a worker block on "socket readable OR an exec signal" so it
 * can still react to CTRL-C or an IPC message while idle.
 */

#ifndef AMISYNC_NET_H
#define AMISYNC_NET_H

#define NET_INVALID_SOCKET  (-1)

/* bsdsocket's Errno() reports the classic BSD socket error numbers, which are
 * NOT the same as the C library's <errno.h> values. They are spelled out here,
 * with the fixed bsdsocket-ABI numbering (see ndk sys/errno.h), so every module
 * that has to read a socket error compares against the same constants
 * regardless of which errno.h the toolchain picks. Macros only: including this
 * header for them adds no link dependency on net.c. */
#define NET_EPIPE           32
#define NET_EWOULDBLOCK     35
#define NET_EINPROGRESS     36
#define NET_ENETRESET       52
#define NET_ECONNABORTED    53
#define NET_ECONNRESET      54
#define NET_ENOTCONN        57
#define NET_ETIMEDOUT       60

/* True when 'e' means the connection was torn down under us - by the peer, by
 * a middlebox, or by the stack giving up on it - rather than something either
 * end got wrong at the protocol level. See the read path in bep.c. */
#define NET_ERR_IS_RESET(e) \
    ((e) == NET_ECONNRESET   || (e) == NET_ECONNABORTED || \
     (e) == NET_EPIPE        || (e) == NET_ENOTCONN     || \
     (e) == NET_ENETRESET    || (e) == NET_ETIMEDOUT)

/* Connect a TCP socket to host:port, abandoning the attempt after
 * timeout_secs (0 = no timeout: wait as long as the connect takes). 'host' may
 * be a dotted quad or a hostname. Returns a blocking socket, or
 * NET_INVALID_SOCKET on failure. */
int  net_connect(const char *host, unsigned short port, int timeout_secs);

/* Create a listening TCP socket bound to INADDR_ANY:port (SO_REUSEADDR set).
 * Returns the listening socket or NET_INVALID_SOCKET. */
int  net_listen(unsigned short port, int backlog);

/* Accept one inbound connection from a listening socket. If 'peer_ip' is
 * non-NULL, the peer's dotted-quad address is written there (up to
 * peer_ip_len bytes, NUL-terminated when peer_ip_len > 0). Returns the accepted
 * (blocking) socket or NET_INVALID_SOCKET. */
int  net_accept(int lsock, char *peer_ip, int peer_ip_len);

/* Block until 'sock' is readable or one of the exec signals in 'extra_sigs'
 * fires, up to timeout_secs (0 = wait forever). If 'got_sigs' is non-NULL it
 * receives the signals that fired. Returns 1 if the socket is readable or a
 * wanted signal fired, 0 on timeout, -1 on error. */
int  net_wait(int sock, int timeout_secs, unsigned long extra_sigs,
              unsigned long *got_sigs);

/* Disable Nagle (TCP_NODELAY) on a connected socket. Best-effort, no return. */
void net_set_nodelay(int sock);

/* Best-effort SO_RCVBUF/SO_SNDBUF grow toward 'bytes'; a stack that clamps or
 * rejects the size just keeps its default. */
void net_set_buffers(int sock, int bytes);

/* Close a socket from this module. NET_INVALID_SOCKET is ignored. */
void net_close(int sock);

#endif /* AMISYNC_NET_H */
