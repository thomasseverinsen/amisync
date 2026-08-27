/* net.c - TCP socket helpers over bsdsocket for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See net.h. Note: we deliberately do NOT include <sys/time.h> - the
 * toolchain's copy has a broken 'struct timespec' member and won't compile.
 * bsdsocket's own headers supply the 'struct timeval' WaitSelect needs, and we
 * cast it to the prototype's 'struct __timeval *' at the call site - as we cast
 * the fd_sets to the APTR the same prototype declares. m68k is
 * big-endian, so htons()/htonl() are identities here, but we use them for
 * clarity and portability of intent.
 */

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <netinet/in.h>
#include <netdb.h>

#include "netbase.h"     /* pulls in <proto/bsdsocket.h> bound to this task's base */

#ifndef INADDR_NONE               /* inet_addr()'s failure value */
#define INADDR_NONE  ((in_addr_t)-1)
#endif

#include "net.h"

/* bsdsocket's Errno() reports the classic BSD socket error numbers, which are
 * NOT the same as the C library's <errno.h> values. We define just the two we
 * test for, with the fixed bsdsocket-ABI numbering (see ndk sys/errno.h), so
 * the comparison is correct regardless of which errno.h the toolchain picks. */
#define NET_EWOULDBLOCK  35
#define NET_EINPROGRESS  36

/* TCP_NODELAY lives in <netinet/tcp.h>, which the toolchain's headers make
 * awkward to include here; its BSD-ABI value is a stable 1. IPPROTO_TCP comes
 * from <netinet/in.h> (included above). */
#ifndef TCP_NODELAY
#define TCP_NODELAY  1
#endif

/* Resolve 'host' (dotted quad or name) into an in_addr. Returns 1 on success. */
static int resolve(const char *host, struct in_addr *out)
{
    in_addr_t       ip;
    struct hostent *he;

    ip = inet_addr((STRPTR)host);
    if (ip != INADDR_NONE) {            /* already a dotted quad */
        out->s_addr = ip;
        return 1;
    }

    he = gethostbyname((STRPTR)host);
    if (!he || !he->h_addr_list || !he->h_addr_list[0] ||
        he->h_length != (int)sizeof(struct in_addr))
        return 0;

    memcpy(&out->s_addr, he->h_addr_list[0], sizeof(out->s_addr));
    return 1;
}

static int net_set_blocking(int sock, int blocking)
{
    long nb = blocking ? 0 : 1;
    return IoctlSocket(sock, FIONBIO, &nb) == 0;
}

/* Wait for readability (writable==0) or writability (writable==1) on 'sock',
 * also waking on any exec signal in 'extra'. Returns 1 ready/signalled, 0 on
 * timeout, -1 on error. */
static int wait_io(int sock, int writable, int timeout_secs,
                   unsigned long extra, unsigned long *got)
{
    fd_set         fds;
    struct timeval tv;
    unsigned long  sigs = extra;
    long           rc;

    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec  = timeout_secs;
    tv.tv_usec = 0;

    rc = WaitSelect(sock + 1,
                    writable ? NULL : (APTR)&fds,
                    writable ? (APTR)&fds : NULL,
                    NULL,
                    timeout_secs > 0 ? (struct __timeval *)(void *)&tv : NULL,
                    extra ? &sigs : NULL);

    if (got)
        *got = sigs;
    if (rc < 0)
        return -1;
    if (extra && (sigs & extra))
        return 1;
    if (FD_ISSET(sock, &fds))
        return 1;
    return 0;                           /* timed out */
}

int net_wait(int sock, int timeout_secs, unsigned long extra_sigs,
             unsigned long *got_sigs)
{
    return wait_io(sock, 0, timeout_secs, extra_sigs, got_sigs);
}

int net_connect(const char *host, unsigned short port, int timeout_secs)
{
    struct in_addr     addr;
    struct sockaddr_in sa;
    int                s;

    if (!resolve(host, &addr))
        return NET_INVALID_SOCKET;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return NET_INVALID_SOCKET;

    /* Non-blocking connect so a dead peer can't wedge the worker forever. */
    if (!net_set_blocking(s, 0))
        goto fail;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr   = addr;

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = Errno();
        if (e != NET_EINPROGRESS && e != NET_EWOULDBLOCK)
            goto fail;
        /* Connection is in progress: wait for the socket to become writable,
         * or for a stop. SIGBREAKF_CTRL_F is WORKER_SIG_STOP (the same value
         * netbase_open hands bsdsocket as its break mask); taking it here is
         * what stops a dial to a dead host from holding shutdown for the full
         * connect timeout. The signal is reported, not consumed, so the
         * caller's own loop still sees it - we just stop waiting. */
        {
            unsigned long got = 0;
            if (wait_io(s, 1, timeout_secs, SIGBREAKF_CTRL_F, &got) != 1 ||
                (got & SIGBREAKF_CTRL_F))
                goto fail;
        }
        /* Writable can also mean "failed" - confirm via SO_ERROR. */
        {
            int       soerr = 0;
            socklen_t len   = sizeof(soerr);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0 ||
                soerr != 0)
                goto fail;
        }
    }

    if (!net_set_blocking(s, 1))
        goto fail;
    return s;

fail:
    CloseSocket(s);
    return NET_INVALID_SOCKET;
}

void net_set_nodelay(int sock)
{
    int on = 1;
    /* Disable Nagle: amisync's block fetch is request/response, so coalescing
     * tiny Requests only adds round-trip latency (Nagle vs the peer's delayed
     * ACKs). Best-effort. */
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

void net_set_buffers(int sock, int bytes)
{
    /* Grow the socket buffers toward 'bytes'. Amiga stacks default to a few
     * KB, which caps the pipelined block window (WK_WINDOW x up-to-128 KiB
     * Responses in flight) far below the link's capacity. Best-effort: a
     * stack that clamps or rejects the size just leaves its default. */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

int net_listen(unsigned short port, int backlog)
{
    struct sockaddr_in sa;
    int                s, on = 1;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return NET_INVALID_SOCKET;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(s, backlog) < 0) {
        CloseSocket(s);
        return NET_INVALID_SOCKET;
    }
    return s;
}

int net_accept(int lsock, char *peer_ip, int peer_ip_len)
{
    struct sockaddr_in sa;
    socklen_t          len = sizeof(sa);
    int                s;

    s = accept(lsock, (struct sockaddr *)&sa, &len);
    if (s < 0)
        return NET_INVALID_SOCKET;

    if (peer_ip && peer_ip_len > 0) {
        STRPTR dotted = Inet_NtoA(sa.sin_addr.s_addr);
        if (dotted) {
            strncpy(peer_ip, (char *)dotted, peer_ip_len - 1);
            peer_ip[peer_ip_len - 1] = '\0';
        } else {
            peer_ip[0] = '\0';
        }
    }
    return s;
}

void net_close(int sock)
{
    if (sock != NET_INVALID_SOCKET)
        CloseSocket(sock);
}
