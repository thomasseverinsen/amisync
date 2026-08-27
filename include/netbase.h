/* netbase.h - per-task bsdsocket.library base for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * AmigaOS has a single address space, so an ordinary C global such as the
 * classic `struct Library *SocketBase' is shared by every task in the program.
 * But bsdsocket.library must be opened *per task* - each opener gets its own
 * base, bound to that task's sockets - so a shared global is wrong the moment
 * two networking tasks run at once: whoever opened last wins, and the others
 * make socket calls through a base that is not theirs (this is exactly the
 * concurrency Guru seen when the inbound listener ran alongside a dialer).
 *
 * This module keeps each task's own base in a small registry keyed by the task
 * pointer. The bsdsocket inlines are pointed at it through BSDSOCKET_BASE_NAME
 * (defined below), so every socket() / recv() / WaitSelect() resolves the
 * *calling* task's base at the call site.
 *
 * A file that makes socket calls includes THIS header instead of
 * <proto/bsdsocket.h>; the order matters, so include it before anything that
 * might pull the bsdsocket inlines in. A file that only needs the open/close
 * API (and no socket calls) can define NETBASE_NO_BSDSOCKET_INLINE first.
 */

#ifndef AMISYNC_NETBASE_H
#define AMISYNC_NETBASE_H

#include <exec/libraries.h>     /* struct Library, in all three signatures */

/* Open bsdsocket.library v4 for the calling task and record it as that task's
 * base. Returns the base on success, NULL on failure (on failure nothing is
 * registered and any opened library is closed again). Call once per networking
 * task, before any socket call. */
struct Library *netbase_open(void);

/* Unregister and close the calling task's bsdsocket base. Safe to call when the
 * task has none registered (no-op). */
void netbase_close(void);

/* The calling task's registered bsdsocket base, or NULL if it has none. This is
 * what the bsdsocket inlines resolve through and what we hand to AmiSSL. */
struct Library *netbase_get(void);

/* This only redirects inlines pulled in AFTER this point: a file that reached
 * <proto/bsdsocket.h> first keeps the shared-global base and reproduces the
 * concurrency Guru above - silently, and only under load. Include netbase.h
 * before any other bsdsocket include. Nothing can check this for you. */
#ifndef NETBASE_NO_BSDSOCKET_INLINE
#define BSDSOCKET_BASE_NAME (netbase_get())
#include <proto/bsdsocket.h>
#endif

#endif /* AMISYNC_NETBASE_H */
