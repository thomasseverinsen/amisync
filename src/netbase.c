/* netbase.c - per-task bsdsocket.library base registry for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See netbase.h for the why. The registry is a small fixed table of
 * {task, base} pairs, sized from the peer cap so it cannot fall behind it:
 * the worst case is main + one dial worker per peer + the listener + its
 * inbound workers + discovery.
 *
 * Concurrency: open/close search for and mutate a slot, so they run under
 * Forbid() (cheap - just a dispatch-disable nest count, with no I/O inside the
 * critical section; OpenLibrary/CloseLibrary are done outside it). netbase_get()
 * only ever reads the caller's own slot, which only the caller writes, and
 * 32-bit pointer stores on 68k are atomic, so it needs no locking - keeping the
 * per-socket-call hot path free of Forbid().
 */

#include <dos/dos.h>            /* SIGBREAKF_CTRL_F */
#include <proto/exec.h>

/* This file makes exactly one socket call - SocketBaseTags() in netbase_open()
 * to set the per-task break mask - so it takes the bsdsocket inline (resolved
 * through the calling task's base via netbase_get(), like every other module),
 * rather than defining NETBASE_NO_BSDSOCKET_INLINE. */
#include "netbase.h"
#include "config.h"     /* CONFIG_MAX_PEERS sizes the table */

#define NETBASE_MAX (CONFIG_MAX_PEERS * 2)

static struct {
    struct Task    *task;
    struct Library *base;
} slots[NETBASE_MAX];

struct Library *netbase_open(void)
{
    struct Library *base, *old = NULL;
    struct Task    *me;
    int             i, slot = -1;

    base = OpenLibrary("bsdsocket.library", 4);
    if (!base)
        return NULL;

    me = FindTask(NULL);

    Forbid();
    for (i = 0; i < NETBASE_MAX; i++) {
        if (slots[i].task == me) {          /* already registered: replace */
            slot = i;
            old  = slots[i].base;           /* its open count is ours to drop */
            break;
        }
        if (slot < 0 && !slots[i].task)     /* remember first free slot */
            slot = i;
    }
    if (slot >= 0) {
        slots[slot].base = base;            /* ordering is belt-and-braces: */
        slots[slot].task = me;              /* Permit() is what publishes   */
    }
    Permit();

    if (old && old != base)                 /* outside Forbid: it can wait */
        CloseLibrary(old);

    if (slot < 0) {                         /* registry full */
        CloseLibrary(base);
        return NULL;
    }

    /* Make blocking socket calls (recv/WaitSelect, and hence a read parked
     * inside SSL_read) abort when the shutdown signal is posted, so a worker
     * sitting on a quiet long-lived connection drops out promptly on
     * WORKER_SIG_STOP instead of blocking until the peer next sends. The mask
     * is CTRL-F to match WORKER_SIG_STOP (worker.h). The slot is registered
     * now, so the inline resolves this call to our just-opened base. Best-
     * effort: a stack without the tag simply keeps non-interruptible reads. */
    SocketBaseTags(SBTM_SETVAL(SBTC_BREAKMASK), SIGBREAKF_CTRL_F, TAG_END);

    return base;
}

void netbase_close(void)
{
    struct Task    *me   = FindTask(NULL);
    struct Library *base = NULL;
    int             i;

    Forbid();
    for (i = 0; i < NETBASE_MAX; i++) {
        if (slots[i].task == me) {
            base = slots[i].base;
            slots[i].task = NULL;           /* ordering is belt-and-braces */
            slots[i].base = NULL;           /* here too; see netbase_open  */
            break;
        }
    }
    Permit();

    if (base)
        CloseLibrary(base);
}

struct Library *netbase_get(void)
{
    struct Task *me = FindTask(NULL);
    int          i;

    for (i = 0; i < NETBASE_MAX; i++)
        if (slots[i].task == me)
            return slots[i].base;
    return NULL;
}
