/* wreg.c - registry of live sync-worker tasks, for broadcast signalling
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See wreg.h. A fixed table of task pointers, guarded by Forbid()/Permit().
 * Sized well above the real worker count (CONFIG_MAX_PEERS dialers + a handful
 * of inbound workers); an overflow just means a worker isn't woken early.
 */

#include <exec/types.h>
#include <exec/tasks.h>

#include <proto/exec.h>

#include "wreg.h"

#define WREG_MAX 64

static struct Task *wreg_tasks[WREG_MAX];   /* BSS: starts all-NULL */

void wreg_add(void)
{
    struct Task *me = FindTask(NULL);
    int          i, spare = -1;

    Forbid();
    for (i = 0; i < WREG_MAX; i++) {
        if (wreg_tasks[i] == me) { Permit(); return; }   /* already registered */
        if (wreg_tasks[i] == NULL && spare < 0)
            spare = i;
    }
    if (spare >= 0)
        wreg_tasks[spare] = me;
    Permit();
}

void wreg_remove(void)
{
    struct Task *me = FindTask(NULL);
    int          i;

    Forbid();
    for (i = 0; i < WREG_MAX; i++) {
        if (wreg_tasks[i] == me) {
            wreg_tasks[i] = NULL;
            break;
        }
    }
    Permit();
}

void wreg_signal(unsigned long sigmask)
{
    int i;

    Forbid();
    for (i = 0; i < WREG_MAX; i++) {
        if (wreg_tasks[i])
            Signal(wreg_tasks[i], sigmask);
    }
    Permit();
}
