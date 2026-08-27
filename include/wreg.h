/* wreg.h - registry of live sync-worker tasks, for broadcast signalling
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * This module closes the loop between the daemon's state changes and the
 * connected workers. A worker only re-evaluates its peer on its ~60 s idle
 * tick, so anything that changes shared state underneath it - the scanner
 * advancing a folder's sequence, a runtime folder add/remove, a peer table
 * edit - needs to wake it now. There is no true exec "broadcast", so each
 * worker registers its task here while it is in its connected loop, and the
 * changing party signals every registered task at once.
 *
 * AmigaOS has a single address space, so a small static table shared by all
 * tasks works (the same shape as the netbase registry). Access is bracketed with
 * Forbid()/Permit() - add/remove/signal are all short, pointer-only operations,
 * so no semaphore is needed and there is nothing to initialise.
 */

#ifndef AMISYNC_WREG_H
#define AMISYNC_WREG_H

/* Register / unregister the CALLING task (FindTask(NULL)). A worker calls
 * wreg_add() on entering its connected loop and wreg_remove() on leaving it.
 * Both are idempotent and safe if the table is full (the worker simply won't be
 * woken early, falling back to its idle tick) - the table holds 64 tasks,
 * four times CONFIG_MAX_PEERS, so that is a safety net and not a live path. */
void wreg_add(void);
void wreg_remove(void);

/* Signal every registered task with 'sigmask': the scanner after a scan
 * advanced a folder's sequence, the daemon and peer manager after a runtime
 * folder or peer change. In practice that is always WORKER_SIG_RESCAN
 * (worker.h), which workers already read as "re-evaluate and announce now" -
 * which is why no new signal was needed. This module neither knows nor cares
 * which mask it carries. */
void wreg_signal(unsigned long sigmask);

#endif /* AMISYNC_WREG_H */
