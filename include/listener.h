/* listener.h - inbound BEP listener for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Accepts inbound TLS/BEP connections. The listener runs in its own process:
 * it binds the configured port, and for each accepted socket it detaches the
 * socket (ReleaseSocket) and spawns an inbound worker that re-adopts it
 * (ObtainSocket), does the TLS handshake, checks the peer's device ID against
 * the configured peer list, and runs the BEP session. The listener supervises
 * those inbound workers and joins them on shutdown.
 *
 * Threading: the listener and every inbound worker is its own process. Each
 * owns its bsdsocket base (netbase) and shares the one AmiSSL instance via
 * ssl_subtask_init, which is what lets them run alongside the dialer workers.
 */

#ifndef AMISYNC_LISTENER_H
#define AMISYNC_LISTENER_H

#include "config.h"
#include "foldstate.h"

typedef struct ListenerHandle ListenerHandle;

/* Start the listener if cfg->listen_port is non-zero; returns NULL if disabled
 * or on failure (the daemon then runs dial-only). 'folders' is the shared
 * per-folder index (length cfg->num_folders), handed to each inbound worker. */
ListenerHandle *listener_start(const Config *cfg, FolderState *folders);

/* Ask the listener's inbound workers to rescan their folders now. NULL-safe. */
void listener_rescan(ListenerHandle *h);

/* Signal the listener (and its inbound workers), wait for them, free. NULL-safe. */
void listener_stop(ListenerHandle *h);

/* CreateNewProc entry point (pass as NP_Entry). */
void listener_entry(void);

#endif /* AMISYNC_LISTENER_H */
