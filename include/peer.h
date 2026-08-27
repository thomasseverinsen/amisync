/* peer.h - main-side peer table and worker supervision for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The peer manager lives in the main process. It spawns one dialer worker per
 * configured peer, listens (via an exec reply port) for workers finishing, and
 * re-dials with exponential backoff. On shutdown it signals every live worker
 * and waits for them all to reply before returning.
 *
 * The daemon's wait loop folds peer_manager_sigmask() into its Wait() mask and
 * calls peer_manager_handle() whenever that signal fires.
 *
 * The table it manages (cfg->peers[]) is SHARED with the listener's inbound
 * workers, which read and write ConfigPeer.paused/removed/inbound_st (see
 * config.h) - which is why slots are tombstoned rather than compacted, and why
 * peer_info's 'connected' consults the inbound side too.
 *
 * Naming: peer_manager_* acts on the table (create/start/shutdown, add,
 * remove); peer_* acts on one peer or aggregates across peers (pause, rescan,
 * queries). peer_manager_status is the one exception, kept for its history.
 */

#ifndef AMISYNC_PEER_H
#define AMISYNC_PEER_H

#include "config.h"       /* peer_info returns a const ConfigPeer * */

/* Passed through to the workers, never dereferenced here - a forward
 * declaration keeps the whole index model out of peer.h's includers. */
typedef struct FolderState FolderState;

typedef struct PeerManager PeerManager;

/* Create the manager (allocates an exec reply port). 'cfg' must outlive the
 * manager - its strings are handed to workers by pointer, and its peer table
 * is extended in place by peer_manager_add. 'folders' is the shared
 * per-folder index array (length cfg->num_folders), also handed to each
 * worker by pointer; may be NULL only when there are no folders. Returns NULL
 * on failure. */
PeerManager  *peer_manager_create(Config *cfg, FolderState *folders);

/* The reply-port signal bit to add to the daemon's Wait() mask. */
unsigned long peer_manager_sigmask(PeerManager *pm);

/* Spawn the initial dialer for every configured peer. */
void          peer_manager_start(PeerManager *pm);

/* Drain finished workers from the reply port and re-dial as needed. Call when
 * peer_manager_sigmask() fires. */
void          peer_manager_handle(PeerManager *pm);

/* Re-dial peers left without a worker by a failed spawn (out of memory). Call
 * periodically - the daemon does it on the status tick; nothing else would
 * recover such a slot, since the manager is otherwise driven by worker
 * replies. No-op for peers that are paused, removed or awaiting discovery. */
void          peer_manager_retry(PeerManager *pm);

/* Stop all workers, wait for them to finish, and free the manager. */
void          peer_manager_shutdown(PeerManager *pm);

/* ---- status / control (ARexx port, status window) ------------------ */

/* Number of peer SLOTS, tombstones included - the iteration bound, not a live
 * peer count. Walk 0..peer_count-1 and skip the slots peer_info NULLs out. */
int           peer_count(PeerManager *pm);

/* Aggregate one-line sync status across all dial workers into 'out' (cap):
 * "Up to Date" / "Syncing (N files)" / "Offline" / "No peers configured".
 * The optional out-params report the connected-worker count and the total
 * pending fetch backlog. Cheap live read - call it as often as needed. */
void          peer_manager_status(PeerManager *pm, char *out, int cap,
                                  int *out_connected, int *out_pending);

/* Live fetch backlog from peer 'i': files queued plus in flight on its worker
 * (the same per-worker counter peer_manager_status aggregates). 0 when the
 * peer is disconnected or idle - so with a connection up, 0 means "we have
 * everything this peer announced": its per-device "up to date". */
int           peer_pending(PeerManager *pm, int i);

/* Live fetch backlog for folder 'fidx' (config slot index), summed across
 * every connected worker, dial and inbound: the status window's
 * per-folder "Syncing (N files)". 0 = nothing queued for that folder. */
int           peer_folder_pending(PeerManager *pm, int fidx);

/* Files in folder 'fidx' that a peer has deleted and we are keeping because
 * our version won. Not a backlog - there is nothing to fetch - but the peer
 * counts us out of sync for every one of them until a human resolves it. */
int           peer_folder_kept(PeerManager *pm, int fidx);

/* Local edits in this folder that a peer's copy has replaced (receive-only).
 * SUMMED across workers, unlike the two above: a revert is performed once, by
 * the worker that fetched the replacement, so the counts never overlap. */
int           peer_folder_reverted(PeerManager *pm, int fidx);

/* Status of peer 'i' (0..peer_count-1): returns its ConfigPeer (id) and, via the
 * out params, whether a worker is running, whether it has reached the
 * BEP-connected state, whether it is paused, and its effective dial address
 * (host may be "" for a peer still awaiting discovery). Any out param may be
 * NULL. Returns NULL if 'i' is out of range OR its slot has been removed. */
const ConfigPeer *peer_info(PeerManager *pm, int i, int *running, int *connected,
                            int *paused, const char **host, unsigned short *port);

/* Transfer totals and Hello identity for peer 'i': block bytes received/sent
 * across all of its connections since daemon start, and the device/client
 * names from its Hello ("" until it has connected once). Any out param may
 * be NULL; all are defaulted (0 / "") when pm is NULL or 'i' out of range. */
void          peer_xfer_info(PeerManager *pm, int i,
                             unsigned long long *in_bytes,
                             unsigned long long *out_bytes,
                             const char **rname, const char **rclient);

/* Pause / resume peering. 'id' NULL (or "") affects all peers; otherwise the
 * one matching device ID. Pausing stops a running worker and suppresses
 * re-dialling; resuming dials an idle peer that has an address. Returns the
 * number of peers MATCHED, which for 'id' NULL is every live peer - not the
 * number whose state actually changed. */
int           peer_pause(PeerManager *pm, const char *id);
int           peer_resume(PeerManager *pm, const char *id);

/* Ask every live worker to rescan its folders now. */
void          peer_rescan(PeerManager *pm);

/* ---- runtime peer-table changes (main task only) ------------------- */

/* Local discovery found 'id' at 'host:port'. If 'id' is a configured peer,
 * update its dial address and (if idle) dial it now. Ignored otherwise (no
 * auto-accept). */
void          peer_manager_discovered(PeerManager *pm, const char *id,
                                      const char *host, unsigned short port);

/* Add a peer at RUNTIME (ARexx ADDPEER / Tools-menu "Add Discovered"): append
 * it to cfg's peer table, grow a slot and - when an address is known - dial it
 * immediately. 'host' may be NULL/"" for an ID-only peer found later via
 * discovery; port 0 means the default BEP port. In-memory only - the caller
 * persists it with config_append_peer if wanted.
 * Returns: 1 added, 0 invalid device ID, -1 already configured,
 * -2 table full, -3 internal slot/config mismatch (logged; should not
 * happen). */
int           peer_manager_add(PeerManager *pm, const char *id,
                               const char *host, unsigned short port);

/* 1 if 'id' (any dash/case form) is already a configured peer. Removed
 * peers do not count - so local discovery re-lists such a device as
 * unconfigured, where it can be added again. */
int           peer_manager_has(PeerManager *pm, const char *id);

/* Remove peer 'id' at runtime: its slot is tombstoned (never compacted -
 * workers hold pointers into the table), its workers stop, connections in
 * both directions are refused from now on, and it drops out of status and
 * peer_manager_has. peer_manager_add resurrects the slot on a later re-add.
 * The config file line is the caller's business (config_remove_peer).
 * Returns 1 if a peer was removed, 0 if not found. */
int           peer_manager_remove(PeerManager *pm, const char *id);

#endif /* AMISYNC_PEER_H */
