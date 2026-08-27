/* arexx.h - ARexx control port for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_AREXX_H
#define AMISYNC_AREXX_H

#include "config.h"
#include "disco.h"     /* DiscoSeenList for the DISCOVERED verb  */
#include "foldstate.h" /* FolderState for the STATUS folder stats */

/* Result of dispatching the pending ARexx messages. */
typedef enum {
    AREXX_OK = 0,   /* messages handled, keep running */
    AREXX_QUIT      /* a QUIT command was received    */
} ArexxResult;

/* Opaque ARexx port context. */
typedef struct ArexxPort ArexxPort;

typedef struct PeerManager    PeerManager;
typedef struct ListenerHandle ListenerHandle;
typedef struct ScannerHandle  ScannerHandle;

/* Live daemon state the command handlers read/act on. The daemon fills this in
 * each loop iteration and passes it to arexx_dispatch. 'pm' and 'listener' may
 * be NULL (peering or listening disabled). */
typedef struct {
    const Config        *cfg;
    Config              *cfg_rw;  /* same Config, writable: the runtime folder
                                   * ops (daemon_folder_add/remove) mutate the
                                   * shared table through it */
    PeerManager         *pm;
    ListenerHandle      *listener;
    ScannerHandle       *scanner; /* the folder scanner (RESCAN pokes it)    */
    const DiscoSeenList *seen;    /* unconfigured devices seen on the LAN   */
    FolderState         *folders; /* shared index, [cfg->num_folders]; NULLable */
    const char          *our_id;  /* our device ID text ("" if no identity)  */
    long                 start_day;  /* daemon start DateStamp, for uptime   */
    long                 start_min;
} ArexxContext;

/* Create a public ARexx message port with the given name (e.g. "AMISYNC").
 * Returns NULL if a port of that name already exists or on allocation
 * failure. */
ArexxPort  *arexx_open(const char *portname);

/* Tear down the port, replying to any messages still queued. Safe on NULL. */
void        arexx_close(ArexxPort *ap);

/* Signal mask (1L << port->mp_SigBit) for use in the daemon's Wait().
 * Returns 0 if 'ap' is NULL. */
unsigned long arexx_signal(const ArexxPort *ap);

/* Drain and reply to all queued messages, executing their commands against the
 * daemon state in 'ctx' (which may be NULL for control-only use). Returns
 * AREXX_QUIT if a QUIT was seen, otherwise AREXX_OK. */
ArexxResult arexx_dispatch(ArexxPort *ap, const ArexxContext *ctx);

/* Buffer every caller of arexx_build_status must provide. The report grows
 * with the configuration: at the caps (CONFIG_MAX_FOLDERS folders of three
 * lines each, CONFIG_MAX_PEERS peers of two) the body runs past 4 KB, and it
 * is assembled by an append helper that truncates silently - so a 2048-byte
 * buffer did not corrupt anything, it just cut the report off, and what fell
 * off the end was the trailing "Discovered" and "Offered" sections: the only
 * place a user is told a peer wants to share a folder with them. Sized with
 * room to spare; it is a stack buffer on tasks that hold 128 KB. */
#define AREXX_STATUS_MAX  8192

/* Build the human-readable STATUS report into 'buf' (cap bytes, normally
 * AREXX_STATUS_MAX). Shared by the ARexx STATUS verb and the AppIcon fallback
 * requester. The status window does NOT render this text - it builds its own
 * list model from the daemon state (statuswin.c). */
void arexx_build_status(const ArexxContext *ctx, char *buf, int cap);

/* Small formatting helpers the STATUS report and the status window share
 * (defined in arexx.c). mode_str: static label for a FolderMode, never NULL;
 * fmt_size: "1.7 MB" binary sizes with the classic KB/MB labels; fmt_dur:
 * "3m" / "4h 36m" / "2d 5h"; mins_since: minutes elapsed since a DateStamp
 * (day, min), clamped at 0. Both fmt_* buffers must hold at least 24 bytes. */
const char *arexx_mode_str(FolderMode m);
void        arexx_fmt_size(unsigned long long b, char *out);
void        arexx_fmt_dur(long mins, char *out);
long        arexx_mins_since(long day, long min);

#endif /* AMISYNC_AREXX_H */
