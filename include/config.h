/* config.h - configuration loading for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_CONFIG_H
#define AMISYNC_CONFIG_H

#include "device_id.h"

#define CONFIG_PATH_DEFAULT  "S:amisync.conf"

/* The ARexx port name the daemon publishes. config_rexx_port() exists so the
 * pre-detach copy can agree with the daemon on this, so both must default to
 * the same string - hence one definition. */
#define CONFIG_REXX_PORT_DEFAULT  "AMISYNC"
#define CONFIG_LOGFILE_MAX   128
#define CONFIG_PORTNAME_MAX   32
#define CONFIG_PATH_MAX      128
#define CONFIG_NAME_MAX       64
#define CONFIG_HOST_MAX       64
#define CONFIG_FOLDER_ID_MAX  64
#define CONFIG_MAX_PEERS      16
#define CONFIG_MAX_FOLDERS     8
#define CONFIG_DEFAULT_PORT   22000   /* Syncthing's default BEP TCP port */

/* A configured peer: its device ID (for pinning) and where to dial it.
 *
 * The two volatile fields are RUNTIME state, never read from the file. The
 * whole daemon shares one address space, and cfg->peers[] is the one
 * per-peer structure every task can reach (the peer manager, the dial
 * workers, the listener's inbound workers), so pause state and the live
 * inbound connection are published here:
 *  - 'paused' is owned by the peer manager; workers in both directions
 *    check it (a paused peer is neither dialled nor accepted).
 *  - 'inbound_st' is the connected inbound worker's WorkerStartup (or
 *    NULL), set/cleared by that worker inside Forbid(); readers must also
 *    bracket the load+dereference with Forbid(), because the listener
 *    frees the block in its own task after the worker clears the pointer.
 *    While set, the peer's dialer stands down instead of hammering the
 *    peer with duplicate connections it will reject. */
typedef struct {
    char           id[DEVICE_ID_BUFSZ];
    char           host[CONFIG_HOST_MAX];
    unsigned short port;
    volatile int   paused;
    /* Removed at runtime. The slot is TOMBSTONED, never compacted: workers
     * hold pointers into this array, so entries must not move. A removed
     * peer is skipped by status/dialing, refused like a paused one, drops
     * out of peer_manager_has (so discovery re-lists the device as
     * unconfigured), and peer_manager_add resurrects the slot on re-add. */
    volatile int   removed;
    /* volatile qualifies the POINTER: that is the shared datum. Declared via
     * the struct tag (worker.h defines it, and includes this header) so the
     * compiler type-checks the stores several tasks read back. */
    struct WorkerStartup * volatile inbound_st;
    /* The last session with this peer ended still owing us files: it dropped
     * the tail of an oversized index and asked to be re-dialled for the rest.
     * Shared, so it survives the session that set it and covers EITHER
     * direction - the connection that batches is as often the peer's inbound
     * one as our own dial. Status uses it to keep saying "Syncing" across the
     * reconnect, where there is no worker and so nothing to count. Cleared by
     * any session that ends without a remainder, and by a dial that never
     * connected, so a peer that has gone away stops claiming to be busy. */
    volatile int   resyncing;
    /* Block bytes moved by FINISHED inbound sessions with this peer. The peer
     * manager's PeerSlot totals only ever see the workers it spawns and reaps
     * itself - an inbound worker belongs to the listener, which has no slot -
     * so without these a peer that dials US reported no traffic at all, live
     * or afterwards, however many megabytes it moved. Written by the
     * listener's reap paths as each session ends, read by peer_xfer_info. */
    volatile unsigned long long in_bytes_in;
    volatile unsigned long long in_bytes_out;
} ConfigPeer;

/* Folder sync direction. The wire values match BEP's FolderType enum, so they
 * map straight onto Folder.type when we build a ClusterConfig. */
typedef enum {
    FOLDER_SENDRECEIVE = 0,
    FOLDER_SENDONLY    = 1,
    FOLDER_RECEIVEONLY = 2
} FolderMode;

/* A configured folder to share. 'path' is the local AmigaOS directory.
 * 'removed' and 'gen' are RUNTIME state (never read from the file), shared
 * across tasks like ConfigPeer's: a removed folder's slot is TOMBSTONED,
 * never compacted (workers index folders by position), and 'gen' bumps on
 * every (re)add so a connected worker knows to reset that folder's announce
 * cursor. See Config.config_gen for how workers learn of changes at all. */
typedef struct {
    char           id[CONFIG_FOLDER_ID_MAX];
    char           label[CONFIG_NAME_MAX];
    char           path[CONFIG_PATH_MAX];
    FolderMode     mode;
    volatile int   removed;
    volatile int   gen;
} ConfigFolder;

/* Daemon-wide configuration: logging/control, identity, networking, and the
 * peer and folder tables. */
typedef struct {
    char logfile[CONFIG_LOGFILE_MAX];    /* path for the log file         */
    char rexx_port[CONFIG_PORTNAME_MAX]; /* ARexx public port name        */
    int  log_level;                      /* LogLevel threshold (0..3)     */
    int  log_max_kb;                     /* log size cap, KB (0 = none)   */

    char cert_path[CONFIG_PATH_MAX];     /* our identity certificate      */
    char key_path[CONFIG_PATH_MAX];      /* our identity private key      */
    char statedir[CONFIG_PATH_MAX];      /* persisted index directory    */
    int  keep_deletes;                   /* tombstone retention, days     */
    char device_name[CONFIG_NAME_MAX];   /* this node's BEP device name   */
    unsigned short listen_port;          /* inbound BEP port (0 = none)   */
    int  discovery;                      /* 1 = broadcast local discovery */
    int  serial_log;                     /* 1 = tee the log to the serial
                                            debug port (WinUAE/kprintf)   */
    int  appicon;                        /* 1 = status AppIcon on the WB
                                            backdrop (default on)         */
    int  versioning;                     /* 1 = keep the replaced/deleted
                                            copy in .stversions (default off) */
    int  tz_offset_s;                    /* seconds EAST of UTC this machine's
                                            clock is set to (+7200 = CEST)   */
    int  tz_offset_set;                  /* 1 = 'tzoffset' gave a number, which
                                            stands EVEN at +00:00 - "this clock
                                            keeps UTC" is an answer, not the
                                            absence of one                    */
    int  tz_from_locale;                 /* 1 = 'tzoffset = locale': ask
                                            locale.library at startup         */

    int          num_peers;
    ConfigPeer   peers[CONFIG_MAX_PEERS];

    int          num_folders;
    ConfigFolder folders[CONFIG_MAX_FOLDERS];

    /* RUNTIME: bumped (under Forbid) whenever the folder set changes at
     * runtime. A connected worker snapshots it and, on a mismatch at its
     * loop top, re-sends its ClusterConfig in-band and resets the announce
     * cursor of each folder whose ConfigFolder.gen moved. */
    volatile int config_gen;
} Config;

/* Populate 'cfg' with built-in defaults. Always succeeds. */
void config_defaults(Config *cfg);

/* Load INI-style settings from 'path' on top of the current contents of
 * 'cfg' (call config_defaults() first). Missing file is not an error:
 * returns 1 if loaded, 0 if the file was absent or unreadable (defaults
 * are left intact in that case). */
int  config_load(const char *path, Config *cfg);

/* Insert a "peer = <id> [<host>:<port>]" line (plus a "; added at runtime:"
 * note) into the Peers section of the config at 'path' - after the last
 * peer-ish line, or at the end for a config that has none - so a peer added at
 * runtime survives a restart. Temp-file rewrite with a restore path; the
 * user's comments and layout are preserved. 'host' NULL/"" writes an ID-only
 * line (address via discovery). Returns 1 on success, 0 if the file could not
 * be written. */
int  config_append_peer(const char *path, const char *id, const char *host,
                        unsigned short port);

/* Remove the active "peer = <id> ..." line(s) for 'id' (dash differences
 * ignored) from the config at 'path', along with an immediately preceding
 * "; added at runtime:" note line. Temp-file rewrite with a restore path,
 * like the insert - a failure cannot corrupt the config. Returns 1 if a
 * line was removed, 0 if none matched or on I/O trouble. */
int  config_remove_peer(const char *path, const char *id);

/* The folder-line siblings of the peer pair above, with the same contracts:
 * append inserts "folder = <id> <path> <mode>" (plus the runtime note) after
 * the last folder-ish line so it lands in the Folders section; remove strips
 * the active line(s) for 'id' (exact id match) and a preceding note. */
int  config_append_folder(const char *path, const char *id,
                          const char *fpath, FolderMode mode,
                          const char *label);   /* NULL/"" = no label token */
int  config_remove_folder(const char *path, const char *id);

/* Read ONLY the rexxport value from 'path' into 'out' (cap bytes), defaulting
 * to "AMISYNC" when unset or the file is absent. Lightweight (no peer/folder
 * parsing, no big Config) so the pre-detach copy can check for an already-
 * running instance by ARexx port name without loading the whole config. */
void config_rexx_port(const char *path, char *out, int cap);

#endif /* AMISYNC_CONFIG_H */
