/* arexx.c - ARexx control port for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Commands (case-insensitive), e.g. from an ARexx script:
 *     address AMISYNC 'STATUS'   ; say result
 *     address AMISYNC 'RESCAN'
 *     address AMISYNC 'QUIT'
 * STATUS/VERSION/HELP return text in RESULT (the caller must have set
 * OPTIONS RESULTS). rexxsyslib.library is opened for CreateArgstring(); if it
 * is unavailable the commands still run, they just cannot return a string.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <exec/ports.h>
#include <dos/dos.h>
#include <rexx/errors.h>
#include <rexx/storage.h>
#include <rexx/rxslib.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/rexxsyslib.h>

#include "arexx.h"
#include "daemon.h"
#include "offered.h"
#include "peer.h"
#include "listener.h"
#include "scanner.h"
#include "version.h"
#include "log.h"

#define AREXX_NAME_MAX 32

/* Library base for CreateArgstring/DeleteArgstring (rexxsyslib inlines resolve
 * against this global). Best-effort: NULL means "cannot return RESULT". */
struct RxsLib *RexxSysBase;

struct ArexxPort {
    struct MsgPort *port;
    char            name[AREXX_NAME_MAX];
};

/* Compare the first whitespace-delimited token of 'cmd' against 'word',
 * case-insensitively. Lets "QUIT", "quit", "Quit  \n" all match. */
static int first_token_is(const char *cmd, const char *word)
{
    if (!cmd)
        return 0;
    while (*cmd && isspace((unsigned char)*cmd))
        cmd++;
    while (*word) {
        if (tolower((unsigned char)*cmd) != tolower((unsigned char)*word))
            return 0;
        cmd++; word++;
    }
    return *cmd == '\0' || isspace((unsigned char)*cmd);
}

/* Advance to the start of the 'idx'th whitespace-delimited token of 'cmd'
 * (0 = the verb), or to the NUL if there is none. */
static const char *token_start(const char *cmd, int idx)
{
    if (!cmd)
        return "";
    while (*cmd && isspace((unsigned char)*cmd)) cmd++;   /* leading space */
    while (idx-- > 0) {                                   /* skip tokens   */
        while (*cmd && !isspace((unsigned char)*cmd)) cmd++;
        while (*cmd && isspace((unsigned char)*cmd)) cmd++;
    }
    return cmd;
}

/* Copy the 'idx'th whitespace-delimited token of 'cmd' into 'out'. Returns 1
 * only if the WHOLE token fit; a token too long for 'out' reports 0 with 'out'
 * cleared, exactly like an absent one.
 *
 * Truncating instead was quietly destructive. The buffers here are sized to
 * the config fields, so daemon_folder_add's "id/path too long" rejection could
 * never fire on this path - it only ever saw an already-shortened string. An
 * over-long ADDFOLDER path did not fail: folder_ensure_dir CREATED a drawer at
 * the 127-character prefix and the scanner started syncing it, reply "added".
 * Refusing a token we cannot represent is the only answer that does not act on
 * something the caller did not ask for. */
static int token_at(const char *cmd, int idx, char *out, int cap)
{
    const char *p = token_start(cmd, idx);
    int         n = 0;

    out[0] = '\0';
    while (*p && !isspace((unsigned char)*p)) {
        if (n >= cap - 1) {                    /* does not fit: not usable */
            out[0] = '\0';
            return 0;
        }
        out[n++] = *p++;
    }
    out[n] = '\0';
    return n > 0;
}

/* Is there an 'idx'th token at all, whatever its length? token_at cannot say -
 * it reports a token that does not fit as absent, which is right for a value
 * we would otherwise mangle, but wrong for deciding whether the caller
 * supplied something we simply failed to understand. */
static int token_present(const char *cmd, int idx)
{
    return *token_start(cmd, idx) != '\0';
}

/* The command argument: the second whitespace-delimited token. */
static int second_token(const char *cmd, char *out, int cap)
{
    return token_at(cmd, 1, out, cap);
}

/* Map a level name to a LogLevel; returns 1 on success. */
static int level_from_name(const char *s, LogLevel *out)
{
    if (strcasecmp(s, "debug") == 0)      *out = LOG_DEBUG;
    else if (strcasecmp(s, "info") == 0)  *out = LOG_INFO;
    else if (strcasecmp(s, "warn") == 0)  *out = LOG_WARN;
    else if (strcasecmp(s, "error") == 0) *out = LOG_ERROR;
    else return 0;
    return 1;
}

static const char *level_name(LogLevel l)
{
    switch (l) {
    case LOG_DEBUG: return "debug";
    case LOG_INFO:  return "info";
    case LOG_WARN:  return "warn";
    default:        return "error";
    }
}

/* Bounded string append (always NUL-terminated). */
static void app(char *dst, int cap, const char *s)
{
    int dl = (int)strlen(dst);
    int sl = (int)strlen(s);
    if (dl >= cap - 1)
        return;
    if (dl + sl > cap - 1)
        sl = cap - 1 - dl;
    memcpy(dst + dl, s, sl);
    dst[dl + sl] = '\0';
}

/* The four arexx_mode_str/fmt_size/fmt_dur/mins_since helpers are shared with
 * the status window (statuswin.c formats its own list fields) - declared in
 * arexx.h. */
const char *arexx_mode_str(FolderMode m)
{
    switch (m) {
    case FOLDER_SENDONLY:    return "sendonly";
    case FOLDER_RECEIVEONLY: return "receiveonly";
    default:                 return "sendreceive";
    }
}

/* "1.7 MB"-style size formatting without needing printf %llu (libnix). The
 * math is binary (1024) but the labels are the classic KB/MB/GB - the native
 * AmigaOS convention (and what most software shows), where these always meant
 * the binary quantities; Syncthing's GUI would say KiB/MiB for the same
 * values. */
void arexx_fmt_size(unsigned long long b, char *out)
{
    static const char *unit[] = { "B", "KB", "MB", "GB", "TB" };
    int u = 0;
    while (b >= 1024ULL * 1024ULL && u < 3) {   /* reduce until < 1 MiB */
        b >>= 10;
        u++;
    }
    if (b >= 1024)
        sprintf(out, "%lu.%lu %s", (unsigned long)(b >> 10),
                (unsigned long)((b & 1023) * 10 / 1024), unit[u + 1]);
    else
        sprintf(out, "%lu %s", (unsigned long)b, unit[u]);
}

/* Minutes elapsed since the DateStamp (day, min); clamped at 0. */
long arexx_mins_since(long day, long min)
{
    struct DateStamp now;
    long m;
    DateStamp(&now);                        /* fills all three fields */
    m = (now.ds_Days - day) * (24 * 60) + (now.ds_Minute - min);
    return m < 0 ? 0 : m;
}

/* "3m" / "4h 36m" / "2d 5h" duration formatting. */
void arexx_fmt_dur(long mins, char *out)
{
    if (mins < 60)
        sprintf(out, "%ldm", mins);
    else if (mins < 24 * 60)
        sprintf(out, "%ldh %ldm", mins / 60, mins % 60);
    else
        sprintf(out, "%ldd %ldh", mins / (24 * 60), (mins % (24 * 60)) / 60);
}

/* The report body, sectioned like the Syncthing web GUI (This Device /
 * Folders / Remote Devices), headed by the "AmiSync <ver> - " line. */
static void build_status(const ArexxContext *ctx, char *buf, int cap)
{
    char line[256], sz1[24], sz2[24], dur[24];
    int  i, n, first_folder = 1;

    buf[0] = '\0';

    if (!ctx || !ctx->cfg) {
        app(buf, cap, AMISYNC_NAME " " AMISYNC_VERSION "\n");
        app(buf, cap, "(no daemon state)\n");
        return;
    }

    /* Headline: the aggregate published to ENV:amisync/status. */
    {
        char status[64];
        peer_manager_status(ctx->pm, status, sizeof(status), NULL, NULL);
        sprintf(line, AMISYNC_NAME " " AMISYNC_VERSION " - %s\n", status);
        app(buf, cap, line);
    }

    /* One key per line, values in a common column ("discovery:" is the
     * longest key, so everything pads to its width). */
    app(buf, cap, "\nThis Device\n");
    if (ctx->our_id && ctx->our_id[0]) {
        sprintf(line, "  id:        %.7s (%s)\n", ctx->our_id,
                ctx->cfg->device_name);
        app(buf, cap, line);
    }
    arexx_fmt_dur(arexx_mins_since(ctx->start_day, ctx->start_min), dur);
    sprintf(line, "  uptime:    %s\n", dur);
    app(buf, cap, line);
    {
        unsigned long long tin = 0, tout = 0, in, out;
        for (i = 0; i < peer_count(ctx->pm); i++) {
            peer_xfer_info(ctx->pm, i, &in, &out, NULL, NULL);
            tin += in; tout += out;
        }
        arexx_fmt_size(tin, sz1); arexx_fmt_size(tout, sz2);
        sprintf(line, "  traffic:   received %s, sent %s\n", sz1, sz2);
        app(buf, cap, line);
    }
    if (ctx->listener)
        sprintf(line, "  listener:  on (port %u)\n",
                (unsigned)ctx->cfg->listen_port);
    else
        strcpy(line, "  listener:  off\n");
    app(buf, cap, line);
    sprintf(line, "  discovery: %s\n", ctx->cfg->discovery ? "on" : "off");
    app(buf, cap, line);

    {
        int live = 0;
        for (i = 0; i < ctx->cfg->num_folders; i++)
            if (!ctx->cfg->folders[i].removed)
                live++;
        sprintf(line, "\nFolders (%d)\n", live);
    }
    app(buf, cap, line);
    for (i = 0; i < ctx->cfg->num_folders; i++) {
        const ConfigFolder *f = &ctx->cfg->folders[i];
        const char *lbl;
        if (f->removed)
            continue;
        if (!first_folder)
            app(buf, cap, "\n");          /* air between folder blocks */
        first_folder = 0;
        /* Label first (what people recognise), the random Syncthing id in
         * brackets when it differs - matching its GUI's emphasis. */
        lbl = f->label[0] ? f->label : f->id;
        if (strcmp(lbl, f->id) != 0)
            sprintf(line, "  %.40s [%.40s]  %.127s  %s\n",
                    lbl, f->id, f->path, arexx_mode_str(f->mode));
        else
            sprintf(line, "  %.60s  %.127s  %s\n",
                    f->id, f->path, arexx_mode_str(f->mode));
        app(buf, cap, line);
        if (ctx->folders) {
            FolderState       *fs = &ctx->folders[i];
            unsigned long long bytes = 0;
            int                files = 0, dirs = 0, j;
            long               sday, smin;
            int                cverb;
            char               cname[BEP_PATH_MAX];
            foldstate_lock(fs);
            for (j = 0; j < fs->num_files; j++) {
                const FolderRec *m = &fs->files[j];
                if (m->deleted)
                    continue;
                if (m->type == BEP_FILE_DIRECTORY) {
                    dirs++;
                } else {
                    files++;
                    if (m->size > 0)
                        bytes += (unsigned long long)m->size;
                }
            }
            sday = fs->scan_day;
            smin = fs->scan_min;
            cverb = fs->chg_verb;
            memcpy(cname, fs->chg_name, sizeof(cname));
            foldstate_unlock(fs);
            arexx_fmt_size(bytes, sz1);
            if (sday || smin) {
                arexx_fmt_dur(arexx_mins_since(sday, smin), dur);
                sprintf(line, "    %d file%s, %d dir%s, %s - scanned %s ago\n",
                        files, files == 1 ? "" : "s",
                        dirs, dirs == 1 ? "" : "s", sz1, dur);
            } else {
                sprintf(line, "    %d file%s, %d dir%s, %s - not scanned yet\n",
                        files, files == 1 ? "" : "s",
                        dirs, dirs == 1 ? "" : "s", sz1);
            }
            app(buf, cap, line);
            {   /* Two things a folder can be hiding behind "up to date": a
                 * local edit a receive-only mirror has overwritten, and files
                 * a peer deleted that we kept (which it counts us out of sync
                 * for). Say both rather than looking clean. */
                int rev = peer_folder_reverted(ctx->pm, i);
                int kept;
                if (rev > 0) {
                    sprintf(line, "    %d local edit%s replaced by a peer's "
                            "copy (receive-only); the old one%s in "
                            ".stversions\n", rev, rev == 1 ? "" : "s",
                            rev == 1 ? " is" : "s are");
                    app(buf, cap, line);
                }
                kept = peer_folder_kept(ctx->pm, i);
                if (kept > 0) {
                    sprintf(line, "    %d file%s kept against a peer's "
                            "deletion (out of sync there)\n",
                            kept, kept == 1 ? "" : "s");
                    app(buf, cap, line);
                }
            }
            /* Syncthing's "Latest Change". Always shown - "(none yet)" says
             * the feature is there but nothing has changed this run (the note
             * is not persisted; a restart starts blank). */
            if (cverb)
                sprintf(line, "    latest change: %s %.200s\n",
                        cverb == FOLDSTATE_CHG_DELETED ? "deleted" :
                        cverb == FOLDSTATE_CHG_ADDED   ? "added"   : "updated",
                        cname);
            else
                strcpy(line, "    latest change: (none yet)\n");
            app(buf, cap, line);
        }
    }

    n = peer_count(ctx->pm);
    {
        int live = 0;
        for (i = 0; i < n; i++)                /* removed slots don't show */
            if (peer_info(ctx->pm, i, NULL, NULL, NULL, NULL, NULL))
                live++;
        sprintf(line, "\nRemote Devices (%d)\n", live);
    }
    app(buf, cap, line);
    for (i = 0; i < n; i++) {
        int                running = 0, connected = 0, paused = 0;
        const char        *host = "", *rname, *rclient;
        unsigned short     port = 0;
        unsigned long long in, out;
        const ConfigPeer  *p = peer_info(ctx->pm, i, &running, &connected,
                                         &paused, &host, &port);
        char               state[32];
        if (!p)
            continue;
        /* Connected devices get Syncthing's per-device state: our live fetch
         * backlog from them - 0 means we hold everything they announced. */
        if (connected) {
            int pend = peer_pending(ctx->pm, i);
            if (pend > 0)
                sprintf(state, "syncing (%d file%s)",
                        pend, pend == 1 ? "" : "s");
            else
                strcpy(state, "up to date");
        } else {
            strcpy(state, paused ? "paused" : running ? "connecting" : "idle");
        }
        if (host[0])                        /* %.7s: first group of the id */
            sprintf(line, "  %.7s  %s:%u  %s\n",
                    p->id, host, (unsigned)port, state);
        else
            sprintf(line, "  %.7s  (discovering)  %s\n", p->id, state);
        app(buf, cap, line);
        peer_xfer_info(ctx->pm, i, &in, &out, &rname, &rclient);
        if (rname[0] || in || out) {        /* nothing to say pre-first-connect */
            arexx_fmt_size(in, sz1); arexx_fmt_size(out, sz2);
            sprintf(line, "    %s (%s) - received %s, sent %s\n",
                    rname[0] ? rname : "?", rclient[0] ? rclient : "?",
                    sz1, sz2);
            app(buf, cap, line);
        }
    }

    /* Devices local discovery has seen that are NOT configured as peers -
     * the nudge that something on the LAN is waiting to be added (Tools
     * menu "Add Discovered...", ARexx ADDPEER, or the window's Add...).
     * Silent when there are none; the full untruncated IDs come from the
     * DISCOVERED verb. */
    if (ctx->seen) {
        int shown = 0;
        for (i = 0; i < ctx->seen->n; i++) {
            const DiscoSeenEntry *e = &ctx->seen->e[i];
            if (peer_manager_has(ctx->pm, e->id))
                continue;               /* already a peer (e.g. just added) */
            if (!shown) {
                app(buf, cap, "\nDiscovered - not configured\n");
                shown = 1;
            }
            sprintf(line, "  %.7s  %s:%u\n", e->id, e->host, (unsigned)e->port);
            app(buf, cap, line);
        }
    }

    /* Folders peers offer that we have not configured (their ClusterConfig
     * lists them, ours does not) - Syncthing's "wants to share folder X".
     * The window's Accept... turns one into a configured folder.
     * Filtered live, so acceptance drops the entry on the next tick. */
    {
        OfferedFolder of;
        int           oi, shown = 0;
        for (oi = 0; offered_get(oi, &of); oi++) {
            if (!of.id[0])
                continue;                  /* tombstoned slot */
            if (sync_folder_index(ctx->cfg, of.id) >= 0)
                continue;                  /* accepted meanwhile */
            if (!shown) {
                app(buf, cap, "\nOffered - not configured\n");
                shown = 1;
            }
            if (of.label[0] && strcmp(of.label, of.id) != 0)
                sprintf(line, "  %.32s [%.32s]  (from %.24s)\n", of.label,
                        of.id, of.device_name[0] ? of.device_name : "?");
            else
                sprintf(line, "  %.40s  (from %.24s)\n", of.id,
                        of.device_name[0] ? of.device_name : "?");
            app(buf, cap, line);
        }
    }
}

void arexx_build_status(const ArexxContext *ctx, char *buf, int cap)
{
    build_status(ctx, buf, cap);
}

/* List the unconfigured devices seen on the LAN via local discovery. These are
 * informational only - amisync never connects to them; add one to a peer line
 * to actually sync. */
static void build_discovered(const ArexxContext *ctx, char *buf, int cap)
{
    char line[256];
    int  i, n;

    buf[0] = '\0';
    n = (ctx && ctx->seen) ? ctx->seen->n : 0;
    sprintf(line, "discovered (%d):\n", n);
    app(buf, cap, line);
    for (i = 0; i < n; i++) {
        const DiscoSeenEntry *e = &ctx->seen->e[i];
        sprintf(line, "  %s  %s:%u\n", e->id, e->host, (unsigned)e->port);
        app(buf, cap, line);
    }
}

ArexxPort *arexx_open(const char *portname)
{
    ArexxPort *ap;

    ap = malloc(sizeof(*ap));
    if (!ap)
        return NULL;

    ap->port = CreateMsgPort();
    if (!ap->port) {
        free(ap);
        return NULL;
    }

    strncpy(ap->name, portname, sizeof(ap->name) - 1);
    ap->name[sizeof(ap->name) - 1] = '\0';
    ap->port->mp_Node.ln_Name = ap->name;
    ap->port->mp_Node.ln_Pri  = 0;

    /* Publish the port atomically: refuse if one already exists (another
     * amisync instance is running). */
    Forbid();
    if (FindPort(ap->name)) {
        Permit();
        DeleteMsgPort(ap->port);
        free(ap);
        return NULL;
    }
    AddPort(ap->port);
    Permit();

    /* Best-effort: needed only to return RESULT strings. */
    if (!RexxSysBase)
        RexxSysBase = (struct RxsLib *)OpenLibrary("rexxsyslib.library", 0);

    return ap;
}

void arexx_close(ArexxPort *ap)
{
    struct Message *msg;

    if (!ap)
        return;

    Forbid();
    RemPort(ap->port);
    while ((msg = GetMsg(ap->port)) != NULL)
        ReplyMsg(msg);
    Permit();

    DeleteMsgPort(ap->port);
    free(ap);

    if (RexxSysBase) {
        CloseLibrary((struct Library *)RexxSysBase);
        RexxSysBase = NULL;
    }
}

unsigned long arexx_signal(const ArexxPort *ap)
{
    if (!ap || !ap->port)
        return 0;
    return 1UL << ap->port->mp_SigBit;
}

/* Reply OK, attaching 'text' as RESULT if the caller asked for it (and we can). */
static void reply_ok(struct RexxMsg *rm, const char *text)
{
    rm->rm_Result1 = RC_OK;
    rm->rm_Result2 = 0;
    if (text && RexxSysBase && (rm->rm_Action & RXFF_RESULT))
        rm->rm_Result2 = (LONG)CreateArgstring((STRPTR)text, (LONG)strlen(text));
    ReplyMsg((struct Message *)rm);
}

static void reply_error(struct RexxMsg *rm)
{
    rm->rm_Result1 = RC_ERROR;
    rm->rm_Result2 = 0;
    ReplyMsg((struct Message *)rm);
}

ArexxResult arexx_dispatch(ArexxPort *ap, const ArexxContext *ctx)
{
    struct RexxMsg *rm;
    ArexxResult     result = AREXX_OK;

    if (!ap)
        return AREXX_OK;

    while ((rm = (struct RexxMsg *)GetMsg(ap->port)) != NULL) {
        const char *cmd;

        /* The port is public, so anything on the machine can PutMsg it - and
         * not everything that arrives is a RexxMsg. rm_Args[0] sits ~44 bytes
         * into the struct, so a short message from a confused sender had us
         * reading past their allocation and then following whatever was there
         * as a char *.
         *
         * Only mn_Length is checked, and only when the sender filled it in: a
         * message that declares its own size and is too small to BE a RexxMsg
         * cannot be one. Identifying a genuine RexxMsg positively (the ln_Name
         * "REXX" convention) would be stricter, but getting that assumption
         * wrong rejects every real command and takes the whole control
         * interface out - a far worse failure than the one being fixed, and
         * not something this build can verify without an Amiga. A zero
         * mn_Length is therefore let through exactly as before.
         *
         * Note this is robustness, not a security boundary: AmigaOS has no
         * memory protection, so a hostile local program never needed our
         * message port in the first place. */
        if (rm->rm_Node.mn_Length > 0 &&
            rm->rm_Node.mn_Length < (UWORD)sizeof(struct RexxMsg)) {
            log_printf(LOG_WARN, "ARexx: ignoring a %u-byte message on '%s' - "
                       "too small to be an ARexx command",
                       (unsigned)rm->rm_Node.mn_Length, ap->name);
            ReplyMsg((struct Message *)rm);
            continue;
        }
        cmd = (const char *)rm->rm_Args[0];

        if (first_token_is(cmd, "QUIT")) {
            log_printf(LOG_INFO, "ARexx: QUIT received");
            result = AREXX_QUIT;
            reply_ok(rm, NULL);
        } else if (first_token_is(cmd, "STATUS")) {
            char buf[AREXX_STATUS_MAX];
            arexx_build_status(ctx, buf, sizeof(buf));
            reply_ok(rm, buf);
        } else if (first_token_is(cmd, "DISCOVERED")) {
            char buf[2048];
            build_discovered(ctx, buf, sizeof(buf));
            reply_ok(rm, buf);
        } else if (first_token_is(cmd, "RESCAN")) {
            if (ctx) {
                scanner_rescan(ctx->scanner);   /* re-hash now; it then wakes workers */
                peer_rescan(ctx->pm);           /* also nudge workers to re-announce  */
                listener_rescan(ctx->listener);
            }
            log_printf(LOG_INFO, "ARexx: RESCAN triggered");
            reply_ok(rm, "rescan triggered");
        } else if (first_token_is(cmd, "PAUSE")) {
            char id[DEVICE_ID_BUFSZ];
            int  arg = second_token(cmd, id, sizeof(id));
            int  nn  = ctx ? peer_pause(ctx->pm, arg ? id : NULL) : 0;
            log_printf(LOG_INFO, "ARexx: PAUSE %s (%d peer(s))", arg ? id : "all", nn);
            /* Report what actually happened. device_id_equal needs the FULL
             * id, so the obvious "PAUSE ABCDEFG" - the 7-char group STATUS
             * prints - matches nothing; answering RC_OK "paused" told a
             * script it had paused a device that is still syncing. */
            if (arg && nn == 0)
                reply_error(rm);
            else
                reply_ok(rm, "paused");
        } else if (first_token_is(cmd, "RESUME")) {
            char id[DEVICE_ID_BUFSZ];
            int  arg = second_token(cmd, id, sizeof(id));
            int  nn  = ctx ? peer_resume(ctx->pm, arg ? id : NULL) : 0;
            log_printf(LOG_INFO, "ARexx: RESUME %s (%d peer(s))", arg ? id : "all", nn);
            if (arg && nn == 0)                /* see PAUSE above */
                reply_error(rm);
            else
                reply_ok(rm, "resumed");
        } else if (first_token_is(cmd, "ADDPEER")) {
            /* ADDPEER <device-id> [<host>[:<port>]] - add a peer at runtime
             * and persist it to the config file. */
            char id[DEVICE_ID_BUFSZ], canon[DEVICE_ID_BUFSZ];
            char hostbuf[CONFIG_HOST_MAX], *colon;
            unsigned short port = 0;
            if (!second_token(cmd, id, sizeof(id)) ||
                !device_id_normalize(id, canon)) {
                log_printf(LOG_WARN, "ARexx: ADDPEER with missing/bad device id");
                reply_error(rm);
            } else {
                if (token_at(cmd, 2, hostbuf, sizeof(hostbuf))) {
                    colon = strrchr(hostbuf, ':');
                    if (colon) {
                        *colon = '\0';
                        port = (unsigned short)atoi(colon + 1);
                    }
                } else {
                    hostbuf[0] = '\0';
                }
                switch (ctx ? peer_manager_add(ctx->pm, canon, hostbuf, port) : 0) {
                case 1:
                    reply_ok(rm, config_append_peer(CONFIG_PATH_DEFAULT, canon,
                                                    hostbuf, port)
                                 ? "added" : "added (config not writable - "
                                             "lost on restart)");
                    break;
                case -1: reply_ok(rm, "already configured"); break;
                case -2: reply_ok(rm, "peer table full");     break;
                default: reply_error(rm);                    break;
                }
            }
        } else if (first_token_is(cmd, "ADDFOLDER")) {
            /* ADDFOLDER <id> <path> [sendreceive|sendonly|receiveonly] -
             * share a folder at runtime; connected peers get an updated
             * ClusterConfig in-band and the scanner picks it up now. */
            char idb[CONFIG_FOLDER_ID_MAX], pathb[CONFIG_PATH_MAX], modeb[16];
            FolderMode mode = FOLDER_SENDRECEIVE;
            int        mode_bad = 0;
            /* An unrecognised mode word must NOT fall back to the default.
             * "recieveonly" used to be accepted as sendreceive and answered
             * "added" - the user asked for a folder that only takes changes
             * and got one that pushes their local files out to every peer. A
             * mode we do not understand is a refusal, not a guess. */
            if (token_at(cmd, 3, modeb, sizeof(modeb))) {
                /* Case-insensitive like every other word we parse -
                 * ARexx scripts conventionally shout. */
                if (strcasecmp(modeb, "sendonly") == 0)
                    mode = FOLDER_SENDONLY;
                else if (strcasecmp(modeb, "receiveonly") == 0)
                    mode = FOLDER_RECEIVEONLY;
                else if (strcasecmp(modeb, "sendreceive") != 0)
                    mode_bad = 1;
            } else if (token_present(cmd, 3)) {
                mode_bad = 1;                  /* present but far too long */
            }
            if (!second_token(cmd, idb, sizeof(idb)) ||
                !token_at(cmd, 2, pathb, sizeof(pathb))) {
                log_printf(LOG_WARN, "ARexx: ADDFOLDER needs <id> <path>, "
                           "each within its length limit");
                reply_error(rm);
            } else if (mode_bad) {
                log_printf(LOG_WARN, "ARexx: ADDFOLDER: unknown mode '%.16s' "
                           "(sendreceive, sendonly or receiveonly)", modeb);
                reply_error(rm);
            } else {
                switch (daemon_folder_add(ctx, idb, pathb, mode, NULL)) {
                case 1:  reply_ok(rm, "added");              break;
                case -1: reply_ok(rm, "already configured"); break;
                case -2: reply_ok(rm, "folder table full (restart to "
                                      "reclaim removed slots)");    break;
                case -3: reply_ok(rm, "path overlaps an already-synced "
                                      "folder");             break;
                default: reply_error(rm);                    break;
                }
            }
        } else if (first_token_is(cmd, "REMOVEFOLDER")) {
            char idb[CONFIG_FOLDER_ID_MAX];
            if (!second_token(cmd, idb, sizeof(idb))) {
                reply_error(rm);
            } else if (daemon_folder_remove(ctx, idb)) {
                reply_ok(rm, "removed");
            } else {
                reply_ok(rm, "unknown folder");
            }
        } else if (first_token_is(cmd, "LOGLEVEL")) {
            char     arg[16];
            LogLevel lv;
            if (!second_token(cmd, arg, sizeof(arg))) {
                reply_ok(rm, level_name(log_get_level()));     /* report current */
            } else if (level_from_name(arg, &lv)) {
                log_set_level(lv);
                log_printf(LOG_INFO, "ARexx: log level set to %s", level_name(lv));
                reply_ok(rm, "ok");
            } else {
                reply_error(rm);
            }
        } else if (first_token_is(cmd, "VERSION")) {
            reply_ok(rm, AMISYNC_NAME " " AMISYNC_VERSION);
        } else if (first_token_is(cmd, "HELP")) {
            reply_ok(rm, "commands: STATUS DISCOVERED ADDPEER <id> [host[:port]] "
                         "ADDFOLDER <id> <path> [mode] REMOVEFOLDER <id> "
                         "RESCAN PAUSE [id] RESUME [id] "
                         "LOGLEVEL [debug|info|warn|error] VERSION HELP QUIT");
        } else {
            log_printf(LOG_WARN, "ARexx: unknown command '%s'", cmd ? cmd : "");
            reply_error(rm);
        }
    }

    return result;
}
