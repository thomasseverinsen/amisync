/* appicon.c - Workbench AppIcon status indicator for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Places an AppIcon on the Workbench backdrop whose label is the live sync
 * status ("Up to Date", "Syncing (3 files)", ...). Everything is best-effort:
 * at boot amisync starts from User-Startup BEFORE LoadWB, so the first
 * AddAppIcon calls fail; appicon_update() simply retries on each status tick
 * (2 s) until Workbench is up and the icon appears. If workbench.library or
 * icon.library is unavailable the feature is skipped - the status is still
 * in ENV:amisync/status and the ARexx STATUS verb.
 *
 * Workbench has no "relabel AppIcon" call, so a changed status re-adds the
 * icon (RemoveAppIcon + AddAppIcon); that only happens when the text actually
 * changed. On V44+ Workbench writes the icon's position back into our
 * DiskObject (WBAPPICONA_PropagatePosition), so the re-add lands where the
 * user put it, and Snapshot saves it to APPICON_POS_FILE for the next start.
 * Directory Opus Magellan ignores those tags and keys its own snapshots by
 * label text, so each status had its own position; DAE_SnapShot has it hand
 * the Snapshot to us instead, and its ChangeAppIcon relabels in place, so a
 * dragged icon stays put there too.
 * Double-clicking the icon opens the live status window (statuswin.c;
 * single-instance and non-blocking), with the old modal EasyRequest kept only
 * as the fallback when the window cannot open.
 *
 * Icon imagery: an icon FILE is preferred, so users get whatever their
 * icon.library can render (256-colour GlowIcons format on OS 3.2/3.5+, PNG
 * icons under PeterK's icon.library, ...) and can swap the art at will.
 * tools/genglowicon.py generates the shipped dual-format amisync.info from
 * the official Syncthing logo SVG. Without an icon file the system's default
 * tool icon (GetDefDiskObject) is used - native look on every setup, no
 * embedded art to bit-rot. No icon.library at all -> feature skipped.
 *
 * The module also puts the daemon's global commands in Workbench's Tools
 * menu (AddAppMenuItem: Status/Rescan All/Pause All/Resume All/Stop) - the
 * canonical place for background-app controls. On workbench.library V45+
 * (OS 3.9/3.2) they sit in an "AmiSync" sub menu (WBAPPMENUA_GetKey/
 * UseKey); older Workbenches ignore those tags' mechanism, so there they
 * are added as flat "AmiSync: ..." entries instead. The items share the
 * AppIcon's message port and retry logic. Selection-scoped and
 * parameterized verbs live in the STATUS WINDOW (and ARexx). Stop asks for
 * confirmation first - it stops the whole daemon.
 */

#include <stdio.h>
#include <string.h>

#include <exec/execbase.h>
#include <exec/memory.h>
#include <intuition/intuition.h>
#include <workbench/workbench.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/icon.h>
#include <proto/intuition.h>
#include <proto/wb.h>

#include "appicon.h"
#include "version.h"
#include "peer.h"
#include "scanner.h"
#include "listener.h"
#include "log.h"

struct Library        *WorkbenchBase;   /* proto/wb.h inlines resolve here  */
struct Library        *IconBase;        /* proto/icon.h; may be NULL        */
struct IntuitionBase  *IntuitionBase;   /* proto/intuition.h; may be NULL   */

/* Icon files tried in order (".info" appended by GetDiskObject). PROGDIR:
 * may be unset in the detached daemon process, hence the ENVARC: fallback
 * next to the identity/state files. */
static const char *appicon_paths[] = {
    "PROGDIR:amisync",
    "ENVARC:Amisync/appicon",
    NULL
};

/* The snapshotted backdrop position, "x y". Not the icon file's own: that
 * one places the program's icon in its drawer. */
#define APPICON_POS_FILE "ENVARC:Amisync/appicon.pos"

/* Magellan's AppIcon snapshot protocol, from its dopus5.h. The position uses
 * the same origin as do_CurrentX/Y. */
#define DAE_SnapShot         (TAG_USER + 1)
#define MTYPE_APPSNAPSHOT    0x3812
#define APPSNAPF_UNSNAPSHOT  (1 << 0)

/* dopus5.library calls, LVOs from its dopus_lib.fd. */
#define APP_ICON    0
#define CAIF_TITLE  (1 << 2)

static struct Library *DOpusBase;

#define LockAppList() \
      LP0(0x450, APTR, LockAppList, , DOpusBase)
#define NextAppEntry(last, type) \
      LP2(0x456, APTR, NextAppEntry, APTR, last, a0, ULONG, type, d0, \
      , DOpusBase)
#define UnlockAppList() \
      LP0NR(0x45c, UnlockAppList, , DOpusBase)
#define ChangeAppIcon(icon, render, select, title, flags) \
      LP5NR(0x684, ChangeAppIcon, APTR, icon, a0, struct Image *, render, a1, \
      struct Image *, select, a2, char *, title, a3, ULONG, flags, d0, \
      , DOpusBase)

struct AppSnapshotMsg {
    struct AppMessage ap_msg;
    long              position_x;
    long              position_y;
    struct IBox       window_pos;
    unsigned long     flags;
    long              id;
};

/* Tools-menu commands. IDs are am_ID values in the AppMessages; 0 is the
 * AppIcon (and the sub-menu parent, which never fires itself). On V45+ the
 * short labels go into an "AmiSync" sub menu; pre-V45 gets the flat labels,
 * prefixed because they land directly in the shared Tools menu. */
enum {
    MENU_STATUS = 1,
    MENU_RESCAN,
    MENU_PAUSE,
    MENU_RESUME,
    MENU_QUIT,
    MENU_COUNT_                    /* table size sentinel, not an item */
};
#define MENU_ITEMS (MENU_COUNT_ - 1)

static const char *menu_labels_sub[MENU_ITEMS] = {
    "Status...", "Rescan All", "Pause All", "Resume All", "Stop...",
};
static const char *menu_labels_flat[MENU_ITEMS] = {
    "AmiSync: Status...",
    "AmiSync: Rescan All",
    "AmiSync: Pause All",
    "AmiSync: Resume All",
    "AmiSync: Stop...",
};

struct AppIconUI {
    struct MsgPort     *port;      /* AppIcon + menu event port            */
    struct AppIcon     *icon;      /* NULL until AddAppIcon succeeds       */
    struct AppMenuItem *parent;    /* V45+ "AmiSync" sub-menu parent item  */
    ULONG               menukey;   /* sub-menu key GetKey wrote for it     */
    struct AppMenuItem *menu[MENU_ITEMS];   /* Tools-menu items, NULL-able */
    struct DiskObject  *dobj;      /* from icon file or GetDefDiskObject   */
    int                 announced; /* logged the successful placement once */
    char                label[2][64]; /* [cur] is placed and read by WB;
                                       * a Magellan relabel takes the other */
    int                 cur;
    long                relabelled; /* when the label last changed         */
};

/* A relabel is a remove + add. The count in "Syncing (N files)" changes
 * nearly every tick, so a count-only change waits this long; a state change
 * goes at once. */
#define APPICON_RELABEL_SECS 10

static long now_seconds(void)
{
    struct DateStamp ds;

    DateStamp(&ds);
    return ds.ds_Days * 86400L + ds.ds_Minute * 60L + ds.ds_Tick / 50;
}

/* Length of the status text up to its "(count)" part. */
static int state_len(const char *s)
{
    const char *p = strchr(s, '(');
    return p ? (int)(p - s) : (int)strlen(s);
}

/* Whether Magellan placed this icon: its AddAppIconA patch returns one of its
 * own entries. Only uses dopus5.library if it is already in memory. */
static int magellan_icon(struct AppIcon *icon)
{
    APTR e;

    if (!DOpusBase) {
        Forbid();
        e = FindName(&SysBase->LibList, (STRPTR)"dopus5.library");
        Permit();
        if (e)
            DOpusBase = OpenLibrary("dopus5.library", 0);
        if (!DOpusBase)
            return 0;
    }
    for (e = LockAppList(); e && (e = NextAppEntry(e, APP_ICON)) != NULL; )
        if (e == (APTR)icon)
            break;
    UnlockAppList();
    return e != NULL;
}

/* Lazy-open intuition.library for the two fallback requesters. Returns 0 if
 * it cannot open, which on a running system never happens. */
static int open_intuition(void)
{
    if (!IntuitionBase)
        IntuitionBase = (struct IntuitionBase *)
                        OpenLibrary("intuition.library", 37);
    return IntuitionBase != NULL;
}

static void pos_load(struct DiskObject *dobj)
{
    char buf[32];
    long x, y;
    LONG n;
    BPTR fh = Open((STRPTR)APPICON_POS_FILE, MODE_OLDFILE);

    if (!fh)
        return;
    n = Read(fh, buf, sizeof(buf) - 1);
    Close(fh);
    if (n <= 0)
        return;
    buf[n] = '\0';
    if (sscanf(buf, "%ld %ld", &x, &y) == 2) {
        dobj->do_CurrentX = x;
        dobj->do_CurrentY = y;
    }
}

static void pos_save(long x, long y)
{
    char buf[32];
    BPTR fh;
    LONG n;

    n  = sprintf(buf, "%ld %ld\n", x, y);
    fh = Open((STRPTR)APPICON_POS_FILE, MODE_NEWFILE);
    if (!fh || Write(fh, buf, n) != n)
        log_printf(LOG_WARN, "appicon: could not save the snapshot to %s",
                   APPICON_POS_FILE);
    if (fh)
        Close(fh);
}

/* Load the icon imagery: the first present icon file, else the system's
 * default tool icon. Returns NULL only without icon.library (or if even the
 * default icon can't load), which disables the AppIcon feature. */
static struct DiskObject *load_icon(void)
{
    struct DiskObject *dobj = NULL;
    int                i;

    if (!IconBase)
        IconBase = OpenLibrary("icon.library", 37);
    if (!IconBase)
        return NULL;

    for (i = 0; appicon_paths[i]; i++) {
        dobj = GetDiskObject((STRPTR)appicon_paths[i]);
        if (dobj) {
            log_printf(LOG_INFO, "appicon: using icon file %s.info",
                       appicon_paths[i]);
            break;
        }
    }
    if (!dobj) {
        dobj = GetDefDiskObject(WBTOOL);
        if (dobj)
            log_printf(LOG_INFO,
                       "appicon: no icon file; using default tool icon");
    }
    if (dobj) {
        dobj->do_CurrentX = NO_ICON_POSITION;     /* WB places it, unless... */
        dobj->do_CurrentY = NO_ICON_POSITION;
        pos_load(dobj);                           /* ...it was snapshotted */
    }
    return dobj;
}

AppIconUI *appicon_create(int enabled)
{
    AppIconUI *ui;

    if (!enabled)
        return NULL;

    ui = AllocVec(sizeof(*ui), MEMF_ANY | MEMF_CLEAR);
    if (!ui)
        return NULL;

    ui->port = CreateMsgPort();
    ui->dobj = load_icon();
    if (!ui->port || !ui->dobj) {
        appicon_destroy(ui);
        return NULL;
    }
    strcpy(ui->label[0], AMISYNC_NAME);
    return ui;
}

unsigned long appicon_sigmask(const AppIconUI *ui)
{
    return (ui && ui->port) ? (1UL << ui->port->mp_SigBit) : 0;
}

/* Try to place the icon and the Tools-menu items. Fails harmlessly while
 * Workbench isn't running yet (or workbench.library can't open); the caller
 * just tries again next tick, and only the still-missing pieces are added. */
static void appicon_try_add(AppIconUI *ui)
{
    const char *const *labels = menu_labels_flat;   /* pre-V45: flat entries */
    struct TagItem     sub[2];
    struct TagItem    *tags   = NULL;
    int                i;

    if (!WorkbenchBase)
        WorkbenchBase = OpenLibrary("workbench.library", 39);
    if (!WorkbenchBase)
        return;

    if (!ui->icon) {
        struct TagItem itags[5];

        itags[0].ti_Tag  = WBAPPICONA_PropagatePosition;
        itags[0].ti_Data = TRUE;
        itags[1].ti_Tag  = WBAPPICONA_SupportsSnapshot;
        itags[1].ti_Data = TRUE;
        itags[2].ti_Tag  = WBAPPICONA_SupportsUnSnapshot;
        itags[2].ti_Data = TRUE;
        itags[3].ti_Tag  = DAE_SnapShot;
        itags[3].ti_Data = TRUE;
        itags[4].ti_Tag  = TAG_DONE;
        ui->icon = AddAppIconA(0, 0, ui->label[ui->cur], ui->port, 0, ui->dobj,
                               WorkbenchBase->lib_Version >= 44 ? itags : NULL);
        if (ui->icon)
            ui->relabelled = now_seconds();
        if (ui->icon && !ui->announced) {
            log_printf(LOG_INFO, "appicon: placed on the Workbench backdrop");
            ui->announced = 1;
        }
    }

    if (WorkbenchBase->lib_Version >= 45) {
        /* One "AmiSync" entry in the Tools menu, commands as its sub menu. */
        if (!ui->parent) {
            struct TagItem ptags[2];
            ptags[0].ti_Tag  = WBAPPMENUA_GetKey;
            ptags[0].ti_Data = (ULONG)&ui->menukey;
            ptags[1].ti_Tag  = TAG_DONE;
            ui->parent = AddAppMenuItemA(0, 0, (STRPTR)AMISYNC_NAME,
                                         ui->port, ptags);
        }
        if (!ui->parent)
            return;              /* no parent yet: retry the sub menu next
                                  * tick rather than fall back to flat ones */
        sub[0].ti_Tag  = WBAPPMENUA_UseKey;
        sub[0].ti_Data = ui->menukey;
        sub[1].ti_Tag  = TAG_DONE;
        labels = menu_labels_sub;
        tags   = sub;
    }

    for (i = 0; i < MENU_ITEMS; i++)
        if (!ui->menu[i])
            ui->menu[i] = AddAppMenuItemA(i + 1, 0, (STRPTR)labels[i],
                                          ui->port, tags);
}

void appicon_update(AppIconUI *ui, const char *status)
{
    char *label;

    if (!ui || !status || !status[0])
        return;
    label = ui->label[ui->cur];

    if (ui->icon && strcmp(label, status) != 0) {
        int a = state_len(label), b = state_len(status);

        if (a == b && strncmp(label, status, a) == 0 &&
            now_seconds() - ui->relabelled < APPICON_RELABEL_SECS)
            return;                        /* count-only change: not yet    */
        log_printf(LOG_DEBUG, "appicon: relabel \"%s\" -> \"%s\"",
                   label, status);
        if (magellan_icon(ui->icon)) {
            /* Magellan reads the title later from its own process, so the
             * old buffer must stay intact until it has. */
            ui->cur ^= 1;
            label = ui->label[ui->cur];
            strncpy(label, status, sizeof(ui->label[0]) - 1);
            label[sizeof(ui->label[0]) - 1] = '\0';
            ChangeAppIcon(ui->icon, NULL, NULL, label, CAIF_TITLE);
            ui->relabelled = now_seconds();
            appicon_try_add(ui);
            return;
        }
        /* Honour the answer rather than assume it. The invariant below - only
         * rewrite the label while no icon holds it, because Workbench reads
         * this buffer for as long as the icon is placed - was asserted by a
         * comment and then broken unconditionally: a failed removal left the
         * icon up while we rewrote the string under it, and then added a
         * second icon beside it. Leaving it alone until the next tick costs a
         * stale label for a second. */
        if (RemoveAppIcon(ui->icon))       /* no relabel call: re-add      */
            ui->icon = NULL;
    }
    /* Only rewrite the label while no icon holds it - Workbench reads this
     * buffer for as long as the icon is placed. */
    if (!ui->icon) {
        strncpy(label, status, sizeof(ui->label[0]) - 1);
        label[sizeof(ui->label[0]) - 1] = '\0';
    }
    /* Unconditional: try_add only fills what is missing, so a menu item that
     * failed to add under memory pressure gets retried on later ticks even
     * when the status text never changes again. */
    appicon_try_add(ui);
}

/* Pop the full STATUS report in a requester. Best-effort: without intuition
 * (never on a running system) the click is silently ignored. The report text
 * goes through "%s" so any '%' in folder paths is shown literally. */
static void appicon_show_status(const ArexxContext *ctx)
{
    static struct EasyStruct es = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME, "%s", "OK"
    };
    char  buf[AREXX_STATUS_MAX];
    APTR  args[1];

    if (!open_intuition())
        return;

    arexx_build_status(ctx, buf, sizeof(buf));
    args[0] = buf;
    EasyRequestArgs(NULL, &es, NULL, args);
}

/* Ask before stopping the daemon from the menu. Returns 1 to quit. */
static int appicon_confirm_quit(void)
{
    static struct EasyStruct es = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        "Stop AmiSync?\nSyncing halts until it is started again.",
        "Stop|Cancel"
    };

    if (!open_intuition())
        return 0;
    return EasyRequestArgs(NULL, &es, NULL, NULL) == 1;
}

int appicon_handle(AppIconUI *ui, const ArexxContext *ctx, StatusWin *sw)
{
    struct AppMessage *am;
    int                status = 0, rescan = 0, pause = 0, resume = 0;
    int                quit = 0;

    if (!ui || !ui->port)
        return 0;

    /* Reply everything BEFORE any action or modal requester: Workbench waits
     * for the reply, and must not sit blocked while a requester is up. */
    while ((am = (struct AppMessage *)GetMsg(ui->port)) != NULL) {
        if (am->am_Type == MTYPE_APPSNAPSHOT) {
            struct AppSnapshotMsg *sm = (struct AppSnapshotMsg *)am;

            if (sm->flags & APPSNAPF_UNSNAPSHOT) {
                DeleteFile((STRPTR)APPICON_POS_FILE);
                ui->dobj->do_CurrentX = NO_ICON_POSITION;
                ui->dobj->do_CurrentY = NO_ICON_POSITION;
            } else {
                pos_save(sm->position_x, sm->position_y);
                ui->dobj->do_CurrentX = sm->position_x;   /* for re-adds */
                ui->dobj->do_CurrentY = sm->position_y;
            }
        } else if (am->am_Type == AMTYPE_APPICON &&
                   am->am_Class == AMCLASSICON_Snapshot) {
            pos_save(ui->dobj->do_CurrentX, ui->dobj->do_CurrentY);
        } else if (am->am_Type == AMTYPE_APPICON &&
                   am->am_Class == AMCLASSICON_UnSnapshot) {
            DeleteFile((STRPTR)APPICON_POS_FILE);
        } else if (am->am_Type == AMTYPE_APPICON && am->am_NumArgs == 0) {
            status = 1;                    /* double-click (not a drop) */
        } else if (am->am_Type == AMTYPE_APPMENUITEM) {
            switch (am->am_ID) {
            case MENU_STATUS:  status  = 1; break;
            case MENU_RESCAN:  rescan  = 1; break;
            case MENU_PAUSE:   pause   = 1; break;
            case MENU_RESUME:  resume  = 1; break;
            case MENU_QUIT:    quit    = 1; break;
            }
        }
        ReplyMsg((struct Message *)am);
    }

    /* Same command paths as the ARexx verbs. */
    if (rescan && ctx) {
        scanner_rescan(ctx->scanner);
        peer_rescan(ctx->pm);
        listener_rescan(ctx->listener);
        log_printf(LOG_INFO, "appicon: RESCAN triggered from Tools menu");
    }
    if (pause && ctx) {
        peer_pause(ctx->pm, NULL);
        log_printf(LOG_INFO, "appicon: PAUSE all from Tools menu");
    }
    if (resume && ctx) {
        peer_resume(ctx->pm, NULL);
        log_printf(LOG_INFO, "appicon: RESUME all from Tools menu");
    }
    if (status) {
        /* The live window is the primary presentation; the old modal
         * requester only backs it up when the window cannot open. */
        if (!statuswin_show(sw, ctx, ui->dobj))
            appicon_show_status(ctx);
    }

    return quit ? appicon_confirm_quit() : 0;
}

void appicon_destroy(AppIconUI *ui)
{
    struct Message *m;
    int             i;

    if (!ui)
        return;

    if (ui->icon)
        RemoveAppIcon(ui->icon);
    for (i = 0; i < MENU_ITEMS; i++)
        if (ui->menu[i])
            RemoveAppMenuItem(ui->menu[i]);
    if (ui->parent)
        RemoveAppMenuItem(ui->parent);   /* after its children */
    if (ui->port) {
        while ((m = GetMsg(ui->port)) != NULL)   /* clicks queued pre-removal */
            ReplyMsg(m);
        DeleteMsgPort(ui->port);
    }
    if (ui->dobj)
        FreeDiskObject(ui->dobj);    /* before IconBase closes below */
    FreeVec(ui);

    if (DOpusBase) {
        CloseLibrary(DOpusBase);
        DOpusBase = NULL;
    }
    if (IconBase) {
        CloseLibrary(IconBase);
        IconBase = NULL;
    }
    if (WorkbenchBase) {
        CloseLibrary(WorkbenchBase);
        WorkbenchBase = NULL;
    }
    if (IntuitionBase) {
        CloseLibrary((struct Library *)IntuitionBase);
        IntuitionBase = NULL;
    }
}
