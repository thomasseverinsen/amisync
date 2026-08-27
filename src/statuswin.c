/* statuswin.c - live-updating Workbench status window for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See statuswin.h.
 * Syncthing-web-style select-then-act with expand-on-select, top to bottom:
 *
 *   header band     logo + "AmiSync <ver> (<cpu>, <date>)" + the aggregate
 *                   status (FILLPEN bold); the window TITLE carries the
 *                   status too, for when the window is depth-arranged away
 *   This Device     group frame, five glance facts in two key/value columns
 *   Folders (N)     group frame: bold column header (Name/Path/Mode), a
 *                   list bevel with scroller, then [Open][Accept...][Remove...]
 *   Remote Devices  group frame: header (Name/ID/Address/State), list, then
 *                   [Add...][Pause|Resume][Remove...]
 *   bottom row      [Rescan][Pause All]    [Open Log][Stop...], GadTools;
 *                   verbs left, meta right; Stop names the daemon so the
 *                   close gadget (close the window) cannot be confused
 *
 * Each folder/device is ONE collapsed row; clicking it selects (inverse
 * video, FILLPEN) and expands its detail lines beneath; clicking again
 * collapses. Offered folders and discovered devices are rows in the same
 * lists, wearing an "Offered"/"Discovered" badge in the Mode/State
 * column; the verb buttons ghost (GA_Disabled)
 * whenever the selection does not apply. Opening a folder's drawer is the
 * Open verb (OpenWorkbenchObject, workbench.library V44+). Selection is
 * tracked by IDENTITY (kind + id), never row index, so it survives ticks
 * and removals.
 *
 * The list bodies are custom-drawn, NOT GT_LISTVIEW: live values (traffic,
 * "scanned Xm ago") sit inside expanded blocks and change on status ticks,
 * and a GadTools listview redraws whole when its labels change - flicker
 * on every tick during a sync. This renderer updates rows in place (JAM2),
 * like the previous incarnation of this window. Everything around the list
 * bodies - verb buttons, scrollers - is stock GadTools.
 *
 * Sizing: the window fits itself to the content, each list sized for all
 * its rows plus one expansion's worth of slack (so expanding never resizes
 * anything), until the user resizes - from then on their size wins and the
 * lists absorb the difference (min 2 visible rows, scrollers take over).
 * Self-initiated ChangeWindowBox is deferred, so repaints ride the
 * IDCMP_NEWSIZE it raises; a user resize is told apart by not matching the
 * size we last asked for. Rendering is Topaz 8.
 *
 * intuition.library and workbench.library are shared with appicon.c (which
 * closes them - hence statuswin_destroy runs first); graphics.library and
 * gadtools.library are opened here and closed in statuswin_destroy.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <exec/memory.h>
#include <intuition/intuition.h>
#include <intuition/screens.h>
#include <intuition/imageclass.h>   /* IDS_NORMAL */
#include <graphics/text.h>
#include <graphics/gfxbase.h>
#include <libraries/gadtools.h>
#include <libraries/asl.h>
#include <workbench/workbench.h>
#include <dos/dostags.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/graphics.h>
#include <proto/gadtools.h>
#include <proto/asl.h>
#include <proto/icon.h>
#include <proto/intuition.h>
#include <proto/wb.h>

#include "statuswin.h"
#include "daemon.h"
#include "offered.h"
#include "version.h"
#include "peer.h"
#include "scanner.h"
#include "listener.h"
#include "log.h"

extern struct IntuitionBase *IntuitionBase;   /* owned by appicon.c */
extern struct Library       *IconBase;        /* owned by appicon.c */
extern struct Library       *WorkbenchBase;   /* owned by appicon.c */
struct GfxBase              *GfxBase;         /* opened here, lazily */
struct Library              *GadToolsBase;    /* opened here, lazily (the
                                               * proto header declares it) */
struct Library              *AslBase;         /* opened on first folder accept */

#define SW_PAD           6   /* pixels around the content                 */
#define SW_GPAD          8   /* group frame inner side padding            */
#define SW_GGAP          8   /* vertical air between groups               */
/* Extra pixels between text rows. Topaz 8 fills its whole 8-px cell, so rows
 * stacked at bare tf_YSize nearly touch (authentic for a Shell, cramped for
 * a status page); 2 px of leading is ~25% air, close to a GUI line height. */
#define SW_LEADING       2

#define SW_SCR_W        14   /* scroller width (right edge of each list)  */
#define SW_BT_H         14   /* button height (Topaz 8 label + bevel)     */
/* Bottom row: the rule, 6 px of air under it before the buttons, and
 * SW_PAD+4 below them - the extra 4 clears the size gadget, which
 * intrudes ~8 px into the interior corner. That lets Stop... sit flush
 * with the group frames' right edge instead of holding a horizontal
 * clearance that read as misalignment. (The air ABOVE the rule is
 * layout()'s SW_GGAP.) */
#define SW_BROW_H       (SW_BT_H + 8 + SW_PAD + 4)

#define SW_LINE_MAX     96   /* one built list line (head/detail/header)  */
#define SW_KEY_MAX      72   /* selection identity "K:<id>"               */
#define SW_DET_MAX       4   /* detail lines per item                     */
/* One list's worth of rows: whichever of the two lists can hold more. Derived
 * from all four caps rather than asserted, so raising any of them cannot
 * silently start truncating a list. */
#define SW_FOLDER_ROWS  (CONFIG_MAX_FOLDERS + OFFERED_MAX)
#define SW_DEVICE_ROWS  (CONFIG_MAX_PEERS + DISCO_SEEN_MAX)
#define SW_ITEMS_MAX    (SW_FOLDER_ROWS > SW_DEVICE_ROWS ? \
                         SW_FOLDER_ROWS : SW_DEVICE_ROWS)

/* Item kinds - also the first letter of the selection key. */
enum { LK_FOLDER, LK_OFFER, LK_DEVICE, LK_DISCO };

/* Gadget IDs. */
enum {
    GID_RESCAN = 1,
    GID_PAUSEALL,
    GID_OPENLOG,
    GID_QUIT,
    GID_FADD,
    GID_FOPEN,
    GID_FRESCAN,
    GID_FACCEPT,
    GID_FREMOVE,
    GID_DADD,
    GID_DPAUSE,
    GID_DREMOVE,
    GID_FSCROLL,
    GID_DSCROLL
};

/* The window's menu strip (shown on the right mouse button, Amiga
 * convention - a window without one presents an EMPTY menu bar). App-level
 * verbs only: the list verbs live in their button rows. */
enum {
    SW_MENU_OPENLOG = 1,
    SW_MENU_ABOUT,
    SW_MENU_CLOSE,
    SW_MENU_STOP,
    SW_MENU_RESCANALL,
    SW_MENU_PAUSEALL,
    SW_MENU_RESUMEALL
};
static struct NewMenu sw_newmenu[] = {
    { NM_TITLE, (STRPTR)"Project",         0,          0, 0, 0 },
    { NM_ITEM,  (STRPTR)"Open Log",        (STRPTR)"L", 0, 0,
      (APTR)SW_MENU_OPENLOG },
    { NM_ITEM,  (STRPTR)"About...",        0,          0, 0,
      (APTR)SW_MENU_ABOUT },
    { NM_ITEM,  (STRPTR)NM_BARLABEL,       0,          0, 0, 0 },
    { NM_ITEM,  (STRPTR)"Close Window",    0,          0, 0,
      (APTR)SW_MENU_CLOSE },
    { NM_ITEM,  (STRPTR)"Stop AmiSync...", (STRPTR)"Q", 0, 0,
      (APTR)SW_MENU_STOP },
    /* The global sync verbs, mirroring the bottom button row (and the
     * Workbench Tools menu) - menus are what carry keyboard shortcuts.
     * Selection verbs stay in their button rows. */
    { NM_TITLE, (STRPTR)"Sync",            0,          0, 0, 0 },
    { NM_ITEM,  (STRPTR)"Rescan All",      (STRPTR)"R", 0, 0,
      (APTR)SW_MENU_RESCANALL },
    { NM_ITEM,  (STRPTR)"Pause All",       (STRPTR)"P", 0, 0,
      (APTR)SW_MENU_PAUSEALL },
    { NM_ITEM,  (STRPTR)"Resume All",      (STRPTR)"U", 0, 0,
      (APTR)SW_MENU_RESUMEALL },
    { NM_END,   0,                         0,          0, 0, 0 }
};

/* Header-band product line and the fixed Topaz 8 the whole window uses.
 * The CPU variant matters here: the Installer picks one of three builds,
 * and this is where a user checks which one is actually running. */
static const char SW_TITLE[] =
    AMISYNC_NAME " " AMISYNC_VERSION
    " (" AMISYNC_CPU ", " AMISYNC_DATE ")";
static struct TextAttr sw_topaz = { "topaz.font", 8, 0, 0 };

/* One list row-able entity: a folder, an offered folder, a device or a
 * discovered device. head is the pre-padded columnar line; det[] the
 * expansion (already indented). */
typedef struct {
    int  kind;
    int  idx;                       /* index into its backing table        */
    char key[SW_KEY_MAX];           /* selection identity, survives ticks  */
    char head[SW_LINE_MAX];
    int  state_col;                 /* head col where a live state word
                                     * starts (FILLPEN); -1 = none         */
    char det[SW_DET_MAX][SW_LINE_MAX];
    int  ndet;
    int  paused;                    /* devices: drives Pause/Resume label  */
} SWItem;

/* One accordion list (Folders / Remote Devices): items, selection,
 * scroll state and the layout the last recalc gave it. */
typedef struct {
    SWItem items[SW_ITEMS_MAX];
    int    n;
    char   header[SW_LINE_MAX];     /* bold column header line             */
    char   sel_key[SW_KEY_MAX];     /* "" = nothing selected               */
    int    top;                     /* first visible content row           */
    int    rows;                    /* visible rows in the bevel           */
    int    max_det;                 /* largest ndet (expansion slack)      */
    /* layout, window coords (recalced with the window) */
    int    title_y;                 /* group title row                     */
    int    hdr_y;                   /* column header row                   */
    int    bev_x, bev_y, bev_w, bev_h;
    int    tx, ty;                  /* text origin inside the bevel        */
    int    cols;                    /* text columns inside the bevel       */
    int    btn_y;                   /* verb button row                     */
    int    grp_end;                 /* y just past the bottom groove       */
    struct Gadget *scroller;
} SWList;

struct StatusWin {
    struct Window   *win;
    struct TextFont *font;              /* Topaz 8, owned                  */
    APTR             vi;                /* GadTools VisualInfo             */
    struct Menu     *menus;             /* Project menu strip              */
    struct Gadget   *glist;             /* context + buttons + scrollers   */
    struct Gadget   *g_fadd, *g_fopen, *g_frescan, *g_faccept, *g_fremove;
    struct Gadget   *g_dadd, *g_dpause, *g_dremove;
    int              textpen, bgpen;    /* screen DrawInfo pens            */
    int              shinepen, shadowpen;
    int              fillpen, filltextpen;
    /* Header imagery, kept for repaints (the DiskObject belongs to
     * appicon.c and outlives us - see the statuswin_destroy order). */
    struct DiskObject *dobj;
    int              logo_w, logo_h;
    int              band_h;            /* header band height              */
    /* This Device: the six formatted glance values + the aggregate.
     * Traffic is split into received/sent so every cell in the two-column
     * grid stays short (one long value would run under the right column). */
    char             td_id[64], td_up[24], td_li[32], td_di[8];
    char             td_rx[24], td_tx[24];
    char             status[64];
    int              td_y;              /* This Device group title row     */
    int              td_val_y;          /* ...its first content row        */
    SWList           fl, dl;            /* Folders / Remote Devices        */
    char             fl_title[40], dl_title[40];   /* "Folders (2)" etc.   */
    int              nf_last, nd_last;  /* item counts at last full draw   */
    /* Sizing policy: the last size WE asked for; a NEWSIZE that differs
     * means the user resized, which ends auto-fitting for this window. */
    int              want_w, want_h;
    int              user_sized;
    int              paused_all;        /* state behind Pause All/Resume All */
    int              dpause_resume;     /* device Pause gadget says Resume */
    /* Window title, "AmiSync - <aggregate status>". Double-buffered:
     * Intuition keeps reading the pointer given to SetWindowTitles, so each
     * new title is composed in the buffer NOT currently on display. */
    char             title[2][80];
    int              tcur;
};

StatusWin *statuswin_create(void)
{
    return AllocVec(sizeof(StatusWin), MEMF_ANY | MEMF_CLEAR);
}

unsigned long statuswin_sigmask(const StatusWin *sw)
{
    return (sw && sw->win) ? (1UL << sw->win->UserPort->mp_SigBit) : 0;
}

/* ---- string building --------------------------------------------------- */

/* Append 's' to dst (cap total), left-justified/truncated in a 'w'-column
 * field, then 'gap' spaces. The columnar lines are built with this instead
 * of "%-*.*s" so nothing leans on libnix printf's '*' support. */
static void padcat(char *dst, int cap, const char *s, int w, int gap)
{
    int dl = (int)strlen(dst);
    int sl = (int)strlen(s);
    int i;

    for (i = 0; i < w + gap && dl < cap - 1; i++)
        dst[dl++] = (i < w && i < sl) ? s[i] : ' ';
    dst[dl] = '\0';
}

/* Trailing-space trim (padcat pads full fields; the last field needn't). */
static void rtrim(char *s)
{
    int l = (int)strlen(s);
    while (l > 0 && s[l - 1] == ' ')
        s[--l] = '\0';
}

/* ---- the list model ---------------------------------------------------- */

/* Append one detail line to an item, truncated to fit and capped at
 * SW_DET_MAX rows. The formats below can outrun SW_LINE_MAX - "latest change:"
 * plus a 7-char verb and a 70-char filename needs 98 of 96 - and det[] is
 * followed in SWItem by 'ndet' itself, so the two bytes over used to land in
 * the count that bounds the expansion loop. Nothing here may use bare
 * sprintf into det[]. */
static void det_add(SWItem *it, const char *fmt, ...)
{
    va_list ap;

    if (it->ndet >= SW_DET_MAX)
        return;
    va_start(ap, fmt);
    vsnprintf(it->det[it->ndet], SW_LINE_MAX, fmt, ap);
    va_end(ap);
    it->ndet++;
}

/* The first dash-group of a device ID, as Syncthing abbreviates it. The
 * columnar builders need it as a string (padcat takes one); everything else
 * in the tree uses a %.7s precision. */
static void short_id(char out[8], const char *id)
{
    sprintf(out, "%.7s", id);
}

/* Case-insensitive head-line comparison: heads begin with the padded Name
 * field, so this sorts a list segment by display name (Syncthing sorts
 * its lists the same way). */
static int head_cmp(const SWItem *a, const SWItem *b)
{
    const unsigned char *x = (const unsigned char *)a->head;
    const unsigned char *y = (const unsigned char *)b->head;

    while (*x && *y) {
        int cx = (*x >= 'A' && *x <= 'Z') ? *x + 32 : *x;
        int cy = (*y >= 'A' && *y <= 'Z') ? *y + 32 : *y;
        if (cx != cy)
            return cx - cy;
        x++;
        y++;
    }
    return *x - *y;
}

/* Sort items[from..to) by name (insertion sort: n <= 32, and usually
 * already sorted from the last tick). Sorted per GROUP - configured
 * entries, then offered/discovered - so the badged "action needed" rows
 * stay together at the list's bottom. */
static void sort_items(SWItem *items, int from, int to)
{
    int i, j;

    for (i = from + 1; i < to; i++) {
        SWItem tmp;
        if (head_cmp(&items[i - 1], &items[i]) <= 0)
            continue;
        tmp = items[i];
        for (j = i; j > from && head_cmp(&items[j - 1], &tmp) > 0; j--)
            items[j] = items[j - 1];
        items[j] = tmp;
    }
}

/* The Mode column speaks Syncthing's GUI language; the config-token forms
 * (arexx_mode_str: "sendreceive"...) stay in the config file and ARexx text. */
static const char *mode_disp(FolderMode m)
{
    switch (m) {
    case FOLDER_SENDONLY:    return "Send Only";
    case FOLDER_RECEIVEONLY: return "Receive Only";
    default:                 return "Send & Receive";
    }
}

/* Folder display name: the label, or the id when there is no separate
 * label. The id itself lives in the EXPANSION (like Syncthing's GUI,
 * which shows "Folder ID" only in a folder's expanded details). */
static const char *folder_name(const ConfigFolder *f)
{
    return f->label[0] ? f->label : f->id;
}

/* Rebuild the Folders list: configured folders first, then offered ones
 * ("Offered" badge). Columns sized to content, clamped so a stock
 * 640-wide screen still fits. */
static void build_folder_items(StatusWin *sw, const ArexxContext *ctx)
{
    SWList *l = &sw->fl;
    int     i, nw = 4, pw = 4;   /* min widths: the header words           */

    l->n = 0;
    l->max_det = 1;
    if (!ctx || !ctx->cfg)
        return;

    /* Pass 1: column widths. */
    for (i = 0; i < ctx->cfg->num_folders; i++) {
        const ConfigFolder *f = &ctx->cfg->folders[i];
        int w;
        if (f->removed)
            continue;
        w = (int)strlen(folder_name(f));
        if (w > nw) nw = w;
        w = (int)strlen(f->path);
        if (w > pw) pw = w;
    }
    {
        OfferedFolder of;
        int oi;
        for (oi = 0; offered_get(oi, &of); oi++) {
            int w;
            if (!of.id[0] || sync_folder_index(ctx->cfg, of.id) >= 0)
                continue;
            w = (int)strlen(of.label[0] ? of.label : of.id);
            if (w > nw) nw = w;
        }
    }
    if (nw > 28) nw = 28;
    if (pw > 24) pw = 24;

    /* Pass 2: the rows. */
    for (i = 0; i < ctx->cfg->num_folders && l->n < SW_ITEMS_MAX; i++) {
        const ConfigFolder *f = &ctx->cfg->folders[i];
        SWItem            *it;
        unsigned long long bytes = 0;
        int                files = 0, dirs = 0, j, cverb = 0;
        long               sday = 0, smin = 0;
        int                have_stats = ctx->folders != NULL;
        int                pend, kept, rev;
        char               cname[BEP_PATH_MAX];
        char               state[40], sz[24], dur[24];

        if (f->removed)
            continue;

        if (have_stats) {
            FolderState *fs = &ctx->folders[i];
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
        }

        /* The folder's live state, Syncthing-style: fetch backlog across
         * every connected worker beats everything, a never-finished first
         * scan shows as Scanning, otherwise it is up to date. */
        pend = peer_folder_pending(ctx->pm, i);
        kept = peer_folder_kept(ctx->pm, i);
        rev  = peer_folder_reverted(ctx->pm, i);
        if (pend > 0)
            sprintf(state, "Syncing (%d file%s)", pend, pend == 1 ? "" : "s");
        else if (have_stats && !sday && !smin)
            strcpy(state, "Scanning");
        else if (rev > 0)
            /* Ahead of Kept: that is a disagreement, this is something the
             * user wrote here that has been overwritten and now survives only
             * in .stversions. */
            sprintf(state, "Replaced (%d)", rev);
        else if (kept > 0)
            /* Nothing to fetch, but a peer counts us out of sync for these. */
            sprintf(state, "Kept (%d)", kept);
        else
            strcpy(state, "Up to Date");

        it = &l->items[l->n++];
        it->kind = LK_FOLDER;
        it->idx  = i;
        sprintf(it->key, "F:%.64s", f->id);
        it->head[0] = '\0';
        padcat(it->head, SW_LINE_MAX, folder_name(f), nw, 2);
        padcat(it->head, SW_LINE_MAX, f->path, pw, 2);
        padcat(it->head, SW_LINE_MAX, mode_disp(f->mode), 14, 2);
        it->state_col = (int)strlen(it->head);
        padcat(it->head, SW_LINE_MAX, state, (int)strlen(state), 0);

        /* Expansion details, each ONLY when it says something the row
         * above doesn't: the folder id (when a label hides it), the full
         * path (when the column truncated it). */
        it->ndet = 0;
        if (strcmp(folder_name(f), f->id) != 0)
            det_add(it, "    id: %s", f->id);
        if ((int)strlen(f->path) > pw)
            det_add(it, "    %s", f->path);
        if (have_stats) {
            arexx_fmt_size(bytes, sz);
            if (sday || smin) {
                arexx_fmt_dur(arexx_mins_since(sday, smin), dur);
                det_add(it, "    %d file%s, %d dir%s, %s - scanned %s ago",
                        files, files == 1 ? "" : "s",
                        dirs, dirs == 1 ? "" : "s", sz, dur);
            } else {
                det_add(it, "    %d file%s, %d dir%s, %s - not scanned yet",
                        files, files == 1 ? "" : "s",
                        dirs, dirs == 1 ? "" : "s", sz);
            }
            if (cverb)
                det_add(it, "    latest change: %s %s",
                        cverb == FOLDSTATE_CHG_DELETED ? "deleted" :
                        cverb == FOLDSTATE_CHG_ADDED   ? "added"   : "updated",
                        cname);
            else
                det_add(it, "    latest change: (none yet)");
        }
        if (it->ndet > l->max_det)
            l->max_det = it->ndet;
    }

    {
        OfferedFolder of;
        int oi, split = l->n;         /* configured / offered boundary */
        for (oi = 0; offered_get(oi, &of) && l->n < SW_ITEMS_MAX; oi++) {
            SWItem *it;
            if (!of.id[0] || sync_folder_index(ctx->cfg, of.id) >= 0)
                continue;
            it = &l->items[l->n++];
            it->kind = LK_OFFER;
            it->idx  = oi;
            sprintf(it->key, "O:%.64s", of.id);
            /* No marker glyph: the "Offered" badge in the State column
             * (FILLPEN, like device states) carries the meaning; Path and
             * Mode stay honestly empty - no local drawer exists yet. */
            it->head[0] = '\0';
            padcat(it->head, SW_LINE_MAX,
                   of.label[0] ? of.label : of.id, nw, 2);
            padcat(it->head, SW_LINE_MAX, "", pw, 2);
            padcat(it->head, SW_LINE_MAX, "", 14, 2);
            it->state_col = (int)strlen(it->head);
            padcat(it->head, SW_LINE_MAX, "Offered", 7, 0);
            it->ndet = 0;
            if (of.label[0] && strcmp(of.label, of.id) != 0)
                det_add(it, "    id: %s", of.id);
            det_add(it, "    offered by %s",
                    of.device_name[0] ? of.device_name : "?");
            if (it->ndet > l->max_det)
                l->max_det = it->ndet;
        }
        sort_items(l->items, 0, split);       /* configured, by name */
        sort_items(l->items, split, l->n);    /* then offered, by name */
    }

    /* The bold column header, aligned with the fields above. */
    l->header[0] = '\0';
    padcat(l->header, SW_LINE_MAX, "Name", nw, 2);
    padcat(l->header, SW_LINE_MAX, "Path", pw, 2);
    padcat(l->header, SW_LINE_MAX, "Mode", 14, 2);
    padcat(l->header, SW_LINE_MAX, "State", 5, 0);
    rtrim(l->header);
}

/* Rebuild the Remote Devices list: configured peers first, then devices
 * local discovery has seen that are NOT configured ("Discovered" badge). */
static void build_device_items(StatusWin *sw, const ArexxContext *ctx)
{
    SWList *l = &sw->dl;
    int     i, n, nw = 4, aw = 7;   /* min widths: the header words        */

    l->n = 0;
    l->max_det = 1;
    if (!ctx)
        return;

    n = peer_count(ctx->pm);

    /* Pass 1: column widths. */
    for (i = 0; i < n; i++) {
        const char *host = "", *rname, *rclient;
        unsigned short port = 0;
        char addr[80];
        int  w;
        if (!peer_info(ctx->pm, i, NULL, NULL, NULL, &host, &port))
            continue;
        peer_xfer_info(ctx->pm, i, NULL, NULL, &rname, &rclient);
        w = (int)strlen(rname[0] ? rname : "?");
        if (w > nw) nw = w;
        if (host[0])
            sprintf(addr, "%.64s:%u", host, (unsigned)port);
        else
            strcpy(addr, "(discovering)");
        w = (int)strlen(addr);
        if (w > aw) aw = w;
    }
    if (ctx->seen) {
        for (i = 0; i < ctx->seen->n; i++) {
            char addr[80];
            int  w;
            if (peer_manager_has(ctx->pm, ctx->seen->e[i].id))
                continue;
            sprintf(addr, "%.64s:%u", ctx->seen->e[i].host,
                    (unsigned)ctx->seen->e[i].port);
            w = (int)strlen(addr);
            if (w > aw) aw = w;
        }
    }
    if (nw > 16) nw = 16;
    if (aw > 22) aw = 22;

    /* Pass 2: configured peers. */
    for (i = 0; i < n && l->n < SW_ITEMS_MAX; i++) {
        int                running = 0, connected = 0, paused = 0;
        const char        *host = "", *rname, *rclient;
        unsigned short     port = 0;
        unsigned long long in, out;
        const ConfigPeer  *p = peer_info(ctx->pm, i, &running, &connected,
                                         &paused, &host, &port);
        SWItem            *it;
        char               sid[8], addr[80], state[32];
        char               sz1[24], sz2[24];
        if (!p)
            continue;
        it = &l->items[l->n++];
        it->kind   = LK_DEVICE;
        it->idx    = i;
        it->paused = paused;
        sprintf(it->key, "D:%.64s", p->id);
        short_id(sid, p->id);
        /* Connected devices get Syncthing's per-device state: our live fetch
         * backlog from them - 0 means we hold everything they announced. */
        if (connected) {
            int pend = peer_pending(ctx->pm, i);
            if (pend > 0)
                sprintf(state, "Syncing (%d file%s)",
                        pend, pend == 1 ? "" : "s");
            else
                strcpy(state, "Up to Date");
        } else {
            strcpy(state, paused ? "Paused" : running ? "Connecting" : "Idle");
        }
        if (host[0])
            sprintf(addr, "%.64s:%u", host, (unsigned)port);
        else
            strcpy(addr, "(discovering)");
        peer_xfer_info(ctx->pm, i, &in, &out, &rname, &rclient);

        it->head[0] = '\0';
        padcat(it->head, SW_LINE_MAX, rname[0] ? rname : "?", nw, 2);
        padcat(it->head, SW_LINE_MAX, sid, 7, 2);
        padcat(it->head, SW_LINE_MAX, addr, aw, 2);
        it->state_col = (int)strlen(it->head);
        padcat(it->head, SW_LINE_MAX, state, (int)strlen(state), 0);

        /* Client identity only - the Name column already names the device
         * (a detail line never repeats the collapsed row). */
        it->ndet = 0;
        det_add(it, "    %s", rclient[0] ? rclient : "(no connection yet)");
        arexx_fmt_size(in, sz1);
        arexx_fmt_size(out, sz2);
        det_add(it, "    received %s, sent %s", sz1, sz2);
        if (it->ndet > l->max_det)
            l->max_det = it->ndet;
    }

    /* Discovered, unconfigured devices. */
    {
        int split = l->n;             /* configured / discovered boundary */
        if (ctx->seen) {
            for (i = 0; i < ctx->seen->n && l->n < SW_ITEMS_MAX; i++) {
                const DiscoSeenEntry *e = &ctx->seen->e[i];
                SWItem *it;
                char    sid[8], addr[80];
                if (peer_manager_has(ctx->pm, e->id))
                    continue;
                it = &l->items[l->n++];
                it->kind   = LK_DISCO;
                it->idx    = i;
                it->paused = 0;
                sprintf(it->key, "S:%.64s", e->id);
                short_id(sid, e->id);
                sprintf(addr, "%.64s:%u", e->host, (unsigned)e->port);
                it->head[0] = '\0';
                padcat(it->head, SW_LINE_MAX, "?", nw, 2);
                padcat(it->head, SW_LINE_MAX, sid, 7, 2);
                padcat(it->head, SW_LINE_MAX, addr, aw, 2);
                it->state_col = (int)strlen(it->head);
                padcat(it->head, SW_LINE_MAX, "Discovered", 10, 0);
                it->ndet = 0;
                det_add(it, "    seen on the LAN - not configured");
                if (it->ndet > l->max_det)
                    l->max_det = it->ndet;
            }
        }
        sort_items(l->items, 0, split);       /* configured, by name */
        sort_items(l->items, split, l->n);    /* then discovered */
    }

    l->header[0] = '\0';
    padcat(l->header, SW_LINE_MAX, "Name", nw, 2);
    padcat(l->header, SW_LINE_MAX, "ID", 7, 2);
    padcat(l->header, SW_LINE_MAX, "Address", aw, 2);
    padcat(l->header, SW_LINE_MAX, "State", 5, 0);
    rtrim(l->header);
}

/* The selected item, or NULL. */
static SWItem *list_selected(SWList *l)
{
    int i;
    if (!l->sel_key[0])
        return NULL;
    for (i = 0; i < l->n; i++)
        if (strcmp(l->items[i].key, l->sel_key) == 0)
            return &l->items[i];
    return NULL;
}

/* Content rows: one per item plus the selected item's expansion (or the
 * one-row "(none)" placeholder). */
static int list_total_rows(SWList *l)
{
    SWItem *sel = list_selected(l);
    int t = l->n ? l->n : 1;
    if (sel)
        t += sel->ndet;
    return t;
}

/* Natural visible rows: every item plus one expansion's slack, so
 * expanding never needs a window resize. */
static int list_natural_rows(SWList *l)
{
    int r = (l->n ? l->n : 1) + l->max_det;
    return r < 3 ? 3 : r;
}

/* Rebuild both lists and the This Device values from the daemon state. */
static void build_model(StatusWin *sw, const ArexxContext *ctx)
{
    build_folder_items(sw, ctx);
    build_device_items(sw, ctx);

    if (!list_selected(&sw->fl))
        sw->fl.sel_key[0] = '\0';       /* vanished item: deselect */
    if (!list_selected(&sw->dl))
        sw->dl.sel_key[0] = '\0';

    sprintf(sw->fl_title, "Folders (%d)", sw->fl.n);
    sprintf(sw->dl_title, "Remote Devices (%d)", sw->dl.n);
    /* Titles count everything in the list, offered/discovered included -
     * matching what the two lists actually show. */

    strcpy(sw->status, "(no daemon state)");
    sw->td_id[0] = sw->td_up[0] = sw->td_rx[0] = sw->td_tx[0] = '\0';
    strcpy(sw->td_li, "off");
    strcpy(sw->td_di, "off");
    if (ctx && ctx->cfg) {
        char dur[24];
        unsigned long long tin = 0, tout = 0, in, out;
        int i;

        peer_manager_status(ctx->pm, sw->status, sizeof(sw->status),
                            NULL, NULL);
        if (ctx->our_id && ctx->our_id[0])
            sprintf(sw->td_id, "%.7s (%.32s)", ctx->our_id,
                    ctx->cfg->device_name);
        arexx_fmt_dur(arexx_mins_since(ctx->start_day, ctx->start_min), dur);
        strcpy(sw->td_up, dur);
        for (i = 0; i < peer_count(ctx->pm); i++) {
            peer_xfer_info(ctx->pm, i, &in, &out, NULL, NULL);
            tin += in;
            tout += out;
        }
        arexx_fmt_size(tin, sw->td_rx);
        arexx_fmt_size(tout, sw->td_tx);
        if (ctx->listener)
            sprintf(sw->td_li, "on (port %u)",
                    (unsigned)ctx->cfg->listen_port);
        sprintf(sw->td_di, "%s", ctx->cfg->discovery ? "on" : "off");
    }
}

/* ---- layout ------------------------------------------------------------ */

/* Place one list group - title, column header, bevelled row area and its
 * button row - starting at 'y'. Returns the group's bottom edge. Both lists
 * go through here so the spacing constants exist once; a tweak that reached
 * only one of them used to show up as a subtle misalignment. */
static int layout_list(StatusWin *sw, SWList *l, int y, int rows, int cx, int cw)
{
    int rh = sw->font->tf_YSize + SW_LEADING;

    l->title_y = y;
    l->hdr_y   = y + rh + 3;
    l->rows    = rows;
    l->bev_x   = cx;
    l->bev_y   = l->hdr_y + rh + 1;
    l->bev_w   = cw - SW_SCR_W;
    l->bev_h   = rows * rh + 4;
    l->tx      = cx + 2;
    l->ty      = l->bev_y + 2;
    l->cols    = (l->bev_w - 4) / sw->font->tf_XSize;
    l->btn_y   = l->bev_y + l->bev_h + 4;
    l->grp_end = l->btn_y + SW_BT_H + 3 + 2;
    return l->grp_end;
}

/* Lay the window out for the given visible list rows, storing every position,
 * and return the needed inner height.
 *
 * SIDE EFFECT: this WRITES sw->fl and sw->dl's geometry every time, including
 * when it is called only to measure a hypothetical size (desired_inner,
 * layout_actual's 'base', statuswin_show's min_h). A measuring call therefore
 * leaves the lists laid out for rows nobody is about to draw. Every caller
 * today follows a measure with layout_actual before anything renders - keep
 * it that way: drawing against a measurement is a window painted to a
 * geometry that is not on screen. */
static int layout(StatusWin *sw, int rows_f, int rows_d)
{
    int rh = sw->font->tf_YSize + SW_LEADING;
    int bl = sw->win ? sw->win->BorderLeft : 4;
    int bt = sw->win ? sw->win->BorderTop : 11;
    int w  = sw->win ? sw->win->Width -
                       (sw->win->BorderLeft + sw->win->BorderRight) : 640;
    int fx  = bl + SW_PAD;
    int fx2 = bl + w - 1 - SW_PAD;
    int cx  = fx + SW_GPAD;
    int cw  = fx2 - SW_GPAD - cx;
    int y;

    sw->band_h = (sw->logo_h > 2 * rh ? sw->logo_h : 2 * rh);
    y = bt + SW_PAD + sw->band_h + SW_GGAP;

    /* This Device */
    sw->td_y     = y;
    sw->td_val_y = y + rh + 3;
    y = sw->td_val_y + 3 * rh + 3 + 2 + SW_GGAP;

    y = layout_list(sw, &sw->fl, y, rows_f, cx, cw) + SW_GGAP;   /* Folders */
    y = layout_list(sw, &sw->dl, y, rows_d, cx, cw);       /* Remote Devices */

    /* air above the rule + the rule/button band itself */
    return (y - bt) + SW_GGAP + SW_BROW_H;
}

/* Character column where This Device's right-hand column starts: past the
 * 11-char key and the device id, with a floor so the grid does not collapse
 * on a short id. content_cols measures with it and draw_tdev draws with it,
 * so the two cannot disagree - the window used to be measured for a layout
 * it no longer drew. */
static int tdev_colb(const StatusWin *sw)
{
    int colb = 11 + (int)strlen(sw->td_id) + 3;
    return colb < 32 ? 32 : colb;
}

/* Longest STRUCTURAL text line the window wants to show, in characters:
 * head rows, column headers and the This Device grid. Detail lines are
 * deliberately EXCLUDED - they are hidden while collapsed, and a long
 * "latest change" filename arriving on a tick once widened the whole
 * window for text nobody could see. Details truncate at draw instead
 * (and a user widening the window by hand is respected as always). */
static int content_cols(StatusWin *sw)
{
    int c = (int)strlen(SW_TITLE), i, l;

    l = (int)strlen(sw->fl.header);
    if (l > c) c = l;
    l = (int)strlen(sw->dl.header);
    if (l > c) c = l;
    for (i = 0; i < sw->fl.n; i++) {
        l = (int)strlen(sw->fl.items[i].head);
        if (l > c) c = l;
    }
    for (i = 0; i < sw->dl.n; i++) {
        l = (int)strlen(sw->dl.items[i].head);
        if (l > c) c = l;
    }
    /* This Device rows, composed as draw_tdev does: left column of width
     * colb, then a 10-char key + the right value. */
    {
        int colb = tdev_colb(sw);
        l = colb + 11 + (int)strlen(sw->td_li);
        if (l > c) c = l;
        l = colb + 11 + (int)strlen(sw->td_tx);
        if (l > c) c = l;
    }
    if (c < 48) c = 48;                 /* room for the button rows */
    return c;
}

/* The INNER window size the current content wants. Measures via layout(), so
 * it leaves the stored geometry set for the natural row counts - see layout().
 */
static void desired_inner(StatusWin *sw, int *iw, int *ih)
{
    *iw = 2 * SW_PAD + 2 * SW_GPAD + 4 + SW_SCR_W +
          content_cols(sw) * sw->font->tf_XSize;
    *ih = layout(sw, list_natural_rows(&sw->fl),
                     list_natural_rows(&sw->dl));
}

/* ...and the outer size, from the OPEN window's actual borders. (The
 * window is opened with WA_InnerWidth/Height precisely so no border
 * guessing happens - a guessed outer size made the window visibly hop
 * a few pixels wider on the first tick.) */
static void desired_size(StatusWin *sw, int *ow, int *oh)
{
    desired_inner(sw, ow, oh);
    *ow += sw->win->BorderLeft + sw->win->BorderRight;
    *oh += sw->win->BorderTop + sw->win->BorderBottom;
}

/* Lay out against the window's ACTUAL size: split the height the lists can
 * have between them (proportional to their natural rows, min 2 each). */
static void layout_actual(StatusWin *sw)
{
    int rh   = sw->font->tf_YSize + SW_LEADING;
    int have = sw->win->Height - sw->win->BorderTop - sw->win->BorderBottom;
    int base = layout(sw, 0, 0);
    int avail, nf, nd, rf, rd;

    avail = (have - base) / rh;
    nf = list_natural_rows(&sw->fl);
    nd = list_natural_rows(&sw->dl);
    if (avail >= nf + nd) {
        /* everything fits; spare rows go to the lists, folders first */
        int spare = avail - nf - nd;
        rf = nf + (spare + 1) / 2;
        rd = nd + spare / 2;
    } else {
        rf = avail * nf / (nf + nd);
        if (rf < 2) rf = 2;
        rd = avail - rf;
        if (rd < 2) rd = 2;
    }
    layout(sw, rf, rd);

    /* Clamp scroll positions to the new geometry. */
    {
        int t = list_total_rows(&sw->fl);
        if (sw->fl.top > t - sw->fl.rows) sw->fl.top = t - sw->fl.rows;
        if (sw->fl.top < 0) sw->fl.top = 0;
        t = list_total_rows(&sw->dl);
        if (sw->dl.top > t - sw->dl.rows) sw->dl.top = t - sw->dl.rows;
        if (sw->dl.top < 0) sw->dl.top = 0;
    }
}

/* ---- drawing ----------------------------------------------------------- */

/* Bold text: 1-px overstrike (deterministic on every renderer, unlike
 * SetSoftStyle's algorithmic bold). Draws at (x, baseline of row y). */
static void text_bold(StatusWin *sw, int x, int y, const char *s, int len)
{
    struct RastPort *rp = sw->win->RPort;

    Move(rp, x, y + sw->font->tf_Baseline);
    Text(rp, (STRPTR)s, (ULONG)len);
    SetDrMd(rp, JAM1);
    Move(rp, x + 1, y + sw->font->tf_Baseline);
    Text(rp, (STRPTR)s, (ULONG)len);
    SetDrMd(rp, JAM2);
}

/* A group frame: a 2-px groove (SHADOW outline with a SHINE outline offset
 * +1,+1) from the title row's middle down to y2, with the bold title
 * punched into the top edge. */
static void draw_group_frame(StatusWin *sw, const char *title,
                             int title_y, int y2)
{
    struct RastPort *rp = sw->win->RPort;
    int fx  = sw->win->BorderLeft + SW_PAD;
    int fx2 = sw->win->Width - sw->win->BorderRight - 1 - SW_PAD;
    int ty  = title_y + 4;
    char buf[64];

    SetDrMd(rp, JAM1);
    SetAPen(rp, sw->shadowpen);
    Move(rp, fx, ty);           Draw(rp, fx2 - 1, ty);        /* top    */
    Move(rp, fx, ty);           Draw(rp, fx, y2 - 1);         /* left   */
    Move(rp, fx, y2 - 1);       Draw(rp, fx2 - 1, y2 - 1);    /* bottom */
    Move(rp, fx2 - 1, ty);      Draw(rp, fx2 - 1, y2 - 1);    /* right  */
    SetAPen(rp, sw->shinepen);
    Move(rp, fx + 1, ty + 1);   Draw(rp, fx2, ty + 1);
    Move(rp, fx + 1, ty + 1);   Draw(rp, fx + 1, y2);
    Move(rp, fx + 1, y2);       Draw(rp, fx2, y2);
    Move(rp, fx2, ty + 1);      Draw(rp, fx2, y2);
    SetDrMd(rp, JAM2);

    sprintf(buf, " %.40s ", title);     /* the spaces punch the groove */
    SetAPen(rp, sw->textpen);
    SetBPen(rp, sw->bgpen);
    text_bold(sw, fx + 10, title_y, buf, (int)strlen(buf));
}

/* A recessed 1-px bevel around a list body. */
static void draw_list_bevel(StatusWin *sw, SWList *l)
{
    struct RastPort *rp = sw->win->RPort;
    int x2 = l->bev_x + l->bev_w - 1;
    int y2 = l->bev_y + l->bev_h - 1;

    SetDrMd(rp, JAM1);
    SetAPen(rp, sw->shadowpen);
    Move(rp, l->bev_x, y2);  Draw(rp, l->bev_x, l->bev_y);
    Draw(rp, x2, l->bev_y);
    SetAPen(rp, sw->shinepen);
    Move(rp, x2, l->bev_y + 1);  Draw(rp, x2, y2);  Draw(rp, l->bev_x, y2);
    SetDrMd(rp, JAM2);
}

/* One text row inside a list bevel. 'sel' inverts it (FILLPEN row, like a
 * listview selection); 'state_col' >= 0 draws that tail in FILLPEN bold. */
static void draw_list_row(StatusWin *sw, SWList *l, int vis_row,
                          const char *text, int sel, int state_col)
{
    struct RastPort *rp = sw->win->RPort;
    int fw  = sw->font->tf_XSize;
    int rh  = sw->font->tf_YSize + SW_LEADING;
    int y   = l->ty + vis_row * rh;
    int len = (int)strlen(text);
    int shown = len > l->cols ? l->cols : len;
    int x2  = l->bev_x + l->bev_w - 2;

    if (sel) {
        SetDrMd(rp, JAM1);
        SetAPen(rp, sw->fillpen);
        RectFill(rp, l->bev_x + 1, y, x2, y + rh - 1);
        SetDrMd(rp, JAM2);
        SetAPen(rp, sw->filltextpen);
        SetBPen(rp, sw->fillpen);
        if (shown > 0) {
            Move(rp, l->tx, y + sw->font->tf_Baseline);
            Text(rp, (STRPTR)text, (ULONG)shown);
        }
        SetBPen(rp, sw->bgpen);
        return;
    }

    SetAPen(rp, sw->textpen);
    SetBPen(rp, sw->bgpen);
    if (shown > 0) {
        Move(rp, l->tx, y + sw->font->tf_Baseline);
        Text(rp, (STRPTR)text, (ULONG)shown);
        if (state_col >= 0 && state_col < shown) {
            SetAPen(rp, sw->fillpen);
            text_bold(sw, l->tx + state_col * fw, y,
                      text + state_col, shown - state_col);
            SetAPen(rp, sw->textpen);
        }
    }
    /* tail fill to the bevel edge (JAM1: plain background wash) */
    SetDrMd(rp, JAM1);
    SetAPen(rp, sw->bgpen);
    RectFill(rp, l->tx + shown * fw, y, x2, y + rh - 1);
    if (l->tx > l->bev_x + 1)
        RectFill(rp, l->bev_x + 1, y, l->tx - 1, y + rh - 1);
    /* JAM2 text only covers the 8-px glyph cells - the row's 2-px leading
     * strip keeps whatever was there before (FILLPEN, when this position
     * showed a selected row). Wash it explicitly. */
    if (shown > 0 && rh > sw->font->tf_YSize)
        RectFill(rp, l->tx, y + sw->font->tf_YSize,
                 l->tx + shown * fw - 1, y + rh - 1);
    SetDrMd(rp, JAM2);
}

/* Redraw a list body in place: heads, the selected expansion, "(none)"
 * placeholder, blanked slack rows. Flicker-free (JAM2 cells + tail fills,
 * no clear). */
static void draw_list(StatusWin *sw, SWList *l)
{
    struct RastPort *rp = sw->win->RPort;
    SWItem *sel = list_selected(l);
    int r = 0, vis = 0, i;

    SetFont(rp, sw->font);
    SetDrMd(rp, JAM2);

    if (l->n == 0) {
        if (l->top == 0) {
            draw_list_row(sw, l, vis, "  (none)", 0, -1);
            vis++;
        }
        r = 1;
    }
    for (i = 0; i < l->n && vis < l->rows; i++) {
        SWItem *it = &l->items[i];
        int expanded = (sel == it);
        int k;
        if (r >= l->top && vis < l->rows) {
            draw_list_row(sw, l, vis, it->head, expanded, it->state_col);
            vis++;
        }
        r++;
        for (k = 0; expanded && k < it->ndet; k++) {
            if (r >= l->top && vis < l->rows) {
                draw_list_row(sw, l, vis, it->det[k], 0, -1);
                vis++;
            }
            r++;
        }
    }
    while (vis < l->rows) {             /* blank the slack rows */
        draw_list_row(sw, l, vis, "", 0, -1);
        vis++;
    }
    /* bottom padding sliver inside the bevel */
    {
        int rh = sw->font->tf_YSize + SW_LEADING;
        int y  = l->ty + l->rows * rh;
        int y2 = l->bev_y + l->bev_h - 2;
        if (y <= y2) {
            SetDrMd(rp, JAM1);
            SetAPen(rp, sw->bgpen);
            RectFill(rp, l->bev_x + 1, y, l->bev_x + l->bev_w - 2, y2);
            SetDrMd(rp, JAM2);
        }
    }
}

/* Push a list's scroll state into its GadTools scroller. */
static void update_scroller(StatusWin *sw, SWList *l)
{
    if (l->scroller)
        GT_SetGadgetAttrs(l->scroller, sw->win, NULL,
                          GTSC_Top,     l->top,
                          GTSC_Visible, l->rows,
                          GTSC_Total,   list_total_rows(l),
                          TAG_DONE);
}

/* This Device: three key/value rows in two columns, redrawn in place. */
static void draw_tdev(StatusWin *sw)
{
    struct RastPort *rp = sw->win->RPort;
    int fw = sw->font->tf_XSize;
    int rh = sw->font->tf_YSize + SW_LEADING;
    int cx = sw->win->BorderLeft + SW_PAD + SW_GPAD;
    int cw = sw->win->Width - sw->win->BorderRight - 1 - SW_PAD - SW_GPAD - cx;
    int cols = cw / fw;
    int colb;                            /* char col of the right column */
    char line[3][SW_LINE_MAX];
    int  i;

    colb = tdev_colb(sw);

    line[0][0] = '\0';
    padcat(line[0], SW_LINE_MAX, "Device ID", 10, 1);
    padcat(line[0], SW_LINE_MAX, sw->td_id, colb - 11 - 1, 1);
    padcat(line[0], SW_LINE_MAX, "Listener", 10, 1);
    padcat(line[0], SW_LINE_MAX, sw->td_li, (int)strlen(sw->td_li), 0);

    line[1][0] = '\0';
    padcat(line[1], SW_LINE_MAX, "Uptime", 10, 1);
    padcat(line[1], SW_LINE_MAX, sw->td_up, colb - 11 - 1, 1);
    padcat(line[1], SW_LINE_MAX, "Discovery", 10, 1);
    padcat(line[1], SW_LINE_MAX, sw->td_di, (int)strlen(sw->td_di), 0);

    line[2][0] = '\0';
    padcat(line[2], SW_LINE_MAX, "Received", 10, 1);
    padcat(line[2], SW_LINE_MAX, sw->td_rx, colb - 11 - 1, 1);
    padcat(line[2], SW_LINE_MAX, "Sent", 10, 1);
    padcat(line[2], SW_LINE_MAX, sw->td_tx, (int)strlen(sw->td_tx), 0);

    SetFont(rp, sw->font);
    SetDrMd(rp, JAM2);
    SetAPen(rp, sw->textpen);
    SetBPen(rp, sw->bgpen);
    for (i = 0; i < 3; i++) {
        int len = (int)strlen(line[i]);
        int shown = len > cols ? cols : len;
        int y = sw->td_val_y + i * rh;
        if (shown > 0) {
            Move(rp, cx, y + sw->font->tf_Baseline);
            Text(rp, (STRPTR)line[i], (ULONG)shown);
        }
        SetDrMd(rp, JAM1);
        SetAPen(rp, sw->bgpen);
        RectFill(rp, cx + shown * fw, y, cx + cols * fw - 1, y + rh - 1);
        SetDrMd(rp, JAM2);
        SetAPen(rp, sw->textpen);
    }
}

/* Draw the AppIcon's imagery at (x, y). icon.library V44+ renders the icon
 * properly (including a PNG/GlowIcon second image); older versions get the
 * plain gadget render. Both the band and the About card go through here so
 * the version fallback exists once. */
static void draw_logo(StatusWin *sw, struct RastPort *rp, int x, int y)
{
    if (!sw->dobj)
        return;
    if (IconBase && IconBase->lib_Version >= 44)
        DrawIconStateA(rp, sw->dobj, NULL, x, y, IDS_NORMAL, NULL);
    else if (sw->dobj->do_Gadget.GadgetRender)
        DrawImage(rp, (struct Image *)sw->dobj->do_Gadget.GadgetRender, x, y);
}

/* Header band: logo, bold product line, aggregate status (FILLPEN bold),
 * redrawn in place on ticks (only the status line actually changes). */
static void draw_band(StatusWin *sw)
{
    struct RastPort *rp = sw->win->RPort;
    int fw = sw->font->tf_XSize;
    int rh = sw->font->tf_YSize + SW_LEADING;
    int x0 = sw->win->BorderLeft + SW_PAD;
    int y0 = sw->win->BorderTop + SW_PAD;
    int tx = x0 + (sw->logo_w > 0 ? sw->logo_w + 2 * SW_PAD : 0);
    int ty = y0 + (sw->band_h - 2 * rh) / 2;
    int cols = (sw->win->Width - sw->win->BorderRight - SW_PAD - tx) / fw;
    int len, shown;

    if (ty < y0)
        ty = y0;

    if (sw->logo_w > 0)
        draw_logo(sw, rp, x0, y0);

    SetFont(rp, sw->font);
    SetDrMd(rp, JAM2);
    SetBPen(rp, sw->bgpen);
    SetAPen(rp, sw->textpen);
    len = (int)strlen(SW_TITLE);
    shown = len > cols ? cols : len;
    text_bold(sw, tx, ty, SW_TITLE, shown);

    SetAPen(rp, sw->fillpen);
    len = (int)strlen(sw->status);
    shown = len > cols ? cols : len;
    text_bold(sw, tx, ty + rh, sw->status, shown);
    if (shown < cols) {                 /* erase a longer previous status */
        SetDrMd(rp, JAM1);
        SetAPen(rp, sw->bgpen);
        RectFill(rp, tx + shown * fw, ty + rh,
                 tx + cols * fw - 1, ty + 2 * rh - 1);
        SetDrMd(rp, JAM2);
    }
    SetAPen(rp, sw->textpen);
}

/* A recessed horizontal rule across the window body at 'y' (2 px). */
static void draw_rule(StatusWin *sw, int y)
{
    struct RastPort *rp = sw->win->RPort;

    SetAPen(rp, sw->shadowpen);
    Move(rp, sw->win->BorderLeft, y);
    Draw(rp, sw->win->Width - sw->win->BorderRight - 1, y);
    SetAPen(rp, sw->shinepen);
    Move(rp, sw->win->BorderLeft, y + 1);
    Draw(rp, sw->win->Width - sw->win->BorderRight - 1, y + 1);
}

/* One list group: its frame, column header, bevel and rows. */
static void draw_list_group(StatusWin *sw, SWList *l, const char *title, int cx)
{
    struct RastPort *rp  = sw->win->RPort;
    int              len = (int)strlen(l->header);

    draw_group_frame(sw, title, l->title_y, l->grp_end - 2);
    SetAPen(rp, sw->textpen);
    SetBPen(rp, sw->bgpen);
    text_bold(sw, cx, l->hdr_y, l->header, len > l->cols ? l->cols : len);
    draw_list_bevel(sw, l);
    draw_list(sw, l);
}

/* Full repaint: background, band, the three groups, both lists, the rule
 * above the bottom row (gadgets refresh themselves). Used at open, after a
 * resize, and on damage refresh. */
static void draw_full(StatusWin *sw)
{
    struct RastPort *rp = sw->win->RPort;
    int cx = sw->win->BorderLeft + SW_PAD + SW_GPAD;

    SetDrMd(rp, JAM1);
    SetAPen(rp, sw->bgpen);
    RectFill(rp, sw->win->BorderLeft, sw->win->BorderTop,
                 sw->win->Width  - sw->win->BorderRight  - 1,
                 sw->win->Height - sw->win->BorderBottom - 1);
    SetDrMd(rp, JAM2);
    SetFont(rp, sw->font);

    draw_band(sw);

    draw_group_frame(sw, "This Device", sw->td_y, sw->td_val_y + 3 *
                     (sw->font->tf_YSize + SW_LEADING) + 3);
    draw_tdev(sw);

    draw_list_group(sw, &sw->fl, sw->fl_title, cx);
    draw_list_group(sw, &sw->dl, sw->dl_title, cx);

    draw_rule(sw, sw->win->Height - sw->win->BorderBottom - SW_BROW_H);

    sw->nf_last = sw->fl.n;
    sw->nd_last = sw->dl.n;
}

/* ---- gadgets ------------------------------------------------------------ */

/* True when every configured peer is paused (the Pause All label). */
static int all_paused(const ArexxContext *ctx)
{
    int i, n, paused_n = 0;

    n = ctx ? peer_count(ctx->pm) : 0;
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        int pa = 0;
        if (peer_info(ctx->pm, i, NULL, NULL, &pa, NULL, NULL) && pa)
            paused_n++;
    }
    return paused_n == n;
}

/* Ghosting: enable each verb exactly when the selection it acts on is
 * there (the design rule: verbs never hide, they ghost). */
static void update_disables(StatusWin *sw)
{
    SWItem *fs = list_selected(&sw->fl);
    SWItem *ds = list_selected(&sw->dl);

#define SW_EN(g, on) \
    if (g) GT_SetGadgetAttrs(g, sw->win, NULL, GA_Disabled, !(on), TAG_DONE)
    /* Add... is a global verb, but it ghosts while an OFFER is selected:
     * two lit "get a folder" buttons invite the wrong click - with an
     * offer selected, Accept... is the path. */
    SW_EN(sw->g_fadd,    !(fs && fs->kind == LK_OFFER));
    SW_EN(sw->g_fopen,   fs && fs->kind == LK_FOLDER);
    SW_EN(sw->g_frescan, fs && fs->kind == LK_FOLDER);
    SW_EN(sw->g_faccept, fs && fs->kind == LK_OFFER);
    SW_EN(sw->g_fremove, fs && fs->kind == LK_FOLDER);
    SW_EN(sw->g_dadd,    ds && ds->kind == LK_DISCO);
    SW_EN(sw->g_dpause,  ds && ds->kind == LK_DEVICE);
    SW_EN(sw->g_dremove, ds && ds->kind == LK_DEVICE);
#undef SW_EN
}

/* Remove the gadget list from the window (if attached), free it, and clear
 * every pointer into it. One place, because a missed pointer here is a
 * dangling gadget the next click follows - a machine-down bug, not a log line.
 * 'attached' is 0 when the list was never AddGList'd (a build that failed
 * partway). */
static void drop_gadgets(StatusWin *sw, int attached)
{
    if (!sw->glist)
        return;
    if (attached)
        RemoveGList(sw->win, sw->glist, -1);
    FreeGadgets(sw->glist);
    sw->glist = NULL;
    sw->fl.scroller = sw->dl.scroller = NULL;
    sw->g_fadd = sw->g_fopen = sw->g_frescan = sw->g_faccept =
        sw->g_fremove = NULL;
    sw->g_dadd = sw->g_dpause = sw->g_dremove = NULL;
}

/* Is 'g' a gadget of the CURRENT list? Intuition queues a gadget message
 * before the message is read, and this window rebuilds its gadgets often - on
 * every resize, every item-count change and every flip-label - so a click
 * landing just before a rebuild leaves a message whose IAddress points into
 * the list that rebuild freed. Reading a GadgetID out of that is a stray verb
 * (Stop..., Remove...) or worse, from memory that now belongs to something
 * else. The pointer is only ever COMPARED here, never followed, so checking
 * it against the live chain costs one walk of a dozen gadgets and makes the
 * dispatch below safe. */
static int gadget_is_live(const StatusWin *sw, const struct Gadget *g)
{
    const struct Gadget *p;

    for (p = sw->glist; p; p = p->NextGadget)
        if (p == g)
            return 1;
    return 0;
}

/* (Re)build the gadget list for the current layout: the per-list verb rows,
 * the two scrollers, and the bottom row. Called at open, after every
 * resize, and when a flip-label (Pause All/Resume All, Pause/Resume) has
 * to change (GadTools buttons cannot relabel in place). */
static int build_gadgets(StatusWin *sw, const ArexxContext *ctx)
{
    struct Gadget   *g;
    struct NewGadget ng;
    SWItem *ds = list_selected(&sw->dl);
    int cx = sw->win->BorderLeft + SW_PAD + SW_GPAD;
    int by = sw->win->Height - sw->win->BorderBottom - SW_BROW_H + 8;
    int x;

    sw->dpause_resume = (ds && ds->kind == LK_DEVICE && ds->paused);

    drop_gadgets(sw, 1);

    g = CreateContext(&sw->glist);
    if (!g)
        return 0;

    memset(&ng, 0, sizeof(ng));
    ng.ng_TextAttr   = &sw_topaz;
    ng.ng_VisualInfo = sw->vi;
    ng.ng_Height     = SW_BT_H;

    /* Folders verbs. Add... first, like the Devices row. */
    ng.ng_TopEdge    = sw->fl.btn_y;
    x = cx;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 6 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Add...";
    ng.ng_GadgetID   = GID_FADD;
    g = sw->g_fadd = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 4 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Open";
    ng.ng_GadgetID   = GID_FOPEN;
    g = sw->g_fopen = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 6 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Rescan";
    ng.ng_GadgetID   = GID_FRESCAN;
    g = sw->g_frescan = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 9 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Accept...";
    ng.ng_GadgetID   = GID_FACCEPT;
    g = sw->g_faccept = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_GadgetText = (STRPTR)"Remove...";
    ng.ng_GadgetID   = GID_FREMOVE;
    g = sw->g_fremove = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);

    /* Remote Devices verbs. */
    ng.ng_TopEdge    = sw->dl.btn_y;
    x = cx;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 6 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Add...";
    ng.ng_GadgetID   = GID_DADD;
    g = sw->g_dadd = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_GadgetText = (STRPTR)(sw->dpause_resume ? "Resume" : "Pause");
    ng.ng_GadgetID   = GID_DPAUSE;
    g = sw->g_dpause = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 9 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Remove...";
    ng.ng_GadgetID   = GID_DREMOVE;
    g = sw->g_dremove = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);

    /* Bottom row: sync verbs left, meta right. "Stop" (not "Quit"): it
     * stops the DAEMON - a service - with a confirm, hence the ellipsis;
     * the close gadget is what closes the window. */
    ng.ng_TopEdge    = by;
    x = sw->win->BorderLeft + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 10 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Rescan All";
    ng.ng_GadgetID   = GID_RESCAN;
    g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    x += ng.ng_Width + SW_PAD;
    ng.ng_LeftEdge   = x;
    ng.ng_Width      = 10 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)(sw->paused_all ? "Resume All" : "Pause All");
    ng.ng_GadgetID   = GID_PAUSEALL;
    g = CreateGadget(BUTTON_KIND, g, &ng,
                     GA_Disabled, ctx && peer_count(ctx->pm) > 0 ? FALSE : TRUE,
                     TAG_DONE);
    {
        int qw = 7 * 8 + 16;                       /* "Stop..."  */
        int lw = 8 * 8 + 16;                       /* "Open Log" */
        /* right-aligned to the group frames' right edge */
        int xr = sw->win->Width - sw->win->BorderRight - SW_PAD;

        ng.ng_LeftEdge   = xr - qw;
        ng.ng_Width      = qw;
        ng.ng_GadgetText = (STRPTR)"Stop...";
        ng.ng_GadgetID   = GID_QUIT;
        g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);

        ng.ng_LeftEdge   = xr - qw - SW_PAD - lw;
        ng.ng_Width      = lw;
        ng.ng_GadgetText = (STRPTR)"Open Log";
        ng.ng_GadgetID   = GID_OPENLOG;
        g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    }

    /* One scroller per list, permanent (listview-style furniture). */
    {
        SWList *ls[2];
        int     ids[2] = { GID_FSCROLL, GID_DSCROLL };
        int     i;
        ls[0] = &sw->fl;
        ls[1] = &sw->dl;
        for (i = 0; i < 2; i++) {
            ng.ng_LeftEdge   = ls[i]->bev_x + ls[i]->bev_w;
            ng.ng_TopEdge    = ls[i]->bev_y;
            ng.ng_Width      = SW_SCR_W;
            ng.ng_Height     = ls[i]->bev_h;
            ng.ng_GadgetText = NULL;
            ng.ng_GadgetID   = ids[i];
            g = CreateGadget(SCROLLER_KIND, g, &ng,
                             GTSC_Top,     ls[i]->top,
                             GTSC_Visible, ls[i]->rows,
                             GTSC_Total,   list_total_rows(ls[i]),
                             GTSC_Arrows,  12,
                             PGA_Freedom,  LORIENT_VERT,
                             TAG_DONE);
            ls[i]->scroller = g;
        }
    }

    if (!g) {                     /* a CreateGadget failed along the chain */
        drop_gadgets(sw, 0);      /* never attached: nothing to remove */
        return 0;
    }

    AddGList(sw->win, sw->glist, (UWORD)-1, -1, NULL);
    RefreshGList(sw->glist, sw->win, NULL, -1);
    GT_RefreshWindow(sw->win, NULL);
    update_disables(sw);
    return 1;
}

/* Fit the window to the current content unless the user has taken over the
 * size: exact height, grow-only width. Returns 1 when a resize was issued -
 * the repaint then happens on the IDCMP_NEWSIZE that follows. */
static int resize_to_fit(StatusWin *sw)
{
    int ow, oh;
    int max_w = sw->win->WScreen->Width - 16;
    int max_h = sw->win->WScreen->Height - 16;

    if (sw->user_sized)
        return 0;

    desired_size(sw, &ow, &oh);
    if (ow < sw->win->Width)
        ow = sw->win->Width;                     /* width: grow-only */
    if (ow > max_w) ow = max_w;
    if (oh > max_h) oh = max_h;
    if (ow < (int)sw->win->MinWidth)  ow = sw->win->MinWidth;
    if (oh < (int)sw->win->MinHeight) oh = sw->win->MinHeight;

    if (ow != sw->win->Width || oh != sw->win->Height) {
        sw->want_w = ow;
        sw->want_h = oh;
        ChangeWindowBox(sw->win, sw->win->LeftEdge, sw->win->TopEdge, ow, oh);
        return 1;
    }
    return 0;
}

/* Reflect the live status in the title bar - visible even when the window
 * sits depth-arranged behind the work. Only on an actual change: a title
 * redraw flashes, and most ticks change nothing. */
static void update_title(StatusWin *sw)
{
    char *next = sw->title[sw->tcur ^ 1];

    sprintf(next, AMISYNC_NAME " - %.60s", sw->status);
    if (strcmp(next, sw->title[sw->tcur]) != 0) {
        sw->tcur ^= 1;
        SetWindowTitles(sw->win, (STRPTR)sw->title[sw->tcur], (STRPTR)-1);
    }
}

/* ---- actions ------------------------------------------------------------ */

static void act_rescan(const ArexxContext *ctx)
{
    if (!ctx)
        return;
    scanner_rescan(ctx->scanner);
    peer_rescan(ctx->pm);
    listener_rescan(ctx->listener);
    log_printf(LOG_INFO, "statuswin: RESCAN triggered");
}

static void act_pause_all(StatusWin *sw, const ArexxContext *ctx)
{
    if (!ctx)
        return;
    if (sw->paused_all) {
        peer_resume(ctx->pm, NULL);
        log_printf(LOG_INFO, "statuswin: RESUME all");
    } else {
        peer_pause(ctx->pm, NULL);
        log_printf(LOG_INFO, "statuswin: PAUSE all");
    }
    /* sw->paused_all is NOT flipped here: statuswin_update re-derives it
     * (all_paused) and rebuilds the gadgets exactly when it changed -
     * flipping it early made that change invisible, so the button label
     * never updated. */
}

/* Pause/resume the selected device only (Syncthing parity: per-device and
 * global both exist). No confirm: it is freely reversible. */
static void act_pause_device(StatusWin *sw, const ArexxContext *ctx)
{
    SWItem           *ds = list_selected(&sw->dl);
    const ConfigPeer *p;

    if (!ctx || !ds || ds->kind != LK_DEVICE)
        return;
    p = peer_info(ctx->pm, ds->idx, NULL, NULL, NULL, NULL, NULL);
    if (!p)
        return;
    if (ds->paused) {
        peer_resume(ctx->pm, p->id);
        log_printf(LOG_INFO, "statuswin: RESUME %.7s", p->id);
    } else {
        peer_pause(ctx->pm, p->id);
        log_printf(LOG_INFO, "statuswin: PAUSE %.7s", p->id);
    }
}

/* Rescan just the selected folder: a targeted scanner pass (the workers
 * announce any advance via the scanner's own wreg signal, so no peer poke
 * is needed here, unlike Rescan All's belt-and-braces sweep). */
static void act_rescan_folder(const ArexxContext *ctx, int fidx)
{
    if (!ctx || fidx < 0 || fidx >= ctx->cfg->num_folders ||
        ctx->cfg->folders[fidx].removed)
        return;
    scanner_rescan_folder(ctx->scanner, fidx);
    log_printf(LOG_INFO, "statuswin: RESCAN folder '%s'",
               ctx->cfg->folders[fidx].id);
}

/* View the log in MultiView (stock since OS 3.0), fully detached. */
static void act_openlog(const ArexxContext *ctx)
{
    char cmd[200];
    BPTR in, out;

    if (!ctx || !ctx->cfg->logfile[0])
        return;
    sprintf(cmd, "SYS:Utilities/MultiView \"%.128s\"", ctx->cfg->logfile);
    in  = Open((STRPTR)"NIL:", MODE_OLDFILE);
    out = Open((STRPTR)"NIL:", MODE_NEWFILE);
    if (!in || !out) {
        /* A NULL BPTR is not a filehandle, and SYS_Asynch hands these to the
         * child to use and to DOS to close - so don't launch with one. */
        if (in)  Close(in);
        if (out) Close(out);
        log_printf(LOG_WARN, "statuswin: no NIL: handles to run MultiView with");
        return;
    }
    if (SystemTags((STRPTR)cmd,
                   SYS_Input,  (ULONG)in,
                   SYS_Output, (ULONG)out,
                   SYS_Asynch, TRUE,
                   TAG_DONE) == -1) {
        /* could not even launch: the handles stay ours to close */
        if (in)  Close(in);
        if (out) Close(out);
        log_printf(LOG_WARN, "statuswin: could not run MultiView");
    }
}

/* The About window: logo, centred typography, an OK button - a proper
 * product card rather than a requester. Synchronous, like every dialog
 * here. Falls back to a plain requester when the window cannot open. */
static void act_about(StatusWin *sw)
{
    /* style: 0 plain, 1 bold (overstrike) */
    struct AboutLine { const char *t; int style; };
    static struct EasyStruct fallback = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        AMISYNC_NAME " " AMISYNC_VERSION
        " (" AMISYNC_CPU " build, " AMISYNC_DATE ")\n\n"
        "\xa9 2026 Thomas Severinsen - MIT license\n\n"
        "Syncthing-compatible file sync for AmigaOS 3.x.\n"
        "An independent project, not affiliated with\n"
        "or endorsed by Syncthing.",
        "OK"
    };
    char gccv[16], build[64];
    struct AboutLine L[16];
    int  nl = 0;
    struct Screen       *scr;
    struct Gadget       *glist = NULL, *g;
    struct Window       *win = NULL;
    struct NewGadget     ng;
    struct IntuiMessage *im;
    int fw = sw->font->tf_XSize;
    int rh = sw->font->tf_YSize + SW_LEADING;
    int bl, bt, iw, ih, y, i, maxw, done = 0;

    /* "GCC 6.5.0b" - __VERSION__ up to its first space. */
    {
        const char *v = __VERSION__;
        int n = 0;
        while (v[n] && v[n] != ' ' && n < (int)sizeof(gccv) - 1)
            n++;
        memcpy(gccv, v, (size_t)n);
        gccv[n] = '\0';
    }
    sprintf(build, "Build %s (%s, GCC %s)",
            AMISYNC_DATE, AMISYNC_CPU, gccv);

#define AB(text, bold) \
    do { L[nl].t = (text); L[nl].style = (bold); nl++; } while (0)
    AB(AMISYNC_NAME " " AMISYNC_VERSION,            1);
    AB("",                                          0);
    AB("Syncthing-compatible file synchronization", 0);
    AB("for AmigaOS 3.x",                           0);
    AB("",                                          0);
    AB(build,                                       0);
    AB("",                                          0);
    AB("\xa9 2026 Thomas Severinsen",               0);
    AB("MIT license",                               0);
    AB("TLS via AmiSSL",                            0);
    AB("",                                          0);
    AB("Not affiliated with Syncthing",             0);
#undef AB

    scr = LockPubScreen(NULL);
    if (!scr) {
        EasyRequestArgs(NULL, &fallback, NULL, NULL);
        return;
    }
    bl = scr->WBorLeft;
    bt = scr->WBorTop + scr->Font->ta_YSize + 1;

    maxw = sw->logo_w;
    for (i = 0; i < nl; i++) {
        int w = (int)strlen(L[i].t) * fw;
        if (w > maxw)
            maxw = w;
    }
    iw = maxw + 4 * SW_PAD;

    y  = bt + SW_PAD;
    if (sw->dobj && sw->logo_h > 0)
        y += sw->logo_h + SW_PAD;
    y += nl * rh + SW_PAD;

    g = CreateContext(&glist);
    memset(&ng, 0, sizeof(ng));
    ng.ng_TextAttr   = &sw_topaz;
    ng.ng_VisualInfo = sw->vi;
    ng.ng_Width      = 4 * 8 + 16;
    ng.ng_Height     = SW_BT_H;
    ng.ng_LeftEdge   = bl + (iw - ng.ng_Width) / 2;
    ng.ng_TopEdge    = y;
    ng.ng_GadgetText = (STRPTR)"OK";
    ng.ng_GadgetID   = 1;
    g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    ih = y + SW_BT_H + SW_PAD;
    if (!g)
        goto out;                          /* fall back to the requester */

    win = OpenWindowTags(NULL,
        WA_Title,     (ULONG)"About " AMISYNC_NAME,
        WA_PubScreen, (ULONG)scr,
        WA_Width,     bl + iw + scr->WBorRight,
        WA_Height,    ih + scr->WBorBottom,
        WA_Left,      (scr->Width - iw) / 3,
        WA_Top,       scr->Height / 6,
        WA_Flags,     WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_CLOSEGADGET |
                      WFLG_ACTIVATE | WFLG_SMART_REFRESH,
        WA_IDCMP,     IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | BUTTONIDCMP,
        WA_Gadgets,   (ULONG)glist,
        TAG_DONE);
    if (!win)
        goto out;
    GT_RefreshWindow(win, NULL);

    {
        struct RastPort *rp = win->RPort;
        int ty = bt + SW_PAD;

        SetFont(rp, sw->font);
        SetDrMd(rp, JAM1);
        SetAPen(rp, sw->textpen);
        if (sw->dobj && sw->logo_h > 0) {
            int lx = bl + (iw - sw->logo_w) / 2;
            draw_logo(sw, rp, lx, ty);
            ty += sw->logo_h + SW_PAD;
        }
        for (i = 0; i < nl; i++, ty += rh) {
            int len = (int)strlen(L[i].t);
            int tx  = bl + (iw - len * fw) / 2;
            if (!len)
                continue;
            Move(rp, tx, ty + sw->font->tf_Baseline);
            Text(rp, (STRPTR)L[i].t, (ULONG)len);
            if (L[i].style == 1) {                 /* bold: overstrike */
                Move(rp, tx + 1, ty + sw->font->tf_Baseline);
                Text(rp, (STRPTR)L[i].t, (ULONG)len);
            }
        }
    }

    while (!done) {
        WaitPort(win->UserPort);
        while ((im = GT_GetIMsg(win->UserPort)) != NULL) {
            if (im->Class == IDCMP_CLOSEWINDOW ||
                im->Class == IDCMP_GADGETUP)
                done = 1;
            else if (im->Class == IDCMP_REFRESHWINDOW) {
                GT_BeginRefresh(win);
                GT_EndRefresh(win, TRUE);
            }
            GT_ReplyIMsg(im);
        }
    }

out:
    /* One unwind for all four exits - the screen lock in particular was
     * released by hand at each of them, which is a leak waiting for the next
     * early return (add_folder_dialog already unwinds this way). */
    if (win)
        CloseWindow(win);
    if (glist)
        FreeGadgets(glist);
    UnlockPubScreen(NULL, scr);
    if (!win)                              /* never got a window up */
        EasyRequestArgs(NULL, &fallback, NULL, NULL);
}

static int act_quit_confirm(void)
{
    static struct EasyStruct es = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        "Stop AmiSync?\nSyncing halts until it is started again.",
        "Stop|Cancel"
    };
    return EasyRequestArgs(NULL, &es, NULL, NULL) == 1;
}

/* Open folder 'fidx's drawer on Workbench (V44+). */
static void act_open_folder(const ArexxContext *ctx, int fidx)
{
    if (!ctx || fidx < 0 || fidx >= ctx->cfg->num_folders ||
        ctx->cfg->folders[fidx].removed)
        return;

    if (WorkbenchBase && WorkbenchBase->lib_Version >= 44) {
        if (OpenWorkbenchObjectA((STRPTR)ctx->cfg->folders[fidx].path, NULL))
            log_printf(LOG_INFO, "statuswin: opened folder '%s'",
                       ctx->cfg->folders[fidx].id);
        else
            log_printf(LOG_WARN, "statuswin: could not open '%s'",
                       ctx->cfg->folders[fidx].path);
    } else {
        log_printf(LOG_INFO, "statuswin: opening folders needs "
                   "workbench.library V44+ (OS 3.5/3.2)");
    }
}

/* Offer to add a discovered device as a peer, found by ID. The seen list is a
 * RING - a 17th sighting overwrites the oldest - so unlike the folder, peer and
 * offer tables (all tombstoned, never compacted) its indices move. Resolving by
 * identity here is what the file header promises selection does. */
static void act_add_device(const ArexxContext *ctx, const char *id)
{
    static struct EasyStruct ask = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        "Add discovered device\n%s\nat %s:%ld?\n\n"
        "Your folders are offered to it; it must\n"
        "also accept this device on its side.",
        "Add|Cancel"
    };
    const DiscoSeenEntry *e = NULL;
    ULONG args[3];
    int   i;

    if (!ctx || !ctx->seen || !id || !id[0])
        return;
    for (i = 0; i < ctx->seen->n; i++)
        if (strcmp(ctx->seen->e[i].id, id) == 0) {
            e = &ctx->seen->e[i];
            break;
        }
    if (!e)
        return;                            /* aged out of the ring meanwhile */

    args[0] = (ULONG)e->id;
    args[1] = (ULONG)e->host;
    args[2] = (ULONG)e->port;
    if (EasyRequestArgs(NULL, &ask, NULL, args) != 1)
        return;

    switch (peer_manager_add(ctx->pm, e->id, e->host, e->port)) {
    case 1:
        if (!config_append_peer(CONFIG_PATH_DEFAULT, e->id, e->host, e->port))
            log_printf(LOG_WARN, "statuswin: added %.7s but could not append "
                       "it to " CONFIG_PATH_DEFAULT, e->id);
        log_printf(LOG_INFO, "statuswin: added discovered peer %.7s", e->id);
        break;                 /* the entry leaves the list next tick */
    case -1:
        log_printf(LOG_INFO, "statuswin: %.7s is already configured", e->id);
        break;
    case -2:
        log_printf(LOG_WARN, "statuswin: peer table full; cannot add %.7s",
                   e->id);
        break;
    default:
        log_printf(LOG_WARN, "statuswin: could not add %.7s (see the log)",
                   e->id);
        break;
    }
}

/* Offer to remove configured peer 'idx': the destructive twin of adding a
 * discovered device, so it confirms first. While the device keeps
 * announcing on the LAN it reappears as discovered afterwards. */
static void act_remove_device(const ArexxContext *ctx, int idx)
{
    static struct EasyStruct ask = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        "Remove device \"%s\"?\n\n"
        "No files are deleted. It can be added\n"
        "again from Discovered.",
        "Remove|Cancel"
    };
    const ConfigPeer *p;
    const char       *rname, *rclient;
    unsigned long long in, out;
    char              sid[8];
    ULONG             args[1];

    if (!ctx)
        return;
    p = peer_info(ctx->pm, idx, NULL, NULL, NULL, NULL, NULL);
    if (!p)
        return;
    peer_xfer_info(ctx->pm, idx, &in, &out, &rname, &rclient);
    short_id(sid, p->id);

    args[0] = (ULONG)(rname && rname[0] ? rname : sid);
    if (EasyRequestArgs(NULL, &ask, NULL, args) != 1)
        return;

    if (peer_manager_remove(ctx->pm, p->id)) {
        if (!config_remove_peer(CONFIG_PATH_DEFAULT, p->id))
            log_printf(LOG_WARN, "statuswin: removed %.7s but no config "
                       "line was found to delete", sid);
        log_printf(LOG_INFO, "statuswin: removed peer %.7s", sid);
    }
}

/* Offer to remove folder 'fidx' from the sync set: the window front-end of
 * daemon_folder_remove (ARexx REMOVEFOLDER). Local files stay; the peer
 * keeps its copy and sees the unshare via the in-band ClusterConfig. */
static void act_remove_folder(const ArexxContext *ctx, int fidx)
{
    static struct EasyStruct ask = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME,
        "Stop syncing folder \"%s\"?\n\n"
        "No files are deleted, here or on peers.",
        "Remove|Cancel"
    };
    ULONG args[1];

    if (!ctx || fidx < 0 || fidx >= ctx->cfg->num_folders ||
        ctx->cfg->folders[fidx].removed)
        return;

    args[0] = (ULONG)(ctx->cfg->folders[fidx].label[0]
                      ? ctx->cfg->folders[fidx].label
                      : ctx->cfg->folders[fidx].id);
    if (EasyRequestArgs(NULL, &ask, NULL, args) != 1)
        return;

    if (daemon_folder_remove(ctx, ctx->cfg->folders[fidx].id))
        log_printf(LOG_INFO, "statuswin: folder removed via window");
}

/* Ask for a drawer via ASL (opened lazily): the user picks an existing
 * one, or names a new one for the caller to create. Returns 1 with the
 * chosen path in 'out'. */
static int ask_drawer(const char *title, char *out, int cap)
{
    struct FileRequester *fr;
    int ok = 0;

    if (!AslBase)
        AslBase = OpenLibrary("asl.library", 38);
    if (!AslBase) {
        log_printf(LOG_WARN, "statuswin: asl.library v38 needed to pick a "
                   "drawer here; use ARexx ADDFOLDER instead");
        return 0;
    }
    fr = (struct FileRequester *)AllocAslRequestTags(ASL_FileRequest,
             ASLFR_TitleText,   (ULONG)title,
             ASLFR_DrawersOnly, TRUE,
             TAG_DONE);
    if (!fr)
        return 0;
    if (AslRequest(fr, NULL) && fr->fr_Drawer && fr->fr_Drawer[0]) {
        int n = (int)strlen((const char *)fr->fr_Drawer);
        if (n > cap - 1)
            n = cap - 1;
        memcpy(out, fr->fr_Drawer, n);
        out[n] = '\0';
        ok = 1;
    }
    FreeAslRequest(fr);
    return ok;
}

/* Accept a folder a peer offered (its CC lists it, ours does not): the ASL
 * drawer requester picks - or names, we create - the local directory, then
 * daemon_folder_add configures it under the peer's OWN folder id, which is
 * the part that must match exactly and is why no typing is involved. Our
 * updated ClusterConfig goes out in-band and syncing starts. */
static void act_accept_offer(const ArexxContext *ctx, int idx, const char *id)
{
    OfferedFolder of;
    char          title[96];
    char          drawer[CONFIG_PATH_MAX];

    if (!ctx || !id || !offered_get(idx, &of) || !of.id[0])
        return;                            /* gone (withdrawn) meanwhile */
    /* The slot index is only a hint: offer slots are tombstoned in place and
     * reused, so a ClusterConfig landing between the tick that drew the row
     * and this click can put a DIFFERENT peer's offer in it - and accepting
     * configures a folder by id. Confirm the slot still holds what was
     * selected, the identity rule the rest of this file follows. */
    if (strcmp(of.id, id) != 0)
        return;
    if (sync_folder_index(ctx->cfg, of.id) >= 0)
        return;                            /* accepted meanwhile */

    sprintf(title, "Choose or type a drawer for \"%.40s\"",
            of.label[0] ? of.label : of.id);
    if (!ask_drawer(title, drawer, sizeof(drawer)))
        return;
    switch (daemon_folder_add(ctx, of.id, drawer,
                              FOLDER_SENDRECEIVE, of.label)) {
    case 1:
        log_printf(LOG_INFO, "statuswin: accepted offered folder '%s' "
                   "at '%s'", of.id, drawer);
        break;                 /* leaves the list on the next tick */
    case -2:
        log_printf(LOG_WARN, "statuswin: folder table full; restart "
                   "reclaims removed slots");
        break;
    case -3: {
        static struct EasyStruct oops = {
            sizeof(struct EasyStruct), 0, AMISYNC_NAME,
            "That drawer is (or contains, or is inside)\n"
            "a folder that is already being synced -\n"
            "choose a different one.", "OK"
        };
        EasyRequestArgs(NULL, &oops, NULL, NULL);
        break;
    }
    default:
        log_printf(LOG_WARN, "statuswin: could not add folder '%s'",
                   of.id);
        break;
    }
}

/* Small synchronous "Add Folder" dialog: shows the chosen drawer, offers
 * the folder's display NAME for editing in a string gadget (that is the
 * LABEL; the id stays the drawer's name - Syncthing's id/label split),
 * and confirms. Returns 1 on Add ('name' holds the possibly edited text,
 * prefilled by the caller), 0 on cancel. Blocks the daemon loop exactly
 * as the EasyRequest/AslRequest steps around it already do. */
static int add_folder_dialog(const char *path, char *name, int cap)
{
    enum { DID_NAME = 1, DID_ADD, DID_CANCEL };
    struct Screen       *scr;
    APTR                 vi = NULL;
    struct TextFont     *font = NULL;
    struct Gadget       *glist = NULL, *g, *gstr = NULL;
    struct Window       *win = NULL;
    struct NewGadget     ng;
    struct IntuiMessage *im;
    char  pline[64], info[64];
    int   bl, bt, iw, ih, y, ok = 0, done = 0;

    scr = LockPubScreen(NULL);
    if (!scr)
        return 0;
    vi   = GetVisualInfoA(scr, NULL);
    font = OpenFont(&sw_topaz);
    if (!vi || !font)
        goto out;

    bl = scr->WBorLeft;
    bt = scr->WBorTop + scr->Font->ta_YSize + 1;
    iw = 54 * 8;
    sprintf(pline, "Drawer: %.44s", path);
    strcpy(info, "Offered to every configured peer.");

    g = CreateContext(&glist);
    memset(&ng, 0, sizeof(ng));
    ng.ng_TextAttr   = &sw_topaz;
    ng.ng_VisualInfo = vi;

    y = bt + SW_PAD + 10 + SW_PAD;             /* below the drawer line */
    ng.ng_LeftEdge   = bl + SW_PAD + 5 * 8;    /* room for the "Name" label */
    ng.ng_TopEdge    = y;
    ng.ng_Width      = iw - 2 * SW_PAD - 5 * 8;
    ng.ng_Height     = SW_BT_H;
    ng.ng_GadgetText = (STRPTR)"Name";
    ng.ng_GadgetID   = DID_NAME;
    ng.ng_Flags      = PLACETEXT_LEFT;
    g = gstr = CreateGadget(STRING_KIND, g, &ng,
                            GTST_String,   (ULONG)name,
                            GTST_MaxChars, cap - 1,
                            TAG_DONE);

    y += SW_BT_H + SW_PAD + 10 + SW_PAD;       /* below the info line */
    ng.ng_LeftEdge   = bl + SW_PAD;
    ng.ng_TopEdge    = y;
    ng.ng_Width      = 4 * 8 + 16;
    ng.ng_GadgetText = (STRPTR)"Add";
    ng.ng_GadgetID   = DID_ADD;
    ng.ng_Flags      = 0;
    g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    ng.ng_Width      = 6 * 8 + 16;
    ng.ng_LeftEdge   = bl + iw - SW_PAD - ng.ng_Width;
    ng.ng_GadgetText = (STRPTR)"Cancel";
    ng.ng_GadgetID   = DID_CANCEL;
    g = CreateGadget(BUTTON_KIND, g, &ng, TAG_DONE);
    if (!g)
        goto out;
    ih = y + SW_BT_H + SW_PAD;

    win = OpenWindowTags(NULL,
        WA_Title,     (ULONG)"Add Folder",
        WA_PubScreen, (ULONG)scr,
        WA_Width,     bl + iw + scr->WBorRight,
        WA_Height,    ih + scr->WBorBottom,
        WA_Left,      (scr->Width - iw) / 3,
        WA_Top,       scr->Height / 4,
        WA_Flags,     WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_CLOSEGADGET |
                      WFLG_ACTIVATE | WFLG_SMART_REFRESH,
        WA_IDCMP,     IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW |
                      BUTTONIDCMP | STRINGIDCMP,
        WA_Gadgets,   (ULONG)glist,
        TAG_DONE);
    if (!win)
        goto out;
    GT_RefreshWindow(win, NULL);

    {
        struct RastPort *rp = win->RPort;
        SetFont(rp, font);
        SetDrMd(rp, JAM2);
        SetAPen(rp, 1);
        SetBPen(rp, 0);
        Move(rp, bl + SW_PAD, bt + SW_PAD + font->tf_Baseline);
        Text(rp, (STRPTR)pline, (ULONG)strlen(pline));
        Move(rp, bl + SW_PAD,
             bt + SW_PAD + 10 + SW_PAD + SW_BT_H + SW_PAD +
             font->tf_Baseline);
        Text(rp, (STRPTR)info, (ULONG)strlen(info));
    }
    ActivateGadget(gstr, win, NULL);

    while (!done) {
        WaitPort(win->UserPort);
        while ((im = GT_GetIMsg(win->UserPort)) != NULL) {
            switch (im->Class) {
            case IDCMP_CLOSEWINDOW:
                done = 1;
                break;
            case IDCMP_REFRESHWINDOW:
                GT_BeginRefresh(win);
                GT_EndRefresh(win, TRUE);
                break;
            case IDCMP_GADGETUP: {
                struct Gadget *gg = (struct Gadget *)im->IAddress;
                if (gg && (gg->GadgetID == DID_ADD ||
                           gg->GadgetID == DID_NAME))   /* Return = Add */
                    ok = done = 1;
                else if (gg && gg->GadgetID == DID_CANCEL)
                    done = 1;
                break;
            }
            }
            GT_ReplyIMsg(im);
        }
    }

    if (ok && gstr) {
        struct StringInfo *si = (struct StringInfo *)gstr->SpecialInfo;
        if (si && si->Buffer) {
            int n = (int)strlen((const char *)si->Buffer);
            if (n > cap - 1)
                n = cap - 1;
            memcpy(name, si->Buffer, n);
            name[n] = '\0';
        }
    }

out:
    if (win)
        CloseWindow(win);
    if (glist)
        FreeGadgets(glist);
    if (font)
        CloseFont(font);
    if (vi)
        FreeVisualInfo(vi);
    UnlockPubScreen(NULL, scr);
    return ok;
}

/* Add a NEW folder to the sync set: the window twin of ARexx ADDFOLDER.
 * The requester picks - or names, we create - the drawer; the drawer's
 * name becomes the folder id (what peers match on; a custom id is what
 * ARexx ADDFOLDER is for), and the dialog above lets the user edit the
 * LABEL. The folder is offered to every configured peer via the in-band
 * ClusterConfig. */
static void act_add_folder(const ArexxContext *ctx)
{
    static struct EasyStruct oops = {
        sizeof(struct EasyStruct), 0, AMISYNC_NAME, "%s", "OK"
    };
    char        drawer[CONFIG_PATH_MAX];
    char        label[CONFIG_NAME_MAX];
    const char *name;
    ULONG       args[1];

    if (!ctx)
        return;
    if (!ask_drawer("Choose or create a drawer to sync", drawer,
                    sizeof(drawer)))
        return;
    name = (const char *)FilePart((STRPTR)drawer);
    if (!name[0]) {
        args[0] = (ULONG)"Pick a drawer, not a volume root\n"
                         "(the drawer's name becomes the folder id).";
        EasyRequestArgs(NULL, &oops, NULL, args);
        return;
    }
    if (strlen(name) >= CONFIG_FOLDER_ID_MAX) {
        args[0] = (ULONG)"The drawer's name is too long\nfor a folder id.";
        EasyRequestArgs(NULL, &oops, NULL, args);
        return;
    }

    strcpy(label, name);                   /* prefill: label = drawer name */
    if (!add_folder_dialog(drawer, label, sizeof(label)))
        return;

    switch (daemon_folder_add(ctx, name, drawer, FOLDER_SENDRECEIVE,
                              label[0] && strcmp(label, name) != 0
                              ? label : NULL)) {
    case 1:
        log_printf(LOG_INFO, "statuswin: added folder '%s' at '%s'",
                   name, drawer);
        break;
    case -1:
        args[0] = (ULONG)"A folder with that name is\nalready configured.";
        EasyRequestArgs(NULL, &oops, NULL, args);
        break;
    case -2:
        args[0] = (ULONG)"The folder table is full;\n"
                         "a restart reclaims removed slots.";
        EasyRequestArgs(NULL, &oops, NULL, args);
        break;
    case -3:
        args[0] = (ULONG)"That drawer is (or contains, or is inside)\n"
                         "a folder that is already being synced.";
        EasyRequestArgs(NULL, &oops, NULL, args);
        break;
    default:
        args[0] = (ULONG)"Could not add the folder (see the log).";
        EasyRequestArgs(NULL, &oops, NULL, args);
        break;
    }
}

/* ---- selection & clicks -------------------------------------------------- */

/* Scroll so the item's head row (and as much of its expansion as fits) is
 * visible. 'row' is the item's first content row. */
static void ensure_visible(SWList *l, int row, int nrows)
{
    if (row < l->top)
        l->top = row;
    else if (row + nrows > l->top + l->rows) {
        l->top = row + nrows - l->rows;
        if (l->top > row)
            l->top = row;                  /* expansion taller than the list */
    }
    if (l->top < 0)
        l->top = 0;
}

/* The item under content row 'r', or NULL. 'row_out' gets the item's own
 * first content row. */
static SWItem *item_at_row(SWList *l, int r, int *row_out)
{
    SWItem *sel = list_selected(l);
    int i, row = 0;

    for (i = 0; i < l->n; i++) {
        SWItem *it = &l->items[i];
        int span = 1 + (sel == it ? it->ndet : 0);
        if (r >= row && r < row + span) {
            if (row_out)
                *row_out = row;
            return it;
        }
        row += span;
    }
    return NULL;
}

/* A press inside list 'l'? Select/expand or collapse. Returns 1 when the
 * click was this list's business. */
static int list_press(StatusWin *sw, SWList *l, const ArexxContext *ctx,
                      struct IntuiMessage *im)
{
    int rh = sw->font->tf_YSize + SW_LEADING;
    int mx = im->MouseX, my = im->MouseY;
    int r, row0 = 0;
    SWItem *it;

    if (mx < l->bev_x + 1 || mx >= l->bev_x + l->bev_w - 1 ||
        my < l->ty || my >= l->ty + l->rows * rh)
        return 0;

    r  = l->top + (my - l->ty) / rh;
    it = item_at_row(l, r, &row0);
    if (!it)
        return 1;                          /* blank slack: ignore */

    /* Plain toggle: click selects + expands, click again collapses. (A
     * double-click "open drawer" gesture was tried here and cut: any
     * second click within the system double-click time read as "open",
     * which made expand/collapse feel broken. Open is the verb button.) */
    if (strcmp(l->sel_key, it->key) == 0) {
        l->sel_key[0] = '\0';              /* collapse */
    } else {
        strcpy(l->sel_key, it->key);
        ensure_visible(l, row0, 1 + it->ndet);
    }

    draw_list(sw, l);
    update_scroller(sw, l);
    update_disables(sw);
    /* The device Pause verb's label may need to flip with the selection -
     * but rebuilding gadgets MID-DRAIN would free gadgets that queued
     * messages still point at, so the caller does it after the loop. */
    return 1;
}

/* ---- public entry points ---------------------------------------------- */

int statuswin_show(StatusWin *sw, const ArexxContext *ctx,
                   struct DiskObject *dobj)
{
    struct Screen *scr;
    int ow, oh, min_w, min_h;

    if (!sw)
        return 0;

    if (sw->win) {                     /* single instance: refresh + raise */
        statuswin_update(sw, ctx);
        WindowToFront(sw->win);
        ActivateWindow(sw->win);
        return 1;
    }

    if (!IntuitionBase)
        IntuitionBase = (struct IntuitionBase *)
                        OpenLibrary("intuition.library", 37);
    if (!GfxBase)
        GfxBase = (struct GfxBase *)OpenLibrary("graphics.library", 37);
    if (!GadToolsBase)
        GadToolsBase = OpenLibrary("gadtools.library", 37);
    if (!IntuitionBase || !GfxBase || !GadToolsBase)
        return 0;

    if (!sw->font) {
        sw->font = OpenFont(&sw_topaz);
        if (!sw->font)
            return 0;
    }

    sw->user_sized  = 0;
    sw->fl.sel_key[0] = sw->dl.sel_key[0] = '\0';
    sw->fl.top = sw->dl.top = 0;
    sw->paused_all  = all_paused(ctx);

    sw->dobj   = dobj;
    sw->logo_w = sw->logo_h = 0;
    if (dobj) {
        sw->logo_w = dobj->do_Gadget.Width;
        sw->logo_h = dobj->do_Gadget.Height;
        if (sw->logo_w <= 0 || sw->logo_h <= 0 ||
            sw->logo_w > 128 || sw->logo_h > 128)
            sw->logo_w = sw->logo_h = 0;   /* implausible imagery: text-only */
    }

    build_model(sw, ctx);

    scr = LockPubScreen(NULL);
    if (!scr)
        return 0;
    {
        struct DrawInfo *dri = GetScreenDrawInfo(scr);
        sw->textpen     = 1;                     /* sane fixed fallbacks */
        sw->bgpen       = 0;
        sw->shinepen    = 2;
        sw->shadowpen   = 1;
        sw->fillpen     = 3;
        sw->filltextpen = 1;
        if (dri) {
            sw->textpen     = dri->dri_Pens[TEXTPEN];
            sw->bgpen       = dri->dri_Pens[BACKGROUNDPEN];
            sw->shinepen    = dri->dri_Pens[SHINEPEN];
            sw->shadowpen   = dri->dri_Pens[SHADOWPEN];
            sw->fillpen     = dri->dri_Pens[FILLPEN];
            sw->filltextpen = dri->dri_Pens[FILLTEXTPEN];
            FreeScreenDrawInfo(scr, dri);
        }
        if (sw->fillpen == sw->bgpen)            /* odd palette: stay legible */
            sw->fillpen = sw->shadowpen;
    }
    sw->vi = GetVisualInfoA(scr, NULL);
    if (!sw->vi) {
        UnlockPubScreen(NULL, scr);
        return 0;
    }

    /* Initial size: exact INNER fit to the content (Intuition adds the
     * real borders - guessing them here once made the window hop a few
     * pixels wider on the first tick), clamped to the screen. The minimum
     * keeps the fixed parts plus 2 rows per list usable. */
    desired_inner(sw, &ow, &oh);
    min_w = 2 * SW_PAD + 2 * SW_GPAD + 4 + SW_SCR_W + 46 * 8 + 8;
    min_h = layout(sw, 2, 2) + 14;
    if (ow > scr->Width  - 40) ow = scr->Width  - 40;
    if (oh > scr->Height - 32) oh = scr->Height - 32;
    if (ow < min_w) ow = min_w;    /* min_w/h are outer: conservative here */
    if (oh < min_h) oh = min_h;

    sprintf(sw->title[0], AMISYNC_NAME " - %.60s", sw->status);
    sw->tcur = 0;
    sw->win = OpenWindowTags(NULL,
        WA_Title,        (ULONG)sw->title[0],
        WA_PubScreen,    (ULONG)scr,
        WA_InnerWidth,   ow,
        WA_InnerHeight,  oh,
        WA_Left,         (scr->Width  - ow) / 4,
        WA_Top,          (scr->Height - oh) / 4,
        WA_MinWidth,     min_w,
        WA_MinHeight,    min_h,
        WA_MaxWidth,     scr->Width,
        WA_MaxHeight,    scr->Height,
        /* Pairs with LayoutMenus' GTMN_NewLookMenus: without this tag
         * Intuition renders the strip old-style and the two conventions
         * collide into a black-on-black menu panel. */
        WA_NewLookMenus, TRUE,
        WA_Flags,        WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_CLOSEGADGET |
                         WFLG_SIZEGADGET | WFLG_ACTIVATE | WFLG_SMART_REFRESH,
        WA_IDCMP,        IDCMP_CLOSEWINDOW | IDCMP_NEWSIZE |
                         IDCMP_REFRESHWINDOW | IDCMP_MOUSEBUTTONS |
                         IDCMP_MENUPICK | BUTTONIDCMP | SCROLLERIDCMP,
        TAG_DONE);
    UnlockPubScreen(NULL, scr);
    if (!sw->win) {
        log_printf(LOG_WARN, "statuswin: window would not open");
        FreeVisualInfo(sw->vi);
        sw->vi = NULL;
        return 0;
    }
    sw->want_w = sw->win->Width;
    sw->want_h = sw->win->Height;

    layout_actual(sw);
    draw_full(sw);
    if (!build_gadgets(sw, ctx))
        log_printf(LOG_WARN, "statuswin: no gadgets (out of memory?)");

    /* The Project menu (right mouse button). Best-effort: the window is
     * fully usable without it. */
    sw->menus = CreateMenusA(sw_newmenu, NULL);
    if (sw->menus) {
        if (LayoutMenus(sw->menus, sw->vi, GTMN_NewLookMenus, TRUE,
                        TAG_DONE)) {
            SetMenuStrip(sw->win, sw->menus);
        } else {
            FreeMenus(sw->menus);
            sw->menus = NULL;
        }
    }
    return 1;
}

/* The device Pause gadget reads "Resume" when the selected device is paused,
 * so a selection change or a state flip can invalidate the built label.
 * Rebuild the gadgets only when the wanted label differs from the built one -
 * the rule build_gadgets sets sw->dpause_resume by, kept in one place. */
static void sync_dpause_label(StatusWin *sw, const ArexxContext *ctx)
{
    SWItem *ds   = list_selected(&sw->dl);
    int     want = (ds && ds->kind == LK_DEVICE && ds->paused);

    if (want != sw->dpause_resume)
        build_gadgets(sw, ctx);
}

void statuswin_update(StatusWin *sw, const ArexxContext *ctx)
{
    int was_paused;

    if (!sw || !sw->win || !ctx)
        return;
    build_model(sw, ctx);
    update_title(sw);

    was_paused = sw->paused_all;
    sw->paused_all = all_paused(ctx);

    /* When the content outgrew (or no longer fills) the window, resize and
     * let the IDCMP_NEWSIZE repaint; otherwise redraw in place. Item counts
     * changing means group titles/geometry changed: full redraw. */
    if (!resize_to_fit(sw)) {
        layout_actual(sw);
        if (sw->fl.n != sw->nf_last || sw->dl.n != sw->nd_last) {
            draw_full(sw);
            build_gadgets(sw, ctx);
        } else {
            draw_band(sw);
            draw_tdev(sw);
            draw_list(sw, &sw->fl);
            draw_list(sw, &sw->dl);
            update_scroller(sw, &sw->fl);
            update_scroller(sw, &sw->dl);
            update_disables(sw);
            if (sw->paused_all != was_paused)  /* label flip (e.g. via ARexx) */
                build_gadgets(sw, ctx);
            else
                sync_dpause_label(sw, ctx);   /* selected device may have
                                               * flipped under us */
        }
    }
}

int statuswin_handle(StatusWin *sw, const ArexxContext *ctx)
{
    struct IntuiMessage *im;
    int closed = 0, resized = 0, refresh = 0, quit = 0, about = 0;
    int rescan = 0, pause_all = 0, openlog = 0;
    int mpause = 0, mresume = 0;
    int fadd = 0, fopen_ = 0, frescan = 0, faccept = 0, fremove = 0;
    int dadd = 0, dpause = 0, dremove = 0;
    int fscroll = -1, dscroll = -1;

    if (!sw || !sw->win)
        return 0;

    while ((im = GT_GetIMsg(sw->win->UserPort)) != NULL) {
        switch (im->Class) {
        case IDCMP_CLOSEWINDOW:
            closed = 1;
            break;
        case IDCMP_NEWSIZE:
            resized = 1;
            break;
        case IDCMP_REFRESHWINDOW:
            refresh = 1;
            break;
        case IDCMP_MOUSEBUTTONS:
            if (im->Code == SELECTDOWN) {
                if (!list_press(sw, &sw->fl, ctx, im))
                    list_press(sw, &sw->dl, ctx, im);
            }
            break;
        case IDCMP_MENUPICK: {
            UWORD sel = im->Code;
            while (sel != MENUNULL && sw->menus) {
                struct MenuItem *it = ItemAddress(sw->menus, sel);
                if (!it)
                    break;
                switch ((ULONG)GTMENUITEM_USERDATA(it)) {
                case SW_MENU_OPENLOG:   openlog = 1; break;
                case SW_MENU_ABOUT:     about   = 1; break;
                case SW_MENU_CLOSE:     closed  = 1; break;
                case SW_MENU_STOP:      quit    = 1; break;
                case SW_MENU_RESCANALL: rescan  = 1; break;
                case SW_MENU_PAUSEALL:  mpause  = 1; break;
                case SW_MENU_RESUMEALL: mresume = 1; break;
                }
                sel = it->NextSelect;
            }
            break;
        }
        case IDCMP_GADGETUP:
        case IDCMP_GADGETDOWN:
        case IDCMP_MOUSEMOVE: {
            struct Gadget *g = (struct Gadget *)im->IAddress;
            if (!g || !gadget_is_live(sw, g))
                break;                     /* queued against a freed rebuild */
            if (g->GadgetID == GID_FSCROLL) {
                fscroll = im->Code;            /* current top row */
            } else if (g->GadgetID == GID_DSCROLL) {
                dscroll = im->Code;
            } else if (im->Class == IDCMP_GADGETUP) {
                switch (g->GadgetID) {
                case GID_RESCAN:   rescan    = 1; break;
                case GID_PAUSEALL: pause_all = 1; break;
                case GID_OPENLOG:  openlog   = 1; break;
                case GID_QUIT:     quit      = 1; break;
                case GID_FADD:     fadd      = 1; break;
                case GID_FOPEN:    fopen_    = 1; break;
                case GID_FRESCAN:  frescan   = 1; break;
                case GID_FACCEPT:  faccept   = 1; break;
                case GID_FREMOVE:  fremove   = 1; break;
                case GID_DADD:     dadd      = 1; break;
                case GID_DPAUSE:   dpause    = 1; break;
                case GID_DREMOVE:  dremove   = 1; break;
                }
            }
            break;
        }
        }
        GT_ReplyIMsg(im);
    }

    if (closed) {
        if (sw->menus) {
            ClearMenuStrip(sw->win);
            FreeMenus(sw->menus);
            sw->menus = NULL;
        }
        drop_gadgets(sw, 1);
        CloseWindow(sw->win);          /* also removes its queued messages */
        sw->win = NULL;
        if (sw->vi) {
            FreeVisualInfo(sw->vi);
            sw->vi = NULL;
        }
        return 0;
    }

    if (resized) {
        /* A size we did not ask for = the user took over; auto-fit ends. */
        if (sw->win->Width != sw->want_w || sw->win->Height != sw->want_h)
            sw->user_sized = 1;
        layout_actual(sw);
        draw_full(sw);
        build_gadgets(sw, ctx);        /* reposition against the new edges */
    } else if (refresh) {
        GT_BeginRefresh(sw->win);
        draw_full(sw);
        GT_EndRefresh(sw->win, TRUE);
    }

    if (fscroll >= 0 && fscroll != sw->fl.top) {
        sw->fl.top = fscroll;
        draw_list(sw, &sw->fl);
    }
    if (dscroll >= 0 && dscroll != sw->dl.top) {
        sw->dl.top = dscroll;
        draw_list(sw, &sw->dl);
    }

    /* Selection changes may flip the device Pause verb's label; rebuild
     * only now, with the message queue drained (see list_press). */
    if (!resized)
        sync_dpause_label(sw, ctx);

    if (rescan)
        act_rescan(ctx);
    if (pause_all)
        act_pause_all(sw, ctx);
    /* Menu Pause All/Resume All are EXPLICIT (both items always there,
     * like the Tools menu), unlike the toggling bottom button. */
    if (mpause && ctx) {
        peer_pause(ctx->pm, NULL);
        log_printf(LOG_INFO, "statuswin: PAUSE all (menu)");
    }
    if (mresume && ctx) {
        peer_resume(ctx->pm, NULL);
        log_printf(LOG_INFO, "statuswin: RESUME all (menu)");
    }
    if (openlog)
        act_openlog(ctx);
    if (about)
        act_about(sw);
    if (dpause)
        act_pause_device(sw, ctx);
    if (fadd)
        act_add_folder(ctx);
    if (fopen_) {
        SWItem *fs = list_selected(&sw->fl);
        if (fs && fs->kind == LK_FOLDER)
            act_open_folder(ctx, fs->idx);
    }
    if (frescan) {
        SWItem *fs = list_selected(&sw->fl);
        if (fs && fs->kind == LK_FOLDER)
            act_rescan_folder(ctx, fs->idx);
    }
    if (faccept) {
        SWItem *fs = list_selected(&sw->fl);
        if (fs && fs->kind == LK_OFFER)
            act_accept_offer(ctx, fs->idx, fs->key + 2);   /* key is "O:<id>" */
    }
    if (fremove) {
        SWItem *fs = list_selected(&sw->fl);
        if (fs && fs->kind == LK_FOLDER)
            act_remove_folder(ctx, fs->idx);
    }
    if (dadd) {
        SWItem *ds = list_selected(&sw->dl);
        if (ds && ds->kind == LK_DISCO)
            act_add_device(ctx, ds->key + 2);   /* key is "S:<id>" */
    }
    if (dremove) {
        SWItem *ds = list_selected(&sw->dl);
        if (ds && ds->kind == LK_DEVICE)
            act_remove_device(ctx, ds->idx);
    }

    /* Any verb may have changed the model (added/removed/paused something):
     * refresh right away instead of waiting for the next status tick. */
    if (rescan || pause_all || mpause || mresume || dpause || fadd ||
        frescan || faccept || fremove || dadd || dremove)
        statuswin_update(sw, ctx);

    if (quit && act_quit_confirm())
        return 1;
    return 0;
}

void statuswin_destroy(StatusWin *sw)
{
    if (!sw)
        return;
    if (sw->win) {
        if (sw->menus) {
            ClearMenuStrip(sw->win);
            FreeMenus(sw->menus);
        }
        drop_gadgets(sw, 1);
        CloseWindow(sw->win);
        if (sw->vi)
            FreeVisualInfo(sw->vi);
    }
    if (sw->font)
        CloseFont(sw->font);
    FreeVec(sw);
    if (AslBase) {
        CloseLibrary(AslBase);
        AslBase = NULL;
    }
    if (GadToolsBase) {
        CloseLibrary(GadToolsBase);
        GadToolsBase = NULL;
    }
    if (GfxBase) {
        CloseLibrary((struct Library *)GfxBase);
        GfxBase = NULL;
    }
}
