/* appicon.h - Workbench AppIcon status indicator for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_APPICON_H
#define AMISYNC_APPICON_H

#include "arexx.h"     /* ArexxContext: the double-click STATUS report */
#include "statuswin.h" /* StatusWin: the live status window it opens   */

/* Opaque AppIcon state, allocated by appicon_create(). */
typedef struct AppIconUI AppIconUI;

/* Allocate the AppIcon machinery (message port + icon imagery). Does NOT
 * talk to Workbench yet - at boot amisync starts before LoadWB, so the icon
 * and the Tools-menu items are actually placed by appicon_update() retrying
 * each status tick. Returns NULL when disabled by config or on allocation
 * failure; every other call here is NULL-safe, so the daemon treats the
 * feature as best-effort. */
AppIconUI *appicon_create(int enabled);

/* Signal mask of the AppIcon message port for the daemon's Wait(); 0 if ui
 * is NULL. */
unsigned long appicon_sigmask(const AppIconUI *ui);

/* Reflect 'status' (the ENV:amisync/status one-liner) as the icon label.
 * Call on every status tick: while Workbench is not yet up this retries
 * AddAppIcon (cheap failure), once up it re-adds the icon only when the
 * label actually changed. */
void appicon_update(AppIconUI *ui, const char *status);

/* Drain the AppIcon/Tools-menu port. A double-click (or the Status menu
 * item) opens the live status window ('sw'; single-instance - a repeat
 * request raises the existing window), falling back to a modal EasyRequest
 * if the window cannot open; Rescan/Pause/Resume menu picks run the same
 * paths as their ARexx verbs. Returns 1 when the user chose Quit from the
 * menu and confirmed it - the daemon should shut down; 0 otherwise. */
int appicon_handle(AppIconUI *ui, const ArexxContext *ctx, StatusWin *sw);

/* Remove the icon (if placed), reply any queued messages and free
 * everything. Safe on NULL. */
void appicon_destroy(AppIconUI *ui);

#endif /* AMISYNC_APPICON_H */
