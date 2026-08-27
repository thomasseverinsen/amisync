/* statuswin.h - live-updating Workbench status window for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The AppIcon double-click / Tools-menu "Status..." target: header band,
 * a This Device panel, and accordion lists for Folders and Remote Devices
 * (see statuswin.c), redrawn in place on every status tick while open.
 * Non-blocking, unlike the old EasyRequest: the window's IDCMP port joins
 * the daemon's main Wait(), so the daemon keeps dialling, reaping and
 * answering ARexx while the window is up.
 */

#ifndef AMISYNC_STATUSWIN_H
#define AMISYNC_STATUSWIN_H

#include "arexx.h"   /* ArexxContext (an anonymous typedef: cannot be
                      * forward-declared in C89) */

struct DiskObject;

/* Opaque window state, allocated by statuswin_create(). */
typedef struct StatusWin StatusWin;

/* Allocate the (windowless) state. Returns NULL on allocation failure; every
 * other call is NULL-safe, so the feature degrades to the requester. */
StatusWin *statuswin_create(void);

/* Open the window showing the live report - or, if it is already open,
 * refresh it and bring it to the front. 'dobj' (NULLable) supplies the logo
 * imagery for the header, typically the AppIcon's DiskObject. Returns 1 if a
 * window is up, 0 if it could not open (caller falls back to a requester). */
int statuswin_show(StatusWin *sw, const ArexxContext *ctx,
                   struct DiskObject *dobj);

/* Signal mask of the window's IDCMP port for the daemon's Wait(); 0 while no
 * window is open (the mask changes as the window opens/closes, so recompute
 * it every loop pass). */
unsigned long statuswin_sigmask(const StatusWin *sw);

/* Drain the window's IDCMP port, acting on all gadget and window events.
 * Returns 1 when the user chose Stop and confirmed it - the daemon should
 * shut down; 0 otherwise. */
int statuswin_handle(StatusWin *sw, const ArexxContext *ctx);

/* Refresh the report text in place. Call on every status tick; a no-op while
 * no window is open. */
void statuswin_update(StatusWin *sw, const ArexxContext *ctx);

/* Close the window (if open) and free everything. Safe on NULL. Call BEFORE
 * appicon_destroy(): that is what closes intuition/icon.library. */
void statuswin_destroy(StatusWin *sw);

#endif /* AMISYNC_STATUSWIN_H */
