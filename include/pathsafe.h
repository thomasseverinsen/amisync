/* pathsafe.h - validation of untrusted strings for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Two guards over strings that arrive from outside, both pure C (no Amiga
 * headers) so they are unit-tested on the build host:
 *
 *   path_name_safe   a peer sends file names over BEP that amisync joins to a
 *                    folder root with AddPart(). On AmigaOS a path component
 *                    containing ':' is an absolute volume path and a leading
 *                    '/' escapes to the parent, so an unvalidated name like
 *                    "S:User-Startup" or "/foo" would read or write outside
 *                    the synced folder. folder.c's folder_name_safe() is a
 *                    thin wrapper over it.
 *
 *   text_field_safe  strings that end up as tokens in a line of amisync.conf
 *                    (a discovered device's address, a peer-offered folder's
 *                    id and label). The config is line-oriented, so an
 *                    embedded newline does not corrupt a value - it writes a
 *                    whole extra SETTING, which the next load obeys.
 */

#ifndef AMISYNC_PATHSAFE_H
#define AMISYNC_PATHSAFE_H

/* Return 1 if 'name' is a safe relative path to use under a folder root, 0 if
 * it must be refused. Rejects: NULL/empty, a leading '/', any component that
 * contains ':' or '\\', any empty component (from "//" or a trailing '/'),
 * and "." or ".." components. Only forward-slash separated relative paths of
 * ordinary components are accepted. */
int path_name_safe(const char *name);

/* Return 1 if 's' can be written into a config line without changing that
 * line's structure, 0 if it must be refused. Rejects NULL, any control
 * character (a newline writes a whole extra config line; a CR or a tab splits
 * or hides the rest of the value) and the double quote the folder writer uses
 * to wrap paths and labels containing whitespace. An empty string is safe -
 * it injects nothing; callers decide separately whether empty is meaningful.
 * High-bit bytes pass: they are ordinary ISO-8859-1 text in Amiga labels. */
int text_field_safe(const char *s);

#endif /* AMISYNC_PATHSAFE_H */
