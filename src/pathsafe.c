/* pathsafe.c - validation of untrusted strings for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See pathsafe.h. Pure C, no Amiga dependencies, so both guards are exercised
 * by the host unit tests (tests/test_pathsafe.c) - important because this is
 * what keeps a hostile peer name from escaping the synced folder, and a
 * hostile address or folder id from writing its own line into amisync.conf.
 */

#include "pathsafe.h"

int path_name_safe(const char *name)
{
    const char *seg;

    if (!name || !name[0] || name[0] == '/')   /* NULL, empty, or parent escape */
        return 0;

    seg = name;
    for (;;) {
        const char *p = seg;
        int         len;

        while (*p && *p != '/') {               /* one path component */
            if (*p == ':' || *p == '\\')        /* volume / foreign separator */
                return 0;
            p++;
        }
        len = (int)(p - seg);

        if (len == 0)                           /* "" (from "//" or trailing/) */
            return 0;
        if (len == 1 && seg[0] == '.')          /* "." */
            return 0;
        if (len == 2 && seg[0] == '.' && seg[1] == '.')   /* ".." */
            return 0;
        if (!*p)
            break;
        seg = p + 1;
    }
    return 1;
}

int text_field_safe(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    if (!p)
        return 0;
    for (; *p; p++) {
        if (*p < 0x20 || *p == 0x7F)   /* newline first of all: a config line */
            return 0;                  /* of its own, obeyed on the next load */
        if (*p == '"')                 /* unbalances the folder writer's quotes */
            return 0;
    }
    return 1;
}
