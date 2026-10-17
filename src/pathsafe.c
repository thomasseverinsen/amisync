/* pathsafe.c - validation of untrusted strings for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See pathsafe.h. Pure C, no Amiga dependencies, so both guards are exercised
 * by the host unit tests (tests/test_pathsafe.c) - important because this is
 * what keeps a hostile peer name from escaping the synced folder, and a
 * hostile address or folder id from writing its own line into amisync.conf.
 */

#include "pathsafe.h"

#include <string.h>

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

/* Length of the shortest-form UTF-8 sequence at 'p' (1-4) with its code point
 * in *cp, or 0 if 'p' does not start one. Overlong forms, surrogates and
 * anything past U+10FFFF are refused: an overlong C0 AF would otherwise decode
 * to a '/' that path_name_safe never saw. */
static int utf8_seq(const unsigned char *p, unsigned long *cp)
{
    unsigned char lo = 0x80, hi = 0xBF;
    int           n, i;

    if (p[0] < 0x80) { *cp = p[0]; return 1; }
    if (p[0] < 0xC2) return 0;
    if (p[0] < 0xE0) { n = 2; *cp = p[0] & 0x1F; }
    else if (p[0] < 0xF0) {
        n = 3; *cp = p[0] & 0x0F;
        if (p[0] == 0xE0) lo = 0xA0;
        if (p[0] == 0xED) hi = 0x9F;
    } else if (p[0] < 0xF5) {
        n = 4; *cp = p[0] & 0x07;
        if (p[0] == 0xF0) lo = 0x90;
        if (p[0] == 0xF4) hi = 0x8F;
    } else
        return 0;
    for (i = 1; i < n; i++) {
        unsigned char lim_lo = i == 1 ? lo : 0x80, lim_hi = i == 1 ? hi : 0xBF;
        if (p[i] < lim_lo || p[i] > lim_hi)
            return 0;
        *cp = (*cp << 6) | (p[i] & 0x3F);
    }
    return n;
}

/* Classify the component [p, end): 0 not valid UTF-8, 1 valid with every code
 * point in Latin-1, 2 valid with one beyond it. */
static int utf8_class(const unsigned char *p, const unsigned char *end)
{
    int           wide = 0;
    unsigned long cp;

    while (p < end) {
        int n = utf8_seq(p, &cp);
        if (!n || p + n > end)
            return 0;
        if (cp > 0xFF)
            wide = 1;
        p += n;
    }
    return wide ? 2 : 1;
}

int utf8_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    return utf8_class(p, p + strlen(s)) != 0;
}

int name_to_local(char *out, int cap, const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    int                  o = 0;

    for (;;) {
        const unsigned char *end = p;
        int                  conv;

        while (*end && *end != '/')
            end++;
        conv = utf8_class(p, end) == 1;
        while (p < end) {
            unsigned long cp = *p;
            int           n  = conv ? utf8_seq(p, &cp) : 1;
            if (o + 1 >= cap)
                return 0;
            out[o++] = (char)(conv ? cp : *p);
            p += n;
        }
        if (!*p)
            break;
        if (o + 1 >= cap)
            return 0;
        out[o++] = (char)*p++;                 /* the '/' */
    }
    out[o] = '\0';
    return 1;
}

int name_from_local(char *out, int cap, const char *local)
{
    const unsigned char *p = (const unsigned char *)local;
    int                  o = 0;

    for (;;) {
        const unsigned char *end = p;
        int                  raw;

        while (*end && *end != '/')
            end++;
        raw = utf8_class(p, end) == 2;
        for (; p < end; p++) {
            if (raw || *p < 0x80) {
                if (o + 1 >= cap)
                    return 0;
                out[o++] = (char)*p;
            } else {
                if (o + 2 >= cap)
                    return 0;
                out[o++] = (char)(0xC0 | (*p >> 6));
                out[o++] = (char)(0x80 | (*p & 0x3F));
            }
        }
        if (!*p)
            break;
        if (o + 1 >= cap)
            return 0;
        out[o++] = (char)*p++;
    }
    out[o] = '\0';
    return 1;
}
