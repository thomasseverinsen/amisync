/* ignore.c - .stignore pattern matching for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See ignore.h. Pure C (no OS calls) - exercised on the host in
 * tests/test_ignore.c.
 */

#include <string.h>

#include "ignore.h"

static int lc(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

/* Case-insensitive glob over 's' (NUL-terminated):
 *   '*'  matches zero or more characters except '/'
 *   '**' matches zero or more characters including '/'
 *   '?'  matches one character except '/'
 * Recurses on the wildcards. A shared step budget bounds total work: naive
 * backtracking is exponential on pathological multi-star patterns (e.g.
 * "*a*a*a..."), which a user's own .stignore could otherwise turn into a hang.
 * When the budget is exhausted the match gives up (returns no-match) rather
 * than spin. The budget (GLOB_BUDGET) is far above any legitimate pattern. */
#define GLOB_BUDGET  200000

static int glob_rec(const char *p, const char *s, int *budget)
{
    if (--*budget <= 0)
        return 0;                           /* pathological pattern: bail out */
    while (*p) {
        if (p[0] == '*' && p[1] == '*') {
            p += 2;
            if (*p == '/')                  /* a slash after ** may match nothing */
                p++;
            if (*p == '\0')
                return 1;                   /* trailing ** matches the rest */
            for (;; s++) {
                if (glob_rec(p, s, budget))
                    return 1;
                if (*s == '\0')
                    return 0;
            }
        } else if (*p == '*') {
            p++;
            for (;;) {
                if (glob_rec(p, s, budget))
                    return 1;
                if (*s == '\0' || *s == '/')
                    return 0;
                s++;
            }
        } else if (*p == '?') {
            if (*s == '\0' || *s == '/')
                return 0;
            p++; s++;
        } else if (*p == '[') {
            /* Character class [abc] / [a-z] / [!neg] (case-insensitive, never
             * matches '/' or end-of-string). */
            const char *q = p + 1;
            int         neg = 0, matched = 0, sc;
            if (*q == '!' || *q == '^') { neg = 1; q++; }
            if (*s == '\0' || *s == '/')
                return 0;
            sc = lc((unsigned char)*s);
            while (*q && *q != ']') {
                if (q[1] == '-' && q[2] && q[2] != ']') {   /* range a-z */
                    if (sc >= lc((unsigned char)q[0]) && sc <= lc((unsigned char)q[2]))
                        matched = 1;
                    q += 3;
                } else {
                    if (sc == lc((unsigned char)*q))
                        matched = 1;
                    q++;
                }
            }
            if (*q != ']')
                return 0;                       /* malformed class */
            if (matched == neg)
                return 0;
            p = q + 1;
            s++;
        } else {
            if (lc((unsigned char)*p) != lc((unsigned char)*s))
                return 0;
            p++; s++;
        }
    }
    return *s == '\0';
}

static int glob_match(const char *p, const char *s)
{
    int budget = GLOB_BUDGET;
    return glob_rec(p, s, &budget);
}

/* Longest path prefix this matcher will consider. Callers feed it relative
 * paths, which BEP_PATH_MAX caps at 255, so the bound is generous - but a
 * prefix over it is reported as NO MATCH, i.e. the path is not ignored. */
#define IGNORE_PATH_MAX  384

/* Match 'glob' against the leading 'len' bytes of 's' (a path prefix). */
static int glob_match_prefix(const char *glob, const char *s, int len)
{
    char buf[IGNORE_PATH_MAX];
    if (len > (int)sizeof(buf) - 1)
        return 0;                           /* too long: treated as no match */
    memcpy(buf, s, len);
    buf[len] = '\0';
    return glob_match(glob, buf);
}

/* A slash/rooted pattern matches the whole path or any ancestor prefix (so an
 * ignored directory ignores everything beneath it). */
static int match_path(const char *glob, const char *path)
{
    const char *p;
    if (glob_match(glob, path))
        return 1;
    for (p = path; *p; p++)
        if (*p == '/' && glob_match_prefix(glob, path, (int)(p - path)))
            return 1;
    return 0;
}

/* A no-slash pattern matches any single path segment. */
static int match_segment(const char *glob, const char *path)
{
    const char *seg = path;
    const char *p   = path;
    for (;; p++) {
        if (*p == '/' || *p == '\0') {
            if (glob_match_prefix(glob, seg, (int)(p - seg)))
                return 1;
            if (*p == '\0')
                return 0;
            seg = p + 1;
        }
    }
}

void ignore_clear(IgnoreSet *set)
{
    set->n       = 0;
    set->dropped = 0;
}

/* Consume one line (up to '\n' or end); return a pointer past it. */
static const char *parse_line(IgnoreSet *set, const char *p, const char *end,
                              IgnoreInclude inc, void *ctx)
{
    const char   *start = p;
    int           len, negate = 0, rooted = 0;
    IgnorePattern *pat;

    while (p < end && *p != '\n')
        p++;
    len = (int)(p - start);
    if (p < end)
        p++;                                /* step past '\n' for the caller */

    /* trim a trailing '\r' (CRLF files) */
    if (len > 0 && start[len - 1] == '\r')
        len--;

    if (len == 0)
        return p;                           /* blank */
    if (len >= 2 && start[0] == '/' && start[1] == '/')
        return p;                           /* // comment */
    if (start[0] == '#') {
        /* "#include name": hand the name to the caller's loader (verbatim -
         * Syncthing's syntax has no brackets or quoting). */
        static const char inc_kw[] = "#include";
        const int         kwlen    = (int)sizeof(inc_kw) - 1;
        if (inc && len > kwlen + 1 && strncmp(start, inc_kw, kwlen) == 0 &&
            (start[kwlen] == ' ' || start[kwlen] == '\t')) {
            const char *nm = start + kwlen;
            int         nl;
            char        name[IGNORE_PATTERN_MAX];
            while (nm < start + len && (*nm == ' ' || *nm == '\t'))
                nm++;
            nl = (int)((start + len) - nm);
            if (nl > 0 && nl < (int)sizeof(name)) {
                memcpy(name, nm, nl);
                name[nl] = '\0';
                inc(ctx, name, set);
            }
        }
        return p;                           /* other directives: skipped */
    }

    if (start[0] == '!') { negate = 1; start++; len--; }

    /* Skip any (?x) flag group, not just the (?i)/(?d) Syncthing defines
     * today: an unknown flag is better ignored than taken as literal text,
     * the same forward-compatibility bep.c applies to unknown fields. */
    while (len >= 4 && start[0] == '(' && start[1] == '?' && start[3] == ')') {
        start += 4; len -= 4;
    }

    if (len > 0 && start[0] == '/') { rooted = 1; start++; len--; }

    if (len <= 0)
        return p;                           /* empty after flags: not a pattern */
    if (len >= IGNORE_PATTERN_MAX || set->n >= IGNORE_MAX_PATTERNS) {
        set->dropped++;                     /* too long / set full: this line
                                             * will NOT be enforced */
        return p;
    }

    pat = &set->pats[set->n++];
    memcpy(pat->glob, start, len);
    pat->glob[len]  = '\0';
    pat->negate     = (unsigned char)negate;
    pat->has_slash  = (unsigned char)(rooted || strchr(pat->glob, '/') != NULL);
    return p;
}

void ignore_parse(IgnoreSet *set, const char *text, int len,
                  IgnoreInclude inc, void *ctx)
{
    const char *p   = text;
    const char *end = text + len;
    while (p < end)
        p = parse_line(set, p, end, inc, ctx);
}

int ignore_match(const IgnoreSet *set, const char *relpath)
{
    int i;
    for (i = 0; i < set->n; i++) {
        const IgnorePattern *pat = &set->pats[i];
        int hit = pat->has_slash ? match_path(pat->glob, relpath)
                                 : match_segment(pat->glob, relpath);
        if (hit)
            return pat->negate ? 0 : 1;     /* first match decides */
    }
    return 0;
}
