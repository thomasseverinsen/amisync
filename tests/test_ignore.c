/* test_ignore.c - host unit check for .stignore pattern matching
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host (see `make test-ignore`). ignore is pure, so
 * the glob/anchoring/negation rules are checked here with a fast loop.
 */

#include "ignore.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

static void load(IgnoreSet *s, const char *text)
{
    ignore_clear(s);
    ignore_parse(s, text, (int)strlen(text), NULL, NULL);
}

/* Mock #include loader: maps a couple of names to canned ignore text. */
static void mock_include(void *ctx, const char *name, IgnoreSet *set)
{
    (void)ctx;
    if (strcmp(name, "common") == 0)
        ignore_parse(set, "*.bak\n", 6, mock_include, ctx);
}

int main(void)
{
    IgnoreSet s;

    /* no-slash pattern matches the name in any directory */
    load(&s, "*.tmp\n");
    ok("tmp at root",      ignore_match(&s, "a.tmp"));
    ok("tmp in subdir",    ignore_match(&s, "sub/b.tmp"));
    ok("non-tmp kept",    !ignore_match(&s, "a.txt"));
    ok("tmp deep",         ignore_match(&s, "x/y/z.tmp"));

    /* no-slash directory name ignores the directory's contents */
    load(&s, "build\n");
    ok("dir itself",       ignore_match(&s, "build"));
    ok("dir contents",     ignore_match(&s, "build/out.o"));
    ok("dir nested",       ignore_match(&s, "a/build/x"));
    ok("substring kept",  !ignore_match(&s, "rebuild"));

    /* rooted pattern: anchored at the folder root, contents included */
    load(&s, "/secret\n");
    ok("rooted dir",       ignore_match(&s, "secret"));
    ok("rooted contents",  ignore_match(&s, "secret/a.txt"));
    ok("rooted not nested",!ignore_match(&s, "a/secret/b"));

    /* ** crosses directories */
    load(&s, "logs/**\n");
    ok("star2 child",      ignore_match(&s, "logs/app.log"));
    ok("star2 deep",       ignore_match(&s, "logs/2026/06/x.log"));
    ok("star2 other kept",!ignore_match(&s, "logsx/app.log"));

    /* path pattern with a slash is anchored; matches the dir's contents too */
    load(&s, "foo/bar\n");
    ok("path exact",       ignore_match(&s, "foo/bar"));
    ok("path contents",    ignore_match(&s, "foo/bar/baz.txt"));
    ok("path not floating",!ignore_match(&s, "x/foo/bar"));

    /* negation: first match wins, so the ! line must precede the broad one */
    load(&s, "!keep.tmp\n*.tmp\n");
    ok("negated kept",    !ignore_match(&s, "keep.tmp"));
    ok("other ignored",    ignore_match(&s, "drop.tmp"));

    /* comments / blank lines */
    load(&s, "// a comment\n\n*.bak\n");
    ok("comment skipped",  s.n == 1);
    ok("after comment",    ignore_match(&s, "x.bak"));

    /* case-insensitive (AmigaOS file systems) */
    load(&s, "*.TMP\n");
    ok("case-insensitive", ignore_match(&s, "Photo.tmp"));

    /* ? matches one non-slash char */
    load(&s, "file?.txt\n");
    ok("question hit",     ignore_match(&s, "file1.txt"));
    ok("question miss",   !ignore_match(&s, "file12.txt"));

    /* character classes */
    load(&s, "*.[oa]\n");
    ok("class o",          ignore_match(&s, "main.o"));
    ok("class a",          ignore_match(&s, "lib.a"));
    ok("class miss",      !ignore_match(&s, "main.c"));
    load(&s, "file[0-9].txt\n");
    ok("range hit",        ignore_match(&s, "file7.txt"));
    ok("range miss",      !ignore_match(&s, "fileX.txt"));
    load(&s, "[!a-c]*\n");
    ok("negclass hit",     ignore_match(&s, "ztop"));
    ok("negclass miss",   !ignore_match(&s, "atop"));

    /* #include directive via a loader callback */
    ignore_clear(&s);
    ignore_parse(&s, "#include common\n*.tmp\n", 21, mock_include, NULL);
    ok("include pulled",   ignore_match(&s, "x.bak"));   /* from common */
    ok("include + own",    ignore_match(&s, "y.tmp"));   /* own line     */
    /* with no loader, #include is skipped */
    ignore_clear(&s);
    ignore_parse(&s, "#include common\n", 16, NULL, NULL);
    ok("include skipped",  s.n == 0 && !ignore_match(&s, "x.bak"));

    /* empty set ignores nothing */
    load(&s, "");
    ok("empty set",       !ignore_match(&s, "anything"));

    /* Pathological multi-star pattern against a long non-matching string:
     * naive backtracking is exponential and would hang; the glob step budget
     * makes it give up and return (no match). The check here is simply that it
     * RETURNS quickly - a regression would time the test out. */
    load(&s, "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a\n");
    ok("pathological glob returns",
       !ignore_match(&s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
    /* A genuinely matching star pattern still works. */
    load(&s, "*a*b*c\n");
    ok("multi-star still matches", ignore_match(&s, "xxaxxbxxc"));

    /* Overflow accounting: patterns past the set's capacity are dropped AND
     * counted, so the loader can warn that real lines are not enforced. */
    {
        char big[4096];
        int  i, off = 0;
        for (i = 0; i < IGNORE_MAX_PATTERNS + 5; i++)
            off += sprintf(big + off, "pat%d\n", i);
        ignore_clear(&s);
        ignore_parse(&s, big, off, NULL, NULL);
        ok("overflow keeps capacity", s.n == IGNORE_MAX_PATTERNS);
        ok("overflow counted",        s.dropped == 5);
        ok("kept patterns match",     ignore_match(&s, "pat0"));
    }
    /* An over-long single pattern is dropped and counted; blanks and
     * comments are not (they are not patterns). */
    {
        char line[IGNORE_PATTERN_MAX + 8];
        int  i;
        for (i = 0; i < IGNORE_PATTERN_MAX + 2; i++)
            line[i] = 'x';
        line[i++] = '\n';
        line[i] = '\0';
        ignore_clear(&s);
        ignore_parse(&s, line, (int)strlen(line), NULL, NULL);
        ok("over-long pattern counted", s.n == 0 && s.dropped == 1);
        load(&s, "\n// comment\n\n");
        ok("blanks/comments not counted", s.n == 0 && s.dropped == 0);
    }

    if (failures) {
        printf("\n%d ignore check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall ignore checks passed\n");
    return 0;
}
