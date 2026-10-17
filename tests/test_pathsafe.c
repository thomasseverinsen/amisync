/* test_pathsafe.c - host unit check for the untrusted-string guards
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * path_name_safe() is the security boundary that keeps a hostile peer's file
 * name from escaping the synced folder when it is joined with AddPart().
 * text_field_safe() is the one that keeps a hostile address or folder id from
 * writing a config line of its own into amisync.conf. These cases cover the
 * accepted shapes and every rejection the fixes were written for, plus
 * adversarial variants (encodings, mixed, nested, boundary).
 */

#include "pathsafe.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(const char *name, int want)
{
    int got = path_name_safe(name);
    if (got == want) {
        printf("ok   %-40s -> %d\n", name ? name : "(NULL)", got);
    } else {
        printf("FAIL %-40s -> %d (wanted %d)\n", name ? name : "(NULL)", got, want);
        failures++;
    }
}

/* Same, for the config-line guard. Control characters are printed escaped so a
 * failing case is readable in the log. */
static void expect_text(const char *s, int want)
{
    char shown[64];
    int  got = text_field_safe(s), i = 0;

    if (!s) {
        strcpy(shown, "(NULL)");
    } else {
        const unsigned char *p = (const unsigned char *)s;
        for (; *p && i < (int)sizeof(shown) - 5; p++) {
            if (*p >= 0x20 && *p != 0x7F) {
                shown[i++] = (char)*p;
            } else {
                shown[i++] = '\\';
                shown[i++] = *p == '\n' ? 'n' : *p == '\r' ? 'r' :
                             *p == '\t' ? 't' : 'x';
            }
        }
        shown[i] = '\0';
    }
    if (got == want) {
        printf("ok   text %-35s -> %d\n", shown, got);
    } else {
        printf("FAIL text %-35s -> %d (wanted %d)\n", shown, got, want);
        failures++;
    }
}

/* Name charset mapping: 'local' is what lands on disk for wire name 'utf8',
 * and reading 'local' back must give 'utf8' again. */
static void expect_map(const char *utf8, const char *local)
{
    char a[256], b[256];
    int  ok = name_to_local(a, sizeof a, utf8) && strcmp(a, local) == 0 &&
              name_from_local(b, sizeof b, local) && strcmp(b, utf8) == 0 &&
              utf8_valid(b);
    printf("%s map %s\n", ok ? "ok  " : "FAIL", local);
    if (!ok)
        failures++;
}

static void expect_utf8(const char *s, int want)
{
    int got = utf8_valid(s);
    printf("%s utf8_valid -> %d\n", got == want ? "ok  " : "FAIL", got);
    if (got != want)
        failures++;
}

int main(void)
{
    /* --- accepted: ordinary relative names --------------------------- */
    expect("file.txt",              1);
    expect("a",                     1);
    expect("dir/file.txt",          1);
    expect("a/b/c/d/e.bin",         1);
    expect("photos/2026/img.jpg",   1);
    expect("name with spaces.doc",  1);
    expect("weird#chars$ok!.txt",   1);   /* only ':' '\\' '/' are special  */
    expect("...dots.txt",           1);   /* leading dots that aren't . or .. */
    expect("a..b",                  1);   /* ".." only as a whole component */
    expect("file.",                 1);   /* trailing dot in a name is fine  */

    /* --- rejected: empty / null -------------------------------------- */
    expect(NULL,                    0);
    expect("",                      0);

    /* --- rejected: volume (absolute) via ':' ------------------------- */
    expect("S:User-Startup",        0);   /* the classic attack            */
    expect("RAM:x",                 0);
    expect("Work:docs/f",           0);
    expect("dir/DH0:evil",          0);   /* ':' in a later component too   */
    expect("a/b:c",                 0);

    /* --- rejected: parent escape via leading '/' --------------------- */
    expect("/S/x",                  0);
    expect("/",                     0);
    expect("/etc/passwd",           0);

    /* --- rejected: ".." traversal ------------------------------------ */
    expect("..",                    0);
    expect("../x",                  0);
    expect("a/../b",                0);
    expect("a/..",                  0);
    expect("../../x",               0);

    /* --- rejected: "." component ------------------------------------- */
    expect(".",                     0);
    expect("./x",                   0);
    expect("a/./b",                 0);

    /* --- rejected: empty components ("//", trailing '/') ------------- */
    expect("a//b",                  0);
    expect("a/",                    0);   /* trailing slash -> empty last   */
    expect("//x",                   0);

    /* --- rejected: backslash (foreign separator) --------------------- */
    expect("a\\b",                  0);
    expect("dir\\..\\x",            0);

    /* --- text_field_safe: what may become a config-line token --------- */

    /* accepted: ordinary values, including the ones that need quoting */
    expect_text("192.168.1.5",          1);
    expect_text("nas.local",            1);
    expect_text("Work:Documents",       1);   /* a folder path IS a volume path */
    expect_text("My Documents",         1);   /* space: the writer quotes it    */
    expect_text("",                     1);   /* empty injects nothing          */
    expect_text("caf\xe9-backup",       1);   /* ISO-8859-1 label text          */
    expect_text(";not-a-comment-here",  1);   /* only line STARTS are comments  */

    /* rejected: NULL */
    expect_text(NULL,                   0);

    /* rejected: the injection itself - a value that writes its own setting */
    expect_text("1.2.3.4\nfolder = sys SYS: sendreceive", 0);
    expect_text("id\nlistenport = 1",   0);
    expect_text("\n",                   0);
    expect_text("trailing\n",           0);
    expect_text("\rcarriage",           0);   /* CR: a line end for some readers */

    /* rejected: other control characters (tab splits a value into tokens) */
    expect_text("two\ttokens",          0);
    expect_text("bell\a",               0);
    expect_text("del\x7f",              0);

    /* rejected: the quote the folder writer wraps whitespace values in */
    expect_text("say \"hi\"",           0);
    expect_text("\"",                   0);

    /* --- name charset mapping ---------------------------------------- */
    expect_map("plain/name.txt",           "plain/name.txt");
    expect_map("Avi\xC3\xB3n.mp4",          "Avi\xF3n.mp4");        /* Avión */
    expect_map("Caf\xC3\xA9/D\xC3\xA9j\xC3\xA0", "Caf\xE9/D\xE9j\xE0");
    expect_map("\xC3\xBF\xC2\xA0",           "\xFF\xA0");           /* top of Latin-1 */
    /* beyond Latin-1: that component stays raw UTF-8, its neighbours map */
    expect_map("\xE6\x97\xA5/Avi\xC3\xB3n",   "\xE6\x97\xA5/Avi\xF3n");
    expect_map("x\xE2\x82\xAC\xC3\xA9",       "x\xE2\x82\xAC\xC3\xA9");   /* "x€é" */
    /* a Latin-1 name that happens to look like UTF-8 survives the trip */
    expect_map("\xC3\x83\xC2\xB3",           "\xC3\xB3");

    {   /* invalid UTF-8 (overlong '/') is left alone, never decoded */
        char o[16];
        int  ok = name_to_local(o, sizeof o, "a\xC0\xAF") &&
                  strcmp(o, "a\xC0\xAF") == 0;
        printf("%s overlong kept raw\n", ok ? "ok  " : "FAIL");
        if (!ok) failures++;
        ok = !name_from_local(o, 4, "\xE9\xE9");          /* needs 5 bytes */
        printf("%s from_local cap\n", ok ? "ok  " : "FAIL");
        if (!ok) failures++;
        strcpy(o, "Avi\xC3\xB3n");                         /* in place */
        ok = name_to_local(o, sizeof o, o) && strcmp(o, "Avi\xF3n") == 0;
        printf("%s to_local in place\n", ok ? "ok  " : "FAIL");
        if (!ok) failures++;
    }

    expect_utf8("ascii",                1);
    expect_utf8("Caf\xC3\xA9",          1);
    expect_utf8("Caf\xE9",              0);   /* Latin-1 */
    expect_utf8("\xC0\xAF",             0);   /* overlong */
    expect_utf8("\xED\xA0\x80",         0);   /* surrogate */
    expect_utf8("\xF4\x90\x80\x80",     0);   /* past U+10FFFF */
    expect_utf8("\xF0\x9F\x98\x80",     1);   /* emoji */
    expect_utf8("\xC3",                 0);   /* truncated */

    if (failures) {
        printf("\n%d pathsafe check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall pathsafe checks passed\n");
    return 0;
}
