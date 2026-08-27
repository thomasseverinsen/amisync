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

    if (failures) {
        printf("\n%d pathsafe check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall pathsafe checks passed\n");
    return 0;
}
