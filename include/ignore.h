/* ignore.h - .stignore pattern matching for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A pragmatic subset of Syncthing's ignore syntax, enough for the common cases
 * a small folder needs. Pure string logic (no file or OS calls), so the parser
 * and matcher are unit-checked on the build host (tests/test_ignore.c); the
 * folder module reads the .stignore file and hands the text here.
 *
 * Supported per line (against forward-slash relative paths):
 *   - blank lines and `//` comments are skipped.
 *   - `#include file` pulls in another ignore file (the name is taken
 *     verbatim, no brackets or quoting); other `#`-directives are skipped.
 *   - leading `!`  : negate (re-include) - first matching line wins, so put
 *     negations before the broader pattern they carve out of.
 *   - leading `/`  : anchor to the folder root (match the whole path).
 *   - any leading `(?x)` flag group is accepted and ignored - `(?i)` and
 *     `(?d)` are the ones Syncthing defines, and matching here is always
 *     case-insensitive anyway, matching AmigaOS file systems.
 *   - globs `*` (within a path segment), `**` (across segments), `?`, and
 *     character classes `[abc]` / `[a-z]` / `[!neg]`.
 *   - a pattern WITHOUT a slash matches that name in ANY directory (any path
 *     segment); a pattern WITH a slash (or rooted) matches the path or any of
 *     its ancestor directories, so ignoring a directory ignores its contents.
 *
 * Not supported (v1): escaping of glob metacharacters.
 */

#ifndef AMISYNC_IGNORE_H
#define AMISYNC_IGNORE_H

#define IGNORE_MAX_PATTERNS  48
#define IGNORE_PATTERN_MAX  128

typedef struct {
    char          glob[IGNORE_PATTERN_MAX];
    unsigned char negate;     /* line began with '!'                     */
    unsigned char has_slash;  /* rooted, or the glob contains a '/'      */
} IgnorePattern;

typedef struct {
    IgnorePattern pats[IGNORE_MAX_PATTERNS];
    int           n;
    int           dropped;    /* patterns lost to the caps below: real lines
                               * that will NOT be enforced (set full, or one
                               * pattern over IGNORE_PATTERN_MAX). The loader
                               * warns; matching itself stays silent. */
} IgnoreSet;

/* Reset to empty. */
void ignore_clear(IgnoreSet *set);

/* Callback that resolves a `#include name` directive: it should read 'name'
 * and call ignore_parse() on its contents (with the same callback).
 *
 * The callback MUST bound its own nesting depth: a file that includes itself
 * (directly or in a cycle) recurses inc -> ignore_parse -> inc forever, and a
 * runaway stack takes the machine down here. Nothing in this module can see
 * the depth - it doesn't know what a name resolves to. folder_include carries
 * the counter in its ctx. */
typedef void (*IgnoreInclude)(void *ctx, const char *name, IgnoreSet *set);

/* Parse 'len' bytes of .stignore text, appending the patterns found (up to the
 * fixed capacity; over-cap lines are counted in set->dropped). 'inc'/'ctx'
 * handle `#include` (pass NULL to skip includes). May be called more than
 * once. */
void ignore_parse(IgnoreSet *set, const char *text, int len,
                  IgnoreInclude inc, void *ctx);

/* 1 if 'relpath' (a forward-slash relative path, no leading slash) is ignored
 * by the set, else 0. An empty set ignores nothing. */
int ignore_match(const IgnoreSet *set, const char *relpath);

#endif /* AMISYNC_IGNORE_H */
