/* config.c - configuration loading for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Minimal INI-style parser: "key = value" lines, ';' or '#' comment LINES
 * (there are no inline comments), and [section] headers (accepted, ignored).
 * Unknown keys are skipped with a warning so older configs keep working as
 * the daemon grows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "config.h"
#include "pathsafe.h"
#include "log.h"

void config_defaults(Config *cfg)
{
    strcpy(cfg->logfile,   "T:amisync.log");
    strcpy(cfg->rexx_port, CONFIG_REXX_PORT_DEFAULT);
    cfg->log_level  = LOG_INFO;
    cfg->log_max_kb = 256;

    strcpy(cfg->cert_path,   "ENVARC:Amisync/cert.pem");
    strcpy(cfg->key_path,    "ENVARC:Amisync/key.pem");
    strcpy(cfg->statedir,    "ENVARC:Amisync/state");
    cfg->keep_deletes = 180;
    strcpy(cfg->device_name, "amisync");
    cfg->listen_port = CONFIG_DEFAULT_PORT;
    cfg->discovery   = 1;
    cfg->serial_log  = 0;
    cfg->appicon     = 1;
    cfg->versioning  = 0;
    cfg->tz_offset_s    = 0;
    cfg->tz_offset_set  = 0;
    cfg->tz_from_locale = 0;
    cfg->num_peers   = 0;
    cfg->num_folders = 0;
}

/* Parse a boolean-ish config value: yes/on/true/1 -> 1, everything else
 * (no/off/false/0) -> 0. 'o' alone can't decide: "on" and "off" share it,
 * so it needs the second letter. */
static int parse_bool(const char *v)
{
    if (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' ||
        v[0] == 't' || v[0] == 'T')
        return 1;
    return (v[0] == 'o' || v[0] == 'O') && (v[1] == 'n' || v[1] == 'N');
}

/* Trim leading/trailing whitespace in place, returning the new start. */
static char *trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

/* Case-insensitive equality. */
static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Copy 'value' into a fixed field, always NUL-terminating. */
static void set_field(char *dst, int cap, const char *value)
{
    strncpy(dst, value, cap - 1);
    dst[cap - 1] = '\0';
}

/* Copy the next whitespace-delimited token from *cursor into dst (cap), and
 * advance *cursor past it. Returns 1 if a token was found, 0 if none left. */
static int next_token(const char **cursor, char *dst, int cap)
{
    const char *q = *cursor;
    int         n = 0;

    while (*q && isspace((unsigned char)*q)) q++;
    if (!*q) { dst[0] = '\0'; return 0; }
    if (*q == '"') {
        /* Double-quoted token: everything up to the closing quote, spaces
         * included - Amiga paths ("Ram Disk:Stuff") and folder labels need
         * this. An unterminated quote just runs to end of line. There is no
         * escaping; a literal '"' cannot appear inside (none can in an
         * AmigaOS path). */
        q++;
        while (*q && *q != '"' && n < cap - 1)
            dst[n++] = *q++;
        if (*q == '"')
            q++;
    } else {
        while (*q && !isspace((unsigned char)*q) && n < cap - 1)
            dst[n++] = *q++;
    }
    dst[n] = '\0';
    *cursor = q;
    return 1;
}

/* Parse a peer line value of the form "<device-id> <host>[:<port>]" and append
 * it to the peer table. The device ID is validated; a bad line is skipped. */
static void add_peer(Config *cfg, const char *value)
{
    ConfigPeer *p;
    const char *cur = value;
    char        idbuf[DEVICE_ID_BUFSZ];
    char        canon[DEVICE_ID_BUFSZ];
    char        hostbuf[CONFIG_HOST_MAX];
    char       *colon;
    int         i;

    if (cfg->num_peers >= CONFIG_MAX_PEERS) {
        log_printf(LOG_WARN, "config: too many peers, ignoring '%s'", value);
        return;
    }

    next_token(&cur, idbuf, sizeof(idbuf));
    next_token(&cur, hostbuf, sizeof(hostbuf));   /* optional */

    /* The device ID is required and validated; the host is optional - a peer
     * given by ID alone is reached via local discovery. */
    if (!idbuf[0] || !device_id_normalize(idbuf, canon)) {
        log_printf(LOG_WARN, "config: malformed peer line '%s'", value);
        return;
    }

    /* One entry per device. Two lines for the same peer is a natural thing to
     * try when it is reachable at two addresses, and easy to do by accident
     * since the same ID in different dash or case forms is the same device -
     * and it produced two live slots, which the targeted verbs then could not
     * manage: PAUSE or Remove acted on the first and left the second dialling
     * and syncing, while peer_manager_has (which scans them all) went on
     * reporting the device configured, so it never reappeared under
     * Discovered and could not be re-added. Restart was the only way out. */
    for (i = 0; i < cfg->num_peers; i++)
        if (device_id_equal(cfg->peers[i].id, canon)) {
            log_printf(LOG_WARN, "config: peer %.7s is already configured; "
                       "ignoring the duplicate", canon);
            return;
        }

    p = &cfg->peers[cfg->num_peers];
    /* Stored as the user wrote it - that is what STATUS shows them back, and
     * every comparison in the tree goes through device_id_equal, which
     * normalises both sides, so the spelling never has to match. */
    set_field(p->id, sizeof(p->id), idbuf);

    if (!hostbuf[0]) {                 /* ID-only: address comes from discovery */
        p->host[0] = '\0';
        p->port    = 0;
        cfg->num_peers++;
        return;
    }

    p->port = 0;                       /* 0 (absent, or ":0"/":junk") = default */
    colon = strrchr(hostbuf, ':');
    if (colon) {
        *colon = '\0';
        p->port = (unsigned short)atoi(colon + 1);
    }
    if (p->port == 0)
        p->port = CONFIG_DEFAULT_PORT;
    set_field(p->host, sizeof(p->host), hostbuf);

    cfg->num_peers++;
}

/* "[+-]HH[:MM]" -> seconds east of UTC. The sign convention everything modern
 * uses: +02:00 is two hours AHEAD of UTC. Returns 0 (and leaves *out alone) on
 * anything it does not fully understand, rather than guessing an offset - a
 * wrong one is worse than none, because it shifts every timestamp we exchange.
 * Bounded to +/-14:00, the widest real zone. */
static int parse_tz_offset(const char *v, int *out)
{
    int sign = 1, hh = 0, mm = 0;

    while (*v == ' ' || *v == '\t')
        v++;
    if (*v == '+')      v++;
    else if (*v == '-') { sign = -1; v++; }

    if (*v < '0' || *v > '9')
        return 0;
    hh = *v++ - '0';
    if (*v >= '0' && *v <= '9')
        hh = hh * 10 + (*v++ - '0');

    if (*v == ':' || *v == '.') {
        v++;
        if (*v < '0' || *v > '9')
            return 0;
        mm = *v++ - '0';
        if (*v >= '0' && *v <= '9')
            mm = mm * 10 + (*v++ - '0');
    }
    while (*v == ' ' || *v == '\t')
        v++;
    if (*v)                                    /* trailing junk: not a time */
        return 0;
    if (hh > 14 || mm > 59 || (hh == 14 && mm > 0))
        return 0;

    *out = sign * (hh * 3600 + mm * 60);
    return 1;
}

/* Parse a folder line value "<id> <path> [sendreceive|sendonly|receiveonly]"
 * and append it. The label defaults to the id; the mode to send-receive. */
static void add_folder(Config *cfg, const char *value)
{
    ConfigFolder *f;
    const char   *cur = value;
    char          idbuf[CONFIG_FOLDER_ID_MAX];
    char          pathbuf[CONFIG_PATH_MAX];
    char          modebuf[16];

    if (cfg->num_folders >= CONFIG_MAX_FOLDERS) {
        log_printf(LOG_WARN, "config: too many folders, ignoring '%s'", value);
        return;
    }
    if (!next_token(&cur, idbuf, sizeof(idbuf)) ||
        !next_token(&cur, pathbuf, sizeof(pathbuf))) {
        log_printf(LOG_WARN, "config: malformed folder line '%s'", value);
        return;
    }

    /* One entry per folder id, for the same reason peers are deduplicated:
     * sync_folder_index answers with the first, so a second entry is dead
     * weight that still gets announced - two folders with one id in the
     * ClusterConfig we send. */
    {
        int j;
        for (j = 0; j < cfg->num_folders; j++)
            if (strcmp(cfg->folders[j].id, idbuf) == 0) {
                log_printf(LOG_WARN, "config: folder '%s' is already "
                           "configured; ignoring the duplicate", idbuf);
                return;
            }
    }

    /* One entry per folder id, for the reason peers are deduplicated just
     * above: sync_folder_index answers with the first, so a second entry is
     * dead weight that is still announced - two folders sharing one id in the
     * ClusterConfig we send a peer. */
    {
        int j;
        for (j = 0; j < cfg->num_folders; j++)
            if (strcmp(cfg->folders[j].id, idbuf) == 0) {
                log_printf(LOG_WARN, "config: folder '%s' is already "
                           "configured; ignoring the duplicate", idbuf);
                return;
            }
    }

    f = &cfg->folders[cfg->num_folders];
    set_field(f->id, sizeof(f->id), idbuf);
    set_field(f->label, sizeof(f->label), idbuf);     /* label defaults to id */
    set_field(f->path, sizeof(f->path), pathbuf);

    f->mode = FOLDER_SENDRECEIVE;
    if (next_token(&cur, modebuf, sizeof(modebuf))) {
        char labelbuf[CONFIG_NAME_MAX];
        if (ci_equal(modebuf, "sendonly"))         f->mode = FOLDER_SENDONLY;
        else if (ci_equal(modebuf, "receiveonly")) f->mode = FOLDER_RECEIVEONLY;
        else if (!ci_equal(modebuf, "sendreceive"))
            log_printf(LOG_WARN, "config: unknown folder mode '%s', using sendreceive",
                       modebuf);
        /* Optional 5th token: a human label (Syncthing ids are random
         * "abcde-fghij" strings; the label is what people recognise).
         * Single token only - the tokenizer knows no quoting. */
        if (next_token(&cur, labelbuf, sizeof(labelbuf)))
            set_field(f->label, sizeof(f->label), labelbuf);
    }
    cfg->num_folders++;
}

static void apply_setting(Config *cfg, const char *key, const char *value)
{
    if (ci_equal(key, "logfile")) {
        set_field(cfg->logfile, sizeof(cfg->logfile), value);
    } else if (ci_equal(key, "rexxport")) {
        set_field(cfg->rexx_port, sizeof(cfg->rexx_port), value);
    } else if (ci_equal(key, "certfile")) {
        set_field(cfg->cert_path, sizeof(cfg->cert_path), value);
    } else if (ci_equal(key, "keyfile")) {
        set_field(cfg->key_path, sizeof(cfg->key_path), value);
    } else if (ci_equal(key, "statedir")) {
        set_field(cfg->statedir, sizeof(cfg->statedir), value);
    } else if (ci_equal(key, "logmax")) {
        cfg->log_max_kb = atoi(value);
    } else if (ci_equal(key, "keepdeletes")) {
        cfg->keep_deletes = atoi(value);
    } else if (ci_equal(key, "devicename")) {
        set_field(cfg->device_name, sizeof(cfg->device_name), value);
    } else if (ci_equal(key, "listenport")) {
        cfg->listen_port = (unsigned short)atoi(value);
    } else if (ci_equal(key, "discovery")) {
        cfg->discovery = parse_bool(value);
    } else if (ci_equal(key, "seriallog")) {
        cfg->serial_log = parse_bool(value);
    } else if (ci_equal(key, "appicon")) {
        cfg->appicon = parse_bool(value);
    } else if (ci_equal(key, "versioning")) {
        cfg->versioning = parse_bool(value);
    } else if (ci_equal(key, "tzoffset")) {
        int secs;
        if (ci_equal(value, "locale")) {
            cfg->tz_from_locale = 1;
        } else if (parse_tz_offset(value, &secs)) {
            cfg->tz_offset_s   = secs;
            cfg->tz_offset_set = 1;
        } else {
            log_printf(LOG_WARN, "config: tzoffset '%.16s' is not [+-]HH[:MM] "
                       "or 'locale' - ignoring, times stay UTC", value);
        }
    } else if (ci_equal(key, "peer")) {
        add_peer(cfg, value);
    } else if (ci_equal(key, "folder")) {
        add_folder(cfg, value);
    } else if (ci_equal(key, "loglevel")) {
        /* accept a number 0..3 or a name */
        if (ci_equal(value, "debug"))      cfg->log_level = LOG_DEBUG;
        else if (ci_equal(value, "info"))  cfg->log_level = LOG_INFO;
        else if (ci_equal(value, "warn"))  cfg->log_level = LOG_WARN;
        else if (ci_equal(value, "error")) cfg->log_level = LOG_ERROR;
        else                               cfg->log_level = atoi(value);
    } else {
        log_printf(LOG_WARN, "config: ignoring unknown key '%s'", key);
    }
}

void config_rexx_port(const char *path, char *out, int cap)
{
    FILE *fp;
    char  line[256];

    set_field(out, cap, CONFIG_REXX_PORT_DEFAULT);

    fp = fopen(path, "r");
    if (!fp)
        return;

    /* Same line grammar as config_load, but we only care about 'rexxport'. */
    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        char *eq;

        if (*p == '\0' || *p == ';' || *p == '#' || *p == '[')
            continue;
        eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        if (ci_equal(trim(p), "rexxport")) {
            set_field(out, cap, trim(eq + 1));
            break;
        }
    }
    fclose(fp);
}

/* ---- line-document model ---------------------------------------------
 *
 * Programmatic config edits go through a tiny document model: the file is
 * read into a list of lines, edited by index, and written back atomically
 * (temp + rename, restoring the original bytes on a failed swap). Comments
 * and layout ride along as opaque lines, so any edit preserves everything
 * it does not touch - the property that makes the comment-rich config file
 * safe to modify at runtime. Each operation (append peer, remove peer,
 * whatever a future settings UI needs) is a few lines against these
 * helpers instead of bespoke byte surgery.
 */

#define CONFDOC_MAX_BYTES (1024L * 1024L)

typedef struct {
    char **line;                 /* [n] malloc'd lines, no trailing newline */
    int    n, cap;
} ConfDoc;

static void doc_free(ConfDoc *d)
{
    int i;
    for (i = 0; i < d->n; i++)
        free(d->line[i]);
    free(d->line);
    d->line = NULL;
    d->n = d->cap = 0;
}

static int doc_grow(ConfDoc *d, int need)
{
    char **nl;
    int    ncap;

    if (need <= d->cap)
        return 1;
    ncap = d->cap ? d->cap * 2 : 64;
    while (ncap < need)
        ncap *= 2;
    nl = realloc(d->line, (size_t)ncap * sizeof(*nl));
    if (!nl)
        return 0;
    d->line = nl;
    d->cap  = ncap;
    return 1;
}

/* Insert a copy of 'text' as a new line at index 'at' (clamped). */
static int doc_insert(ConfDoc *d, int at, const char *text)
{
    char *copy;

    if (at < 0)
        at = 0;
    if (at > d->n)
        at = d->n;
    if (!doc_grow(d, d->n + 1))
        return 0;
    copy = malloc(strlen(text) + 1);
    if (!copy)
        return 0;
    strcpy(copy, text);
    memmove(&d->line[at + 1], &d->line[at],
            (size_t)(d->n - at) * sizeof(char *));
    d->line[at] = copy;
    d->n++;
    return 1;
}

static void doc_delete(ConfDoc *d, int at)
{
    if (at < 0 || at >= d->n)
        return;
    free(d->line[at]);
    memmove(&d->line[at], &d->line[at + 1],
            (size_t)(d->n - at - 1) * sizeof(char *));
    d->n--;
}

/* Load 'path' into 'd'. Returns 1 if the file existed and read cleanly,
 * 0 if it is absent (empty doc), -1 on I/O trouble (doc left empty). */
static int doc_load(ConfDoc *d, const char *path)
{
    FILE *fp;
    char *buf;
    long  sz, i, start;

    memset(d, 0, sizeof(*d));
    fp = fopen(path, "rb");
    if (!fp)
        return 0;
    if (fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) < 0 ||
        sz > CONFDOC_MAX_BYTES || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    if (sz == 0) {
        fclose(fp);
        return 1;
    }
    buf = malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    start = 0;
    for (i = 0; i <= sz; i++) {
        if (i == sz || buf[i] == '\n') {
            long  len = i - start;
            char *l;
            if (i == sz && len == 0)
                break;                /* final newline: no phantom line */
            l = malloc((size_t)len + 1);      /* memcpy + the store below fill it */
            if (!l || !doc_grow(d, d->n + 1)) {
                free(l);
                free(buf);
                doc_free(d);
                return -1;
            }
            memcpy(l, buf + start, (size_t)len);
            l[len] = '\0';
            d->line[d->n++] = l;
            start = i + 1;
        }
    }
    free(buf);
    return 1;
}

/* Write the doc back atomically: temp + rename, restoring the original
 * bytes if the swap fails - a failure cannot corrupt the config. */
static int doc_save(ConfDoc *d, const char *path)
{
    FILE *fp;
    char  tmp[160];
    char *orig = NULL;
    long  osz = -1;
    int   i, ok = 1;

    if (strlen(path) + 5 >= sizeof(tmp))
        return 0;
    sprintf(tmp, "%s.tmp", path);

    /* Snapshot the original for the restore path (absent file: none). */
    fp = fopen(path, "rb");
    if (fp) {
        if (fseek(fp, 0, SEEK_END) == 0 && (osz = ftell(fp)) >= 0 &&
            osz <= CONFDOC_MAX_BYTES && fseek(fp, 0, SEEK_SET) == 0 &&
            (orig = malloc(osz > 0 ? (size_t)osz : 1)) != NULL &&
            (osz == 0 || fread(orig, 1, (size_t)osz, fp) == (size_t)osz)) {
            /* snapshot held */
        } else {
            free(orig);
            orig = NULL;
            osz  = -1;
        }
        fclose(fp);
    }

    fp = fopen(tmp, "wb");
    if (!fp) {
        free(orig);
        return 0;
    }
    for (i = 0; i < d->n && ok; i++)
        ok = fputs(d->line[i], fp) >= 0 && fputc('\n', fp) != EOF;
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok) {
        remove(tmp);
        free(orig);
        return 0;
    }

    remove(path);                  /* AmigaOS rename() won't replace */
    if (rename(tmp, path) != 0) {
        if (orig && osz >= 0) {
            fp = fopen(path, "wb");
            if (fp) {
                fwrite(orig, 1, (size_t)osz, fp);
                fclose(fp);
            }
        }
        remove(tmp);
        free(orig);
        return 0;
    }
    free(orig);
    return 1;
}

/* ---- line classifiers ------------------------------------------------- */

/* The note the append paths write above a runtime-added entry, and the exact
 * text the remove paths strip again - one literal so they cannot drift. */
static const char runtime_note[] = "; added at runtime:";

static int is_runtime_note(const char *line)
{
    return strcmp(line, runtime_note) == 0;
}

static const char *skip_blanks(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* If 'line' is an ACTIVE "<key> = ..." line, return a pointer to its first
 * value token; else NULL. Comments never match, however key-shaped. */
static const char *value_of(const char *line, const char *key)
{
    const char *p   = skip_blanks(line);
    size_t      len = strlen(key);

    if (*p == ';' || *p == '#')
        return NULL;
    if (strncmp(p, key, len) != 0)
        return NULL;
    p = skip_blanks(p + len);
    if (*p != '=')
        return NULL;
    return skip_blanks(p + 1);
}

/* Length of the token 'v' points at. */
static size_t token_len(const char *v)
{
    const char *p = v;
    while (*p && *p != ' ' && *p != '\t')
        p++;
    return (size_t)(p - v);
}

/* Any "<key> ="-shaped line, active or a commented example: the anchor a
 * runtime-added entry is inserted after, so it lands in the right section. */
static int is_anchor_line(const char *s, const char *key)
{
    s = skip_blanks(s);
    while (*s == ';' || *s == '#')
        s = skip_blanks(s + 1);
    if (strncmp(s, key, strlen(key)) != 0)
        return 0;
    return *skip_blanks(s + strlen(key)) == '=';
}

/* Is 'line' an ACTIVE peer line for device 'id'? IDs compare normalized. */
static int is_peer_line_for(const char *line, const char *id)
{
    const char *v = value_of(line, "peer");
    char        peerid[DEVICE_ID_BUFSZ];
    size_t      n;

    if (!v)
        return 0;
    n = token_len(v);
    if (n == 0 || n >= sizeof(peerid))
        return 0;                    /* too long to be a device ID anyway */
    memcpy(peerid, v, n);
    peerid[n] = '\0';
    return device_id_equal(peerid, id);
}

/* Is 'line' an ACTIVE folder line for 'id' (exact match)? */
static int is_folder_line_for(const char *line, const char *id)
{
    const char *v    = value_of(line, "folder");
    size_t      want = strlen(id);

    if (!v)
        return 0;
    return token_len(v) == want && strncmp(v, id, want) == 0;
}

static int is_peerish_line(const char *s)   { return is_anchor_line(s, "peer"); }
static int is_folderish_line(const char *s) { return is_anchor_line(s, "folder"); }

/* ---- the operations ---------------------------------------------------- */

/* Delete every active line 'match'es, plus the runtime note above it, and save.
 * Returns 1 only if something was removed AND the file was written. */
static int remove_matching(const char *path, const char *id,
                           int (*match)(const char *, const char *))
{
    ConfDoc d;
    int     i, removed = 0, ok;

    if (!id || !id[0])
        return 0;
    if (doc_load(&d, path) != 1) {
        doc_free(&d);
        return 0;
    }

    i = 0;
    while (i < d.n) {
        if (match(d.line[i], id)) {
            doc_delete(&d, i);
            if (i > 0 && is_runtime_note(d.line[i - 1])) {
                doc_delete(&d, i - 1);         /* the note goes with it */
                i--;
            }
            removed = 1;
            continue;                          /* re-check the shifted line */
        }
        i++;
    }

    ok = removed && doc_save(&d, path);
    doc_free(&d);
    return ok;
}

/* Insert 'line' (under the runtime note) after the last 'is_anchor' line, so it
 * lands in that key's section. No anchor - or no file at all - appends at the
 * end, which also covers a fresh config. */
static int append_after_anchor(const char *path, const char *line,
                               int (*is_anchor)(const char *))
{
    ConfDoc d;
    int     i, anchor = -1;

    if (doc_load(&d, path) >= 0) {
        for (i = 0; i < d.n; i++)
            if (is_anchor(d.line[i]))
                anchor = i;
        if (anchor < 0)
            anchor = d.n - 1;
        if (doc_insert(&d, anchor + 1, runtime_note) &&
            doc_insert(&d, anchor + 2, line) &&
            doc_save(&d, path)) {
            doc_free(&d);
            return 1;
        }
    }
    doc_free(&d);

    /* Last resort (doc I/O trouble): plain append, creating if absent. */
    {
        FILE *fp = fopen(path, "a");
        if (!fp)
            return 0;
        fprintf(fp, "%s\n%s\n", runtime_note, line);
        fclose(fp);
        return 1;
    }
}

int config_remove_peer(const char *path, const char *id)
{
    return remove_matching(path, id, is_peer_line_for);
}

int config_remove_folder(const char *path, const char *id)
{
    return remove_matching(path, id, is_folder_line_for);
}

/* Refuse to write a line built from a string that would not stay one line (or
 * one token). The append paths below are the only place untrusted text -
 * a discovered device's address, a peer-offered folder's id and label -
 * becomes config SYNTAX, so this is the choke point that has to hold even if
 * a caller forgets to check: a lone '\n' in a value writes an extra setting
 * that the next config_load obeys. Callers already treat 0 as "not persisted"
 * and log it. */
static int field_ok(const char *what, const char *s)
{
    if (text_field_safe(s))
        return 1;
    log_printf(LOG_WARN, "config: refusing to write a %s containing control "
               "characters or quotes", what);
    return 0;
}

int config_append_peer(const char *path, const char *id, const char *host,
                       unsigned short port)
{
    char line[256];

    if (!field_ok("device id", id) || (host && !field_ok("peer address", host)))
        return 0;

    /* Precisions bound 'line'; they track the field caps in config.h. The
     * parser has no inline comments, so the note gets its own line. */
    if (host && host[0] && port)
        sprintf(line, "peer = %.*s %.*s:%u",
                DEVICE_ID_BUFSZ - 1, id,
                CONFIG_HOST_MAX - 1, host, (unsigned)port);
    else if (host && host[0])
        sprintf(line, "peer = %.*s %.*s",
                DEVICE_ID_BUFSZ - 1, id, CONFIG_HOST_MAX - 1, host);
    else
        sprintf(line, "peer = %.*s", DEVICE_ID_BUFSZ - 1, id);

    return append_after_anchor(path, line, is_peerish_line);
}

static const char *mode_word(FolderMode mode)
{
    switch (mode) {
    case FOLDER_SENDONLY:    return "sendonly";
    case FOLDER_RECEIVEONLY: return "receiveonly";
    default:                 return "sendreceive";
    }
}

int config_append_folder(const char *path, const char *id,
                         const char *fpath, FolderMode mode,
                         const char *label)
{
    char line[380];

    if (!field_ok("folder id", id) || !field_ok("folder path", fpath) ||
        (label && !field_ok("folder label", label)))
        return 0;

    /* Path and label are double-quoted when they contain whitespace (the
     * tokenizer understands quotes); the label rides as an optional trailing
     * token only when it adds information. Precisions bound 'line' and track
     * the field caps in config.h. */
    {
        const char *pq = (strchr(fpath, ' ') || strchr(fpath, '\t')) ? "\"" : "";
        int         n;
        n = sprintf(line, "folder = %.*s %s%.*s%s %s",
                    CONFIG_FOLDER_ID_MAX - 1, id,
                    pq, CONFIG_PATH_MAX - 1, fpath, pq, mode_word(mode));
        if (label && label[0] && strcmp(label, id) != 0) {
            const char *lq = (strchr(label, ' ') || strchr(label, '\t'))
                             ? "\"" : "";
            sprintf(line + n, " %s%.*s%s", lq, CONFIG_NAME_MAX - 1, label, lq);
        }
    }

    return append_after_anchor(path, line, is_folderish_line);
}

int config_load(const char *path, Config *cfg)
{
    FILE *fp;
    char  line[256];

    fp = fopen(path, "r");
    if (!fp)
        return 0;   /* absent/unreadable: keep defaults, not an error */

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        char *eq;

        if (*p == '\0' || *p == ';' || *p == '#')
            continue;                 /* blank or comment */
        if (*p == '[')
            continue;                 /* section header (accepted, unused) */

        eq = strchr(p, '=');
        if (!eq)
            continue;                 /* not a key=value line */

        *eq = '\0';
        apply_setting(cfg, trim(p), trim(eq + 1));
    }

    fclose(fp);
    return 1;
}
