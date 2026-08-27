/* test_config.c - host unit check for the config parser
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host (see `make test-config`). config.c is plain
 * stdio/string code; device_id.c provides the peer-ID validation (compiled
 * with -DDEVICE_ID_HOST_TEST, which drops its OpenSSL cert half). Each case
 * writes a config to a temp file under build/ and loads it.
 */

#include "config.h"
#include "device_id.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* config.c warns through log_printf; the test wants silence. */
void log_printf(LogLevel level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

static int failures;

static void ok(const char *what, int cond)
{
    if (cond) printf("ok   %s\n", what);
    else { printf("FAIL %s\n", what); failures++; }
}

#define TMPCONF "build/test_config.conf"

/* Byte length of the temp config, or -1 if it is not there. */
static long filesize(const char *path)
{
    FILE *f = fopen(path, "rb");
    long  n;
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0)
        n = -1;
    fclose(f);
    return n;
}

/* A verified-valid device ID (the genid M1 reference vector). */
#define GOODID "P56IOI7-MZJNU2Y-IQGDREY-DM2MGTI-MGL3BXN-PQ6W5BM-TBBZ4TJ-XZWICQ2"

/* Further distinct, checksum-valid device IDs, minted from a seed rather than
 * hard-coded: peers are deduplicated by device, so any test that wants more
 * than one peer needs more than one identity. Four rotating buffers, which is
 * enough for one snprintf argument list. */
static const char *otherid(unsigned char seed)
{
    static char   buf[4][DEVICE_ID_BUFSZ];
    static int    slot;
    unsigned char raw[32];
    char         *out = buf[slot++ & 3];

    memset(raw, seed, sizeof(raw));
    raw[0] = (unsigned char)(seed + 1);        /* keep low seeds distinct */
    device_id_from_raw(raw, out);
    return out;
}

/* Write 'text' to the temp config and load it over fresh defaults. */
static int load(Config *cfg, const char *text)
{
    FILE *f = fopen(TMPCONF, "w");
    if (!f) { printf("FAIL cannot write %s\n", TMPCONF); exit(1); }
    fputs(text, f);
    fclose(f);
    config_defaults(cfg);
    return config_load(TMPCONF, cfg);
}

static void test_defaults(void)
{
    Config cfg;
    config_defaults(&cfg);
    ok("default logfile",     strcmp(cfg.logfile, "T:amisync.log") == 0);
    ok("default rexxport",    strcmp(cfg.rexx_port, "AMISYNC") == 0);
    ok("default loglevel",    cfg.log_level == LOG_INFO);
    ok("default listenport",  cfg.listen_port == CONFIG_DEFAULT_PORT);
    ok("default discovery",   cfg.discovery == 1);
    ok("default seriallog",   cfg.serial_log == 0);
    ok("default appicon on",  cfg.appicon == 1);
    ok("default versioning off", cfg.versioning == 0);
    ok("default keepdeletes", cfg.keep_deletes == 180);
    ok("default logmax",      cfg.log_max_kb == 256);
    ok("default no peers",    cfg.num_peers == 0);
    ok("default no folders",  cfg.num_folders == 0);
}

static void test_missing_file(void)
{
    Config cfg;
    config_defaults(&cfg);
    remove(TMPCONF);
    ok("absent file returns 0", config_load(TMPCONF, &cfg) == 0);
    ok("absent file keeps defaults", cfg.listen_port == CONFIG_DEFAULT_PORT);
}

static void test_basic_keys(void)
{
    Config cfg;
    int rc = load(&cfg,
        "; comment\n"
        "# another comment\n"
        "\n"
        "[some-future-section]\n"
        "LogFile = RAM:test.log\n"          /* keys are case-insensitive */
        "  rexxport   =   MYPORT  \n"       /* whitespace is trimmed */
        "certfile = Work:cert.pem\n"
        "keyfile = Work:key.pem\n"
        "statedir = Work:state\n"
        "devicename = testbox\n"
        "keepdeletes = 30\n"
        "listenport = 12345\n"
        "not a key value line\n"            /* ignored: no '=' */
        "unknownkey = whatever\n"           /* ignored with a warning */
    );
    ok("load returns 1",       rc == 1);
    ok("logfile set",          strcmp(cfg.logfile, "RAM:test.log") == 0);
    ok("rexxport trimmed",     strcmp(cfg.rexx_port, "MYPORT") == 0);
    ok("certfile set",         strcmp(cfg.cert_path, "Work:cert.pem") == 0);
    ok("keyfile set",          strcmp(cfg.key_path, "Work:key.pem") == 0);
    ok("statedir set",         strcmp(cfg.statedir, "Work:state") == 0);
    ok("devicename set",       strcmp(cfg.device_name, "testbox") == 0);
    ok("keepdeletes set",      cfg.keep_deletes == 30);
    ok("listenport set",       cfg.listen_port == 12345);
    ok("garbage adds nothing", cfg.num_peers == 0 && cfg.num_folders == 0);

    load(&cfg, "logmax = 64\n"); ok("logmax set",        cfg.log_max_kb == 64);
    load(&cfg, "logmax = 0\n");  ok("logmax 0 = no cap", cfg.log_max_kb == 0);
}

static void test_loglevel(void)
{
    Config cfg;
    load(&cfg, "loglevel = debug\n"); ok("loglevel debug", cfg.log_level == LOG_DEBUG);
    load(&cfg, "loglevel = INFO\n");  ok("loglevel INFO",  cfg.log_level == LOG_INFO);
    load(&cfg, "loglevel = warn\n");  ok("loglevel warn",  cfg.log_level == LOG_WARN);
    load(&cfg, "loglevel = error\n"); ok("loglevel error", cfg.log_level == LOG_ERROR);
    load(&cfg, "loglevel = 2\n");     ok("loglevel numeric", cfg.log_level == 2);
}

static void test_bools(void)
{
    Config cfg;
    load(&cfg, "discovery = yes\n");   ok("bool yes",   cfg.discovery == 1);
    load(&cfg, "discovery = true\n");  ok("bool true",  cfg.discovery == 1);
    load(&cfg, "discovery = 1\n");     ok("bool 1",     cfg.discovery == 1);
    load(&cfg, "discovery = on\n");    ok("bool on",    cfg.discovery == 1);
    load(&cfg, "discovery = ON\n");    ok("bool ON",    cfg.discovery == 1);
    load(&cfg, "discovery = no\n");    ok("bool no",    cfg.discovery == 0);
    load(&cfg, "discovery = false\n"); ok("bool false", cfg.discovery == 0);
    load(&cfg, "discovery = 0\n");     ok("bool 0",     cfg.discovery == 0);
    /* regression: "off" used to parse as true (any 'o' did) */
    load(&cfg, "discovery = off\n");   ok("bool off",   cfg.discovery == 0);
    load(&cfg, "seriallog = OFF\n");   ok("bool OFF",   cfg.serial_log == 0);
    load(&cfg, "appicon = no\n");      ok("appicon off", cfg.appicon == 0);
    load(&cfg, "appicon = yes\n");     ok("appicon on",  cfg.appicon == 1);
    load(&cfg, "versioning = yes\n");  ok("versioning on", cfg.versioning == 1);
}

static void test_peers(void)
{
    Config cfg;
    char   big[4096];
    int    i, n;

    load(&cfg, "peer = " GOODID " 192.168.1.10:22001\n");
    ok("peer accepted",     cfg.num_peers == 1);
    ok("peer id stored",    strcmp(cfg.peers[0].id, GOODID) == 0);
    ok("peer host",         strcmp(cfg.peers[0].host, "192.168.1.10") == 0);
    ok("peer port",         cfg.peers[0].port == 22001);

    load(&cfg, "peer = " GOODID " 192.168.1.10\n");
    ok("peer default port", cfg.num_peers == 1 &&
                            cfg.peers[0].port == CONFIG_DEFAULT_PORT);

    load(&cfg, "peer = " GOODID " 192.168.1.10:0\n");
    ok("peer port 0 -> default", cfg.num_peers == 1 &&
                                 cfg.peers[0].port == CONFIG_DEFAULT_PORT);

    load(&cfg, "peer = " GOODID "\n");
    ok("ID-only peer",      cfg.num_peers == 1 &&
                            cfg.peers[0].host[0] == '\0' &&
                            cfg.peers[0].port == 0);

    load(&cfg, "peer = NOTAREALID-AAAAAAA 10.0.0.1\n");
    ok("bad ID rejected",   cfg.num_peers == 0);

    load(&cfg,
        "peer = P56IOI7-MZJNU2Y-IQGDREY-DM2MGTI-MGL3BXN-PQ6W5BM-TBBZ4TJ-XZWICQ3"
        " 10.0.0.1\n");     /* valid alphabet, wrong Luhn check char */
    ok("bad checksum rejected", cfg.num_peers == 0);

    /* one more line than the table holds: the extra one is dropped */
    n = 0;
    for (i = 0; i < CONFIG_MAX_PEERS + 1; i++)
        n += snprintf(big + n, sizeof(big) - n, "peer = %s 10.0.0.%d\n",
                      otherid((unsigned char)i), i + 1);
    load(&cfg, big);
    ok("peers capped", cfg.num_peers == CONFIG_MAX_PEERS);
}

static void test_folders(void)
{
    Config cfg;
    char   big[2048];
    int    i, n;

    load(&cfg, "folder = docs SYS:Docs\n");
    ok("folder accepted",   cfg.num_folders == 1);
    ok("folder id",         strcmp(cfg.folders[0].id, "docs") == 0);
    ok("folder label = id", strcmp(cfg.folders[0].label, "docs") == 0);
    ok("folder path",       strcmp(cfg.folders[0].path, "SYS:Docs") == 0);
    ok("folder default mode", cfg.folders[0].mode == FOLDER_SENDRECEIVE);

    load(&cfg, "folder = docs SYS:Docs sendonly\n");
    ok("mode sendonly",     cfg.folders[0].mode == FOLDER_SENDONLY);
    load(&cfg, "folder = docs SYS:Docs RECEIVEONLY\n");
    ok("mode receiveonly (ci)", cfg.folders[0].mode == FOLDER_RECEIVEONLY);
    load(&cfg, "folder = docs SYS:Docs sideways\n");
    ok("unknown mode -> sendreceive", cfg.folders[0].mode == FOLDER_SENDRECEIVE);

    load(&cfg, "folder = only-an-id\n");
    ok("folder missing path rejected", cfg.num_folders == 0);

    n = 0;
    for (i = 0; i < CONFIG_MAX_FOLDERS + 1; i++)
        n += snprintf(big + n, sizeof(big) - n, "folder = f%d SYS:F%d\n", i, i);
    load(&cfg, big);
    ok("folders capped", cfg.num_folders == CONFIG_MAX_FOLDERS);
}

static void test_append_peer(void)
{
    Config cfg;

    /* Appending to an existing config preserves what was there. */
    {
        char one[DEVICE_ID_BUFSZ], two[DEVICE_ID_BUFSZ], txt[256];
        strcpy(one, otherid(101));
        strcpy(two, otherid(102));
        sprintf(txt, "devicename = box\npeer = %s 10.0.0.1\n", GOODID);
        load(&cfg, txt);
        ok("append returns 1", config_append_peer(TMPCONF, one,
                                                  "192.168.1.9", 22001) == 1);
        ok("append id-only",   config_append_peer(TMPCONF, two, NULL, 0) == 1);
    }
    config_defaults(&cfg);
    ok("reload after append",  config_load(TMPCONF, &cfg) == 1);
    ok("appends kept original", strcmp(cfg.device_name, "box") == 0);
    ok("appended peers parsed", cfg.num_peers == 3);
    ok("appended host",  strcmp(cfg.peers[1].host, "192.168.1.9") == 0);
    ok("appended port",  cfg.peers[1].port == 22001);
    ok("id-only append", cfg.peers[2].host[0] == '\0' && cfg.peers[2].port == 0);

    /* Appending to a missing file creates it. */
    remove(TMPCONF);
    ok("append creates file", config_append_peer(TMPCONF, GOODID,
                                                 "10.0.0.2", 0) == 1);
    config_defaults(&cfg);
    ok("created file loads", config_load(TMPCONF, &cfg) == 1 &&
                             cfg.num_peers == 1 &&
                             strcmp(cfg.peers[0].host, "10.0.0.2") == 0);

    /* A runtime-added peer is INSERTED after the last peer line (active or
     * commented example) so it lands in the Peers section, not dangling
     * after the folders at the end of the file. */
    load(&cfg, "; peer = <device-id> [<host>[:<port>]]\n"
               "peer = " GOODID " 10.0.0.1\n"
               "\n"
               "; Folders\n"
               "folder = docs RAM:docs\n");
    ok("insert returns 1", config_append_peer(TMPCONF, otherid(103),
                                              "10.0.0.9", 22002) == 1);
    {
        char  fbuf[2048];
        FILE *f = fopen(TMPCONF, "rb");
        long  n = 0;
        char *ppos, *fpos;
        if (f) {
            n = (long)fread(fbuf, 1, sizeof(fbuf) - 1, f);
            fclose(f);
        }
        fbuf[n > 0 ? n : 0] = '\0';
        ppos = strstr(fbuf, "10.0.0.9");
        fpos = strstr(fbuf, "folder =");
        ok("inserted into the Peers section", ppos && fpos && ppos < fpos);
        ok("original tail intact", strstr(fbuf, "RAM:docs") != NULL);
    }
    config_defaults(&cfg);
    ok("insert reloads clean", config_load(TMPCONF, &cfg) == 1 &&
                               cfg.num_peers == 2 && cfg.num_folders == 1 &&
                               cfg.peers[1].port == 22002);
}

static void test_remove_peer(void)
{
    Config cfg;

    /* The peer line AND the runtime note above it go; the rest stays. */
    load(&cfg, "devicename = box\n"
               "; added at runtime:\n"
               "peer = " GOODID " 10.0.0.1\n"
               "folder = docs RAM:docs\n");
    ok("remove returns 1", config_remove_peer(TMPCONF, GOODID) == 1);
    config_defaults(&cfg);
    ok("remove reloads clean", config_load(TMPCONF, &cfg) == 1 &&
                               cfg.num_peers == 0 && cfg.num_folders == 1 &&
                               strcmp(cfg.device_name, "box") == 0);
    {
        char  fbuf[2048];
        FILE *f = fopen(TMPCONF, "rb");
        long  n = 0;
        if (f) {
            n = (long)fread(fbuf, 1, sizeof(fbuf) - 1, f);
            fclose(f);
        }
        fbuf[n > 0 ? n : 0] = '\0';
        ok("remove took the note too", strstr(fbuf, "added at runtime") == NULL);
        ok("remove left the rest", strstr(fbuf, "RAM:docs") != NULL &&
                                   strstr(fbuf, "devicename") != NULL);
    }

    /* Nothing to remove: reports 0, file untouched. */
    ok("remove of absent id is 0", config_remove_peer(TMPCONF, GOODID) == 0);
    config_defaults(&cfg);
    ok("file survives no-op remove", config_load(TMPCONF, &cfg) == 1 &&
                                     cfg.num_folders == 1);

    /* A commented-out example line with the same ID is NOT removed. */
    load(&cfg, "; peer = " GOODID " 10.0.0.1\n"
               "peer = " GOODID " 10.0.0.2\n");
    ok("remove active only", config_remove_peer(TMPCONF, GOODID) == 1);
    {
        char  fbuf[1024];
        FILE *f = fopen(TMPCONF, "rb");
        long  n = 0;
        if (f) {
            n = (long)fread(fbuf, 1, sizeof(fbuf) - 1, f);
            fclose(f);
        }
        fbuf[n > 0 ? n : 0] = '\0';
        ok("comment example kept", strstr(fbuf, "; peer = ") != NULL);
        ok("active line gone", strstr(fbuf, "10.0.0.2") == NULL);
    }
}

static void test_folder_lines(void)
{
    Config cfg;

    /* Insert lands after the last folder-ish line (the commented example),
     * not at the end of the file. */
    load(&cfg, "; folder = <id> <path> [mode]\n"
               "folder = docs RAM:docs\n"
               "\n"
               "; trailing settings\n"
               "loglevel = info\n");
    ok("addfolder returns 1",
       config_append_folder(TMPCONF, "pics", "RAM:pics",
                            FOLDER_SENDONLY, NULL) == 1);
    {
        char  fbuf[2048];
        FILE *f = fopen(TMPCONF, "rb");
        long  n = 0;
        char *fpos, *tpos;
        if (f) {
            n = (long)fread(fbuf, 1, sizeof(fbuf) - 1, f);
            fclose(f);
        }
        fbuf[n > 0 ? n : 0] = '\0';
        fpos = strstr(fbuf, "RAM:pics");
        tpos = strstr(fbuf, "loglevel");
        ok("folder inserted into section", fpos && tpos && fpos < tpos);
    }
    config_defaults(&cfg);
    ok("addfolder reloads", config_load(TMPCONF, &cfg) == 1 &&
                            cfg.num_folders == 2 &&
                            cfg.folders[1].mode == FOLDER_SENDONLY);

    /* Removal takes the line and its note; the other folder survives. */
    ok("removefolder returns 1", config_remove_folder(TMPCONF, "pics") == 1);
    config_defaults(&cfg);
    ok("removefolder reloads", config_load(TMPCONF, &cfg) == 1 &&
                               cfg.num_folders == 1 &&
                               strcmp(cfg.folders[0].id, "docs") == 0);
    ok("removefolder unknown is 0", config_remove_folder(TMPCONF, "pics") == 0);
    /* Exact-id match: "doc" must not remove "docs". */
    ok("removefolder prefix miss", config_remove_folder(TMPCONF, "doc") == 0);

    /* Labels: persisted as the optional trailing token, parsed back; a
       spacey label is not persisted (falls back to the id on reload). */
    load(&cfg, "loglevel = info\n");
    ok("addfolder w/ label",
       config_append_folder(TMPCONF, "abcde-fghij", "RAM:t",
                            FOLDER_SENDRECEIVE, "test4") == 1);
    config_defaults(&cfg);
    ok("label round-trips", config_load(TMPCONF, &cfg) == 1 &&
                            cfg.num_folders == 1 &&
                            strcmp(cfg.folders[0].label, "test4") == 0 &&
                            strcmp(cfg.folders[0].id, "abcde-fghij") == 0);
    /* Whitespace in paths and labels round-trips via double quotes. */
    ok("spacey path+label append",
       config_append_folder(TMPCONF, "x1", "Ram Disk:My Stuff",
                            FOLDER_SENDRECEIVE, "My Photos") == 1);
    config_defaults(&cfg);
    ok("spacey path survives reload",
       config_load(TMPCONF, &cfg) == 1 && cfg.num_folders == 2 &&
       strcmp(cfg.folders[1].path, "Ram Disk:My Stuff") == 0);
    ok("spacey label survives reload",
       strcmp(cfg.folders[1].label, "My Photos") == 0);

    /* Hand-written quoted lines parse too (and unquoted stay as ever). */
    load(&cfg, "folder = docs \"Work:My Docs\" sendonly\n");
    ok("quoted path parses", cfg.num_folders == 1 &&
       strcmp(cfg.folders[0].path, "Work:My Docs") == 0 &&
       cfg.folders[0].mode == FOLDER_SENDONLY);
}

/* The writers are where untrusted text becomes config SYNTAX: a discovered
 * device's address comes from an unauthenticated LAN broadcast, and an offered
 * folder's id and label come from a peer's ClusterConfig. The config is
 * line-oriented, so a newline in one of those does not corrupt a value - it
 * writes an extra SETTING that the next load obeys (a folder rooted at SYS:,
 * say, shared straight back to whoever sent it). Nothing may be written. */
static void test_append_refuses_injection(void)
{
    Config cfg;
    long   before, after;

    load(&cfg, "; peers\npeer = " GOODID "\n");
    before = filesize(TMPCONF);

    ok("peer: newline host refused",
       config_append_peer(TMPCONF, GOODID,
                          "1.2.3.4\nfolder = sys SYS: sendreceive x",
                          22000) == 0);
    ok("peer: newline id refused",
       config_append_peer(TMPCONF, "AAA\nlistenport = 1", "1.2.3.4", 22000) == 0);
    ok("peer: tab host refused",
       config_append_peer(TMPCONF, GOODID, "1.2.3.4\tx", 22000) == 0);

    ok("folder: newline id refused",
       config_append_folder(TMPCONF, "docs\nfolder = sys SYS: sendreceive",
                            "RAM:d", FOLDER_SENDRECEIVE, NULL) == 0);
    ok("folder: newline path refused",
       config_append_folder(TMPCONF, "docs", "RAM:d\nlistenport = 1",
                            FOLDER_SENDRECEIVE, NULL) == 0);
    /* The label is the sneaky one: it is quoted only when it holds whitespace,
     * so a newline would never have been wrapped. */
    ok("folder: newline label refused",
       config_append_folder(TMPCONF, "docs", "RAM:d", FOLDER_SENDRECEIVE,
                            "Docs\nfolder = sys SYS: sendreceive") == 0);
    ok("folder: quote label refused",
       config_append_folder(TMPCONF, "docs", "RAM:d", FOLDER_SENDRECEIVE,
                            "say \"hi\"") == 0);

    after = filesize(TMPCONF);
    ok("refused writes leave the file alone", before > 0 && after == before);

    /* Nothing was smuggled in: the config still holds exactly its one peer. */
    config_defaults(&cfg);
    ok("no injected settings", config_load(TMPCONF, &cfg) == 1 &&
       cfg.num_folders == 0 && cfg.num_peers == 1);

    /* ...and the legitimate neighbours of those values still write. */
    ok("clean append still works",
       config_append_folder(TMPCONF, "docs", "RAM:d", FOLDER_SENDRECEIVE,
                            "My Docs") == 1);
}

/* One entry per device and per folder id. Two lines for the same peer is an
 * easy thing to write - the device is reachable at two addresses, or the same
 * ID gets pasted twice in different case - and it used to produce two live
 * slots, which the targeted verbs could not manage: PAUSE or Remove acted on
 * the first and left the second dialling and syncing. */
static void test_duplicates_refused(void)
{
    Config cfg;
    char   txt[512];

    /* Same device, two addresses. */
    sprintf(txt, "peer = %s 10.0.0.1\npeer = %s 10.0.0.2\n", GOODID, GOODID);
    load(&cfg, txt);
    ok("duplicate peer refused", cfg.num_peers == 1);
    ok("duplicate keeps the first", strcmp(cfg.peers[0].host, "10.0.0.1") == 0);

    /* Same device spelled differently: device_id_equal normalises, so the
     * dedup must catch this too - it is the form a user is most likely to
     * produce by accident. */
    sprintf(txt, "peer = %s 10.0.0.1\npeer = p56ioi7-mzjnu2y-iqgdrey-dm2mgti-"
                 "mgl3bxn-pq6w5bm-tbbz4tj-xzwicq2 10.0.0.2\n", GOODID);
    load(&cfg, txt);
    ok("duplicate peer, other case, refused", cfg.num_peers == 1);

    /* Distinct devices still both land. */
    sprintf(txt, "peer = %s 10.0.0.1\npeer = %s 10.0.0.2\n",
            GOODID, otherid(7));
    load(&cfg, txt);
    ok("distinct peers both kept", cfg.num_peers == 2);

    load(&cfg, "folder = docs RAM:one\nfolder = docs RAM:two\n");
    ok("duplicate folder refused", cfg.num_folders == 1);
    ok("duplicate folder keeps first",
       strcmp(cfg.folders[0].path, "RAM:one") == 0);

    load(&cfg, "folder = docs RAM:one\nfolder = pics RAM:two\n");
    ok("distinct folders both kept", cfg.num_folders == 2);
}

int main(void)
{
    test_defaults();
    test_missing_file();
    test_basic_keys();
    test_loglevel();
    test_bools();
    test_peers();
    test_folders();
    test_append_peer();
    test_remove_peer();
    test_folder_lines();
    test_append_refuses_injection();
    test_duplicates_refused();

    remove(TMPCONF);
    if (failures) {
        printf("\n%d config check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall config checks passed\n");
    return 0;
}
