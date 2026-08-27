/* main.c - entry point for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#include <stdio.h>
#include <string.h>

#include <dos/dos.h>
#include <dos/dostags.h>
#include <dos/dosextens.h>
#include <exec/memory.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include "config.h"
#include "log.h"
#include "daemon.h"
#include "version.h"

/* AmigaOS $VER: cookie, so `Version amisync` reports the version. Marked used
 * so the linker keeps it even though nothing references it at runtime. */
static const char version_cookie[] __attribute__((used)) =
    AMISYNC_VERTAG("amisync");

/* Argument the relaunched background copy is invoked with, so it knows not
 * to detach a second time. */
#define ARG_BACKGROUND  "BACKGROUND"
/* Force staying in the foreground (useful for debug builds / gdb). */
#define ARG_NODETACH    "NODETACH"

/* Stack for the detached background copy. This process runs the whole daemon -
 * config parsing, logging (stdio), the daemon loop and ARexx - so it needs
 * real headroom, matching the worker stacks. Do not shrink casually: AmigaOS
 * stacks have no guard, so an overflow scribbles into adjacent memory and
 * surfaces later as unrelated-looking, nondeterministic crashes. */
#define DAEMON_STACK    131072

/* Bytes of stack this process was actually given. A Workbench launch gets the
 * icon's do_StackSize and a Shell run gets that Shell's `stack` setting -
 * neither is ours to choose, and neither defaults anywhere near DAEMON_STACK.
 * AmigaOS stacks have no guard page, so the only way to find out we are short
 * is to check before we spend it. */
static ULONG stack_size(void)
{
    struct Task *me = FindTask(NULL);
    return (ULONG)((char *)me->tc_SPUpper - (char *)me->tc_SPLower);
}

/* Detach retry budget; see relaunch_detached for why retrying works. */
#define DETACH_TRIES    4
#define DETACH_DELAY    25          /* ticks (~0.5 s at 50 Hz) between attempts */

/* Case-insensitive, as AmigaOS CLI keywords conventionally are: someone
 * typing "amisync nodetach" means it. Safe with argc == 0 (a Workbench
 * start): the loop body never runs and argv is never touched. */
static int has_arg(int argc, char **argv, const char *want)
{
    int i;
    for (i = 1; i < argc; i++)
        if (strcasecmp(argv[i], want) == 0)
            return 1;
    return 0;
}

/* Auto-fail DOS requesters for this process instead of blocking on them.
 * amisync runs as a detached background CLI with no window, so a requester
 * like "Please insert volume Data:" (e.g. the log/state volume briefly not
 * ready at boot) can never be displayed or answered - the daemon would hang
 * forever, invisibly. pr_WindowPtr = -1 makes DOS fail such requests
 * immediately; the affected call (fopen/Open/Lock) then returns an error the
 * code already tolerates (logging degrades to none, a scan retries next pass)
 * rather than wedging the whole daemon. */
static void suppress_requesters(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    if (me->pr_Task.tc_Node.ln_Type == NT_PROCESS)
        me->pr_WindowPtr = (APTR)-1;
}

/* Relaunch ourselves detached from the controlling CLI. Returns 1 if the
 * background copy was started (caller should exit), 0 on failure (caller
 * should run in the foreground instead).
 *
 * The detach loads a FRESH, PRIVATE copy of our own binary and hands the new
 * seglist to CreateNewProc, which owns it (NP_FreeSeglist) and frees it only
 * when the daemon exits. Do not "simplify" this into re-executing ourselves
 * through System(SYS_Asynch): that races our own segment lifetime - the
 * original process's code segments can be freed and reused WHILE the CPU is
 * still executing them, an intermittent boot-time crash. With a private seglist
 * for the child and a plain synchronous return for the parent, the parent's
 * segment is unloaded by its shell only after it has actually returned, and
 * the child's copy lives exactly as long as the daemon does. */
static int relaunch_detached(void)
{
    char            prog[200];   /* program path; GetProgramName truncates */
    BPTR            seg, nilin, nilout;
    struct Process *proc = NULL; /* the loop below always runs, but say so */
    int             try;

    if (!GetProgramName(prog, sizeof(prog)))
        return 0;

    seg = LoadSeg((STRPTR)prog);
    if (seg == (BPTR)0)
        return 0;

    nilin  = Open("NIL:", MODE_OLDFILE);
    nilout = Open("NIL:", MODE_NEWFILE);
    if (nilin == (BPTR)0 || nilout == (BPTR)0) {
        if (nilin  != (BPTR)0) Close(nilin);
        if (nilout != (BPTR)0) Close(nilout);
        UnLoadSeg(seg);
        return 0;
    }

    /* NP_Cli gives the child a real CLI context so the BACKGROUND flag
     * arrives through normal argv parsing; dos copies both the name and the
     * argument string, so nothing here references the parent's segment. The
     * child closes the NIL: handles itself at exit (NP_CloseInput/Output).
     * CreateNewProc allocates the child's 128 KB stack as one block, which can
     * fail on a fragmented heap; retry a few times before giving up (on
     * failure it takes ownership of nothing, so the same seg/handles are
     * reused). */
    for (try = 0; try < DETACH_TRIES; try++) {
        proc = CreateNewProcTags(NP_Seglist,     (ULONG)seg,
                                 NP_FreeSeglist, TRUE,
                                 NP_Cli,         TRUE,
                                 NP_Name,        (ULONG)"amisync",
                                 NP_Arguments,   (ULONG)ARG_BACKGROUND "\n",
                                 NP_StackSize,   DAEMON_STACK,
                                 NP_Input,       nilin,
                                 NP_Output,      nilout,
                                 NP_CloseInput,  TRUE,
                                 NP_CloseOutput, TRUE,
                                 TAG_DONE);
        if (proc)
            break;
        if (try < DETACH_TRIES - 1)
            Delay(DETACH_DELAY);
    }
    if (!proc) {
        Close(nilin);
        Close(nilout);
        UnLoadSeg(seg);
        return 0;
    }
    return 1;
}

/* The daemon proper: load config, then run. Split out of main() and its Config
 * HEAP-allocated on purpose. sizeof(Config) is ~4.8 KB, but the pre-detach copy
 * of amisync runs on the ~4 KB stack of the `Run` background CLI (User-Startup:
 * "Run >NIL: C:amisync") - a Config on that copy's stack overflows it and
 * corrupts adjacent memory. Keeping Config off the stack AND out of main()
 * (see below) means the small-stack copy never touches it; only the detached
 * child (DAEMON_STACK) and the foreground fallback reach here. */
static int run_daemon(int is_background)
{
    Config *cfg;
    int     rc;

#ifdef BOOTTRACE
    log_printf(LOG_DEBUG, "bt: run_daemon: allocating config...");
#endif
    cfg = AllocVec(sizeof(Config), MEMF_ANY | MEMF_CLEAR);
    if (!cfg) {
        if (!is_background)
            printf("amisync: out of memory for configuration\n");
        return RETURN_FAIL;
    }

    config_defaults(cfg);
    config_load(CONFIG_PATH_DEFAULT, cfg);
#ifdef BOOTTRACE
    log_printf(LOG_DEBUG, "bt: config loaded (logfile=%s serial=%d), log_init...",
               cfg->logfile, cfg->serial_log);
#endif

    log_set_max(cfg->log_max_kb);
    if (!log_init(cfg->logfile, (LogLevel)cfg->log_level)) {
        /* No log file: still run, but warn on the console if we have one. */
        if (!is_background)
            printf("amisync: warning: cannot open log file '%s'\n", cfg->logfile);
    }

    /* Tee to the serial debug port when asked (live logs under WinUAE). */
    log_set_serial(cfg->serial_log);
#ifdef BOOTTRACE
    log_set_serial(1);             /* trace build: serial stays on regardless */
#endif

    /* Syncthing-style banner: name, version, build, then how we run. */
    log_printf(LOG_INFO, AMISYNC_NAME " " AMISYNC_VERSION
               " (" AMISYNC_CPU " build, " AMISYNC_DATE ") starting (%s)",
               is_background ? "background" : "foreground");

    rc = daemon_run(cfg);

    log_printf(LOG_INFO, "amisync exited (rc=%d)", rc);
    log_close();

    FreeVec(cfg);
    return rc == 0 ? RETURN_OK : RETURN_FAIL;
}

int main(int argc, char **argv)
{
    int from_workbench = (argc == 0);
    int is_background  = has_arg(argc, argv, ARG_BACKGROUND);
    int no_detach      = has_arg(argc, argv, ARG_NODETACH);

#ifdef BOOTTRACE
    log_trace_init();
    log_printf(LOG_DEBUG, "bt: main entered (argc=%d bg=%d wb=%d)",
               argc, is_background, from_workbench);
#endif

    suppress_requesters();   /* never block on an invisible DOS requester */

    /* Normal CLI start: relaunch detached (which sizes a proper 128 KB stack)
     * and exit this copy. Done BEFORE run_daemon so main()'s frame stays tiny
     * on the 4 KB `Run` CLI stack - see run_daemon. */
    if (!is_background && !no_detach && !from_workbench) {
        /* Single-instance pre-check: if our ARexx port already exists, another
         * amisync is running - report it and DON'T spawn a doomed child (which
         * would print "started in background" and then exit on the same port
         * collision). The detached child still does the authoritative,
         * Forbid-guarded check (arexx_open), so this is just the clean UX. */
        char port[CONFIG_PORTNAME_MAX];
        config_rexx_port(CONFIG_PATH_DEFAULT, port, sizeof(port));
        if (FindPort((STRPTR)port)) {
            printf("amisync: already running (ARexx port '%s')\n", port);
            return RETURN_OK;
        }
#ifdef BOOTTRACE
        log_printf(LOG_DEBUG, "bt: relaunching detached...");
#endif
        if (relaunch_detached()) {
#ifdef BOOTTRACE
            log_printf(LOG_DEBUG, "bt: relaunch ok, original exiting");
#endif
            printf("amisync: started in background\n");
            return RETURN_OK;
        }
        /* Detach failed even after retries (heap too fragmented for a 128 KB
         * stack). Do NOT fall through to run the daemon here: this copy is on
         * the tiny CLI stack, and daemon_run would overflow it and corrupt
         * memory. Fail cleanly and let the user reboot/retry - never crash. */
#ifdef BOOTTRACE
        log_printf(LOG_DEBUG, "bt: relaunch FAILED after retries, exiting clean");
#endif
        printf("amisync: could not create the background process (low memory / "
               "fragmentation) - reboot and retry\n");
        return RETURN_FAIL;
    }

    /* Everything from here runs the daemon IN THIS PROCESS. The detached child
     * arrives with its own DAEMON_STACK, but a Workbench launch runs on the
     * icon's do_StackSize and a NODETACH run on the Shell's - stacks we did
     * not choose and cannot assume. This used to be left to "the caller is
     * responsible for sizing", which is a responsibility no caller knows it
     * has: the icon this project ships declared 8192 while daemon_run's own
     * frame is over 2 KB and answering one STATUS adds several more. The
     * failure mode is not a clean crash but a silent overflow into adjacent
     * memory - the AN_MemCorrupt this daemon has already been debugged out of
     * once. Check instead of trusting. */
    if (stack_size() < DAEMON_STACK) {
        if (from_workbench) {
            /* No Shell to hold and no console to explain ourselves on, so the
             * fix is transparent: relaunch with a stack we DO size. (The
             * shipped icon declares enough on its own; this catches a
             * hand-made or copied one.) */
            if (relaunch_detached())
                return RETURN_OK;
            return RETURN_FAIL;
        }
        /* NODETACH means "stay in this process", so detaching behind the
         * user's back would be the wrong repair. Say exactly what to do. */
        printf("amisync: this Shell gives %lu bytes of stack; running "
               "in the foreground needs %lu.\n"
               "         Use \"stack %lu\" first, or drop NODETACH and let "
               "amisync detach itself.\n",
               (unsigned long)stack_size(), (unsigned long)DAEMON_STACK,
               (unsigned long)DAEMON_STACK);
        return RETURN_FAIL;
    }

    return run_daemon(is_background);
}
