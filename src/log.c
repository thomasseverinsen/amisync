/* log.c - logging subsystem for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <dos/dos.h>
#include <exec/semaphores.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include "log.h"

/* The log is written through dos.library, NOT stdio. Two reasons: MODE_READWRITE
 * takes a SHARED lock, so the log stays readable (Type, MultiView, copying it
 * to the host) WHILE the daemon runs - an exclusive handle, which is what
 * libnix's fopen("a") ends up with, makes the running daemon's own log
 * unreadable ("object is in use"), exactly when you want to read it. And it
 * removes libnix stdio from the multi-task path entirely. */
static BPTR     g_logfh     = 0;
static LogLevel g_threshold = LOG_INFO;
static int      g_serial    = 0;

/* Size cap. The daemon runs indefinitely and the default log lives in T:
 * (usually RAM:), so an unbounded log is a slow leak. When the file would
 * grow past the cap it is truncated in place and restarts with a marker
 * line. 0 = never truncate. */
static long g_max_bytes = 256 * 1024;
static long g_written   = 0;            /* current log file size, bytes */
/* The log path, kept for the size-cap reopen fallback. Sized for the config's
 * logfile field (CONFIG_LOGFILE_MAX, 128), which is the only source of it;
 * log_init gives the fallback up rather than store a truncated path, since
 * reopening THAT would truncate a different file. */
static char g_path[128];

/* All of the daemon's tasks share this one file handle and the size counter
 * (subprocesses run in the same data segment), so every write is bracketed by
 * this semaphore - without it concurrent Write()s interleave mid-line and the
 * size bookkeeping races. It is initialised in log_init(), which main() always
 * calls before the daemon spawns any subprocess. */
static struct SignalSemaphore g_loglock;

/* exec's serial debug primitive, LVO -516 (offset 0x204). sfdc omits it from
 * <inline/exec.h>, so define it with the same LP macro the other exec inlines
 * use. It needs no library open and WinUAE captures it on the host. */
#ifndef RawPutChar
#define RawPutChar(___c) \
      LP1NR(0x204, RawPutChar, UBYTE, ___c, d0, \
      , EXEC_BASE_NAME)
#endif

static const char *level_tag(LogLevel level)
{
    switch (level) {
    case LOG_DEBUG: return "DBG";
    case LOG_INFO:  return "INF";
    case LOG_WARN:  return "WRN";
    case LOG_ERROR: return "ERR";
    default:        return "???";
    }
}

void log_trace_init(void)
{
    /* Diagnostic bring-up: serial-only logging before any config is read, so
     * early-start breadcrumbs (main.c boot trace) can be captured even when
     * the daemon never reaches its normal log setup. */
    InitSemaphore(&g_loglock);
    g_serial    = 1;
    g_threshold = LOG_DEBUG;
}

int log_init(const char *path, LogLevel threshold)
{
    InitSemaphore(&g_loglock);   /* before the open: init even if it fails */
    g_threshold = threshold;
    if (strlen(path) < sizeof g_path)
        strcpy(g_path, path);
    else
        g_path[0] = '\0';           /* no fallback rather than the wrong file */

    /* MODE_READWRITE: shared lock, and creates the file if it is not there. */
    g_logfh = Open((STRPTR)path, MODE_READWRITE);
    if (g_logfh) {               /* appending: count what is already there */
        Seek(g_logfh, 0, OFFSET_END);
        g_written = Seek(g_logfh, 0, OFFSET_CURRENT);   /* returns the pos */
        if (g_written < 0)
            g_written = 0;
    }
    return g_logfh != 0;
}

void log_set_max(long kb)
{
    /* Clamp before the multiply: log_max_kb is an unbounded atoi() of a config
     * value, and kb * 1024 overflows a 32-bit long past 2 MB-of-KB. "logmax
     * 4194305" wrapped to 1024 - a log truncating itself every few lines -
     * and 4194304 wrapped to 0, silently disabling the cap the option had been
     * set to tighten. Absurd values, but they should not invert the meaning. */
    const long max_kb = 1024L * 1024L;          /* 1 GB, far past any real log */

    if (kb <= 0)
        g_max_bytes = 0;                        /* uncapped, as documented */
    else
        g_max_bytes = (kb > max_kb ? max_kb : kb) * 1024;
}

void log_close(void)
{
    if (g_logfh) {
        Close(g_logfh);
        g_logfh = 0;
    }
}

void log_set_level(LogLevel threshold)
{
    g_threshold = threshold;
}

LogLevel log_get_level(void)
{
    return g_threshold;
}

void log_set_serial(int on)
{
    g_serial = on;
}

/* Emit 's' out the RawPutChar debug channel a byte at a time, then a CRLF. */
static void serial_puts(const char *s)
{
    while (*s)
        RawPutChar((UBYTE)*s++);
    RawPutChar('\r');
    RawPutChar('\n');
}

/* ds_Days (days since 1978-01-01) -> civil y/m/d, via Hinnant's
 * days-from-civil inverse (shifted by 2922 days, 1970..1978, then by 719468
 * to the algorithm's 0000-03-01 epoch). Exact for any date the Amiga clock
 * can hold. */
static void ds_date(long days, long *y, long *m, long *d)
{
    long          z   = days + 2922 + 719468;
    long          era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned long doe = (unsigned long)(z - era * 146097);
    unsigned long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned long mp  = (5 * doy + 2) / 153;

    *d = (long)(doy - (153 * mp + 2) / 5 + 1);
    *m = (long)(mp < 10 ? mp + 3 : mp - 9);
    *y = (long)yoe + era * 400 + (*m <= 2);
}

void log_printf(LogLevel level, const char *fmt, ...)
{
    struct DateStamp ds;
    va_list ap;
    char    line[300];
    long    y, mo, d, len;
    int     n;

    if (level < g_threshold)
        return;
    if (g_logfh == 0 && !g_serial)
        return;

    /* Format the whole line once into a buffer so it can be teed to the log
     * file and the serial port without formatting twice.
     * ds_Minute = minutes past midnight, ds_Tick = ticks past the minute
     * (TICKS_PER_SECOND == 50). The full-date stamp matches Syncthing's log
     * columns, so this log lines up with a peer's when read side by side. */
    DateStamp(&ds);
    ds_date(ds.ds_Days, &y, &mo, &d);
    n = snprintf(line, sizeof line, "%04ld-%02ld-%02ld %02ld:%02ld:%02ld %s ",
                 y, mo, d,
                 ds.ds_Minute / 60,
                 ds.ds_Minute % 60,
                 ds.ds_Tick / TICKS_PER_SECOND,
                 level_tag(level));
    if (n < 0 || n >= (int)sizeof line)     /* prefix never truncates, but be safe */
        n = (int)sizeof line - 1;

    va_start(ap, fmt);
    vsnprintf(line + n, sizeof line - n, fmt, ap);
    va_end(ap);

    ObtainSemaphore(&g_loglock);

    if (g_serial)
        serial_puts(line);   /* serialised too, and before the newline goes in:
                              * serial_puts ends the line with its own CRLF */

    /* Newline in the buffer, so a line costs ONE Write() - each is a packet
     * round-trip to the filesystem handler. Only a message that filled the
     * buffer has no room, and there the last character is given up instead. */
    len = (long)strlen(line);
    if (len + 1 >= (long)sizeof line)
        len--;
    line[len++] = '\n';
    line[len]   = '\0';

    if (g_logfh) {
        static const char MARK[] = "[log truncated: size cap reached, see 'logmax']\n";
        int emptied = 0;

        /* Truncate BEFORE the write that would cross the cap, so the
         * triggering line survives as the first line of the fresh log.
         * SetFileSize keeps our shared handle (and so the log stays readable);
         * if the handler does not support it, fall back to a reopen.
         *
         * SetFileSize is not taken on its word - the file is MEASURED
         * afterwards. Observed on the A4000's FFS: the call reported no
         * failure and left the file exactly as long as it had been, so the
         * new log was written over the front of the old one and everything
         * past that point still read back. A log whose tail is last week's
         * events, in order, after today's, is worse than one that is merely
         * too long: it reads as though the daemon replayed them. */
        if (g_max_bytes > 0 && g_written + len > g_max_bytes) {
            if (SetFileSize(g_logfh, 0, OFFSET_BEGINNING) >= 0 &&
                Seek(g_logfh, 0, OFFSET_END) >= 0 &&
                Seek(g_logfh, 0, OFFSET_CURRENT) == 0) {   /* really empty? */
                emptied = 1;
            } else if (g_path[0]) {
                Close(g_logfh);
                g_logfh = Open((STRPTR)g_path, MODE_NEWFILE);   /* truncates */
                if (g_logfh) {
                    Close(g_logfh);
                    g_logfh = Open((STRPTR)g_path, MODE_READWRITE);
                }
                emptied = 1;
            }
            /* Only reset the counter if the file really was emptied: with
             * neither route available the cap simply cannot be enforced, and
             * a zeroed counter would just make g_written stop tracking. */
            if (emptied) {
                g_written = 0;
                if (g_logfh) {
                    LONG w = Write(g_logfh, (APTR)MARK, (LONG)sizeof(MARK) - 1);
                    if (w > 0)              /* Write returns -1 on error */
                        g_written += w;
                }
            }
        }
        if (g_logfh) {
            LONG w = Write(g_logfh, (APTR)line, (LONG)len);
            if (w > 0)
                g_written += w;
        }
    }
    ReleaseSemaphore(&g_loglock);
}
