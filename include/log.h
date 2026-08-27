/* log.h - logging subsystem for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_LOG_H
#define AMISYNC_LOG_H

/* Severity levels, ascending. The active threshold is set in log_init(). */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

/* Open the log file for append. 'path' is an AmigaOS path such as
 * "T:amisync.log". 'threshold' suppresses messages below that level.
 * Returns 1 on success, 0 on failure (logging then degrades to no-op). */
int  log_init(const char *path, LogLevel threshold);

/* Flush and close the log file. Safe to call even if log_init() failed. */
void log_close(void);

/* Change / read the active severity threshold at runtime (for ARexx LOGLEVEL). */
void     log_set_level(LogLevel threshold);
LogLevel log_get_level(void);

/* Enable/disable teeing each log line to the serial debug port (exec
 * RawPutChar - the kprintf channel WinUAE can capture on the host). Off by
 * default; main() turns it on when the SerialLog config option is set. */
void log_set_serial(int on);

/* Cap the log file's size: when a write would grow it past 'kb' KB it is
 * truncated in place and restarts with a marker line. 0 = never truncate.
 * Default 256 KB (the log often lives in RAM: via T:). */
void log_set_max(long kb);

/* Diagnostic bring-up: enable serial-only logging before config/log_init, for
 * early-start breadcrumbs (see the boot trace in main.c). */
void log_trace_init(void);

/* Write a formatted line at the given level. A timestamp, level tag and
 * trailing newline are added automatically. */
void log_printf(LogLevel level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif /* AMISYNC_LOG_H */
