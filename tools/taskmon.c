/* taskmon.c - log, from priority 127, who else was running every second
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A machine-wide freeze has two shapes. Either a task above everyone else's
 * priority is spinning, or nothing runs at all (Forbid/Disable held, or the
 * CPU itself stuck). At priority 127 this tool still gets scheduled in the
 * first case and logs the task it preempted; in the second, the gaps between
 * its lines say so.
 *
 * Each line: time, seconds since the previous line, dispatches and idle ticks
 * in that interval, the head of the ready list (the task that would be running
 * if we were not), how many tasks are ready, and the state of the WiFiPi
 * driver tasks (W wait, R ready, - absent).
 *
 * Usage:  Run >NIL: taskmon [LOG=<file>]     Ctrl-C the process to stop.
 * The file is opened and closed per line so it survives a hard reboot when
 * it lives on a disk rather than RAM:.
 */

#include <string.h>
#include <stdio.h>

#include <exec/execbase.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>

static const char ver[] = "$VER: taskmon 1.0 (11.09.2026)";

#define QUIET_EVERY 10   /* heartbeat line when nothing is going on */

static const char *watched[] = { "WiFiPi Unit", "WiFiPi Packet Receiver" };
#define NWATCH 2

static char state_char(struct Task *t)
{
    if (!t) return '-';
    switch (t->tc_State) {
    case TS_RUN:   return 'X';   /* cannot be, we are running */
    case TS_READY: return 'R';
    case TS_WAIT:  return 'W';
    default:       return '?';
    }
}

static long stamp_secs(const struct DateStamp *d)
{
    return d->ds_Days * 86400L + d->ds_Minute * 60L + d->ds_Tick / TICKS_PER_SECOND;
}

static int append_line(const char *path, const char *line)
{
    BPTR fh = Open((STRPTR)path, MODE_READWRITE);
    long n  = (long)strlen(line);
    int  ok;

    if (!fh)
        return 0;
    Seek(fh, 0, OFFSET_END);
    ok = Write(fh, (APTR)line, n) == n;
    Close(fh);
    return ok;
}

int main(void)
{
    struct RDArgs   *rd;
    LONG             args[1] = { 0 };
    const char      *path    = "RAM:taskmon.log";
    struct Task     *me      = FindTask(NULL);
    struct DateStamp last;
    ULONG            disp0, idle0;
    int              quiet   = 0;
    char             line[160];

    rd = ReadArgs((STRPTR)"LOG/K", args, NULL);
    if (rd && args[0])
        path = (const char *)args[0];

    SetTaskPri(me, 127);
    DateStamp(&last);
    disp0 = SysBase->DispCount;
    idle0 = SysBase->IdleCount;

    sprintf(line, "taskmon: started at priority 127, log %s\n", path);
    append_line(path, line);

    for (;;) {
        struct DateStamp now;
        struct Task     *head;
        struct Node     *n;
        char             hname[32] = "(none)";
        LONG             hpri = 0;
        int              nready = 0, i;
        char             st[NWATCH];
        long             gap_ticks;
        ULONG            disp, idle;

        Delay(TICKS_PER_SECOND);
        if (SetSignal(0L, SIGBREAKF_CTRL_C) & SIGBREAKF_CTRL_C)
            break;

        DateStamp(&now);
        gap_ticks = (stamp_secs(&now) - stamp_secs(&last)) * TICKS_PER_SECOND +
                    (now.ds_Tick % TICKS_PER_SECOND) -
                    (last.ds_Tick % TICKS_PER_SECOND);
        last = now;

        Forbid();
        disp = SysBase->DispCount;
        idle = SysBase->IdleCount;
        for (n = SysBase->TaskReady.lh_Head; n->ln_Succ; n = n->ln_Succ)
            nready++;
        head = (struct Task *)SysBase->TaskReady.lh_Head;
        if (head->tc_Node.ln_Succ) {
            const char *nm = head->tc_Node.ln_Name;
            strncpy(hname, nm ? nm : "(unnamed)", sizeof(hname) - 1);
            hname[sizeof(hname) - 1] = '\0';
            hpri = head->tc_Node.ln_Pri;
        }
        for (i = 0; i < NWATCH; i++)
            st[i] = state_char(FindTask((STRPTR)watched[i]));
        Permit();

        /* Quiet: nobody ready, no gap, driver tasks waiting. */
        if (nready == 0 && gap_ticks <= TICKS_PER_SECOND + 10 &&
            st[0] != 'R' && st[1] != 'R') {
            if (++quiet < QUIET_EVERY) {
                disp0 = disp; idle0 = idle;
                continue;
            }
        }
        quiet = 0;

        sprintf(line, "%02ld:%02ld:%02ld gap=%ld.%02ld disp=%lu idle=%lu "
                "ready=%d head=%s(%ld) unit=%c pkt=%c\n",
                (long)(now.ds_Minute / 60), (long)(now.ds_Minute % 60),
                (long)(now.ds_Tick / TICKS_PER_SECOND),
                gap_ticks / TICKS_PER_SECOND,
                (gap_ticks % TICKS_PER_SECOND) * 100 / TICKS_PER_SECOND,
                (unsigned long)(disp - disp0), (unsigned long)(idle - idle0),
                nready, hname, (long)hpri, st[0], st[1]);
        disp0 = disp; idle0 = idle;
        append_line(path, line);
    }

    append_line(path, "taskmon: stopped\n");
    if (rd)
        FreeArgs(rd);
    (void)ver;
    return 0;
}
