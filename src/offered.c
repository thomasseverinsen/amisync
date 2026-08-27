/* offered.c - folders peers offer us that we have not configured
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See offered.h. The same shape as wreg's registry: one static table in the
 * shared address space, short Forbid()-bracketed memory ops.
 */

#include <string.h>

#include <proto/exec.h>

#include "offered.h"
#include "pathsafe.h"

static OfferedFolder g_offers[OFFERED_MAX];   /* id[0]=='\0' = free slot  */
static unsigned char g_stale[OFFERED_MAX];    /* marked by offered_begin  */

static void scopy(char *dst, const char *src, int cap)
{
    int n = src ? (int)strlen(src) : 0;
    if (n > cap - 1)
        n = cap - 1;
    if (n)                              /* memcpy(dst, NULL, 0) is still UB */
        memcpy(dst, src, (size_t)n);
    dst[n] = '\0';
}

void offered_begin(const char *device_id)
{
    int i;

    if (!device_id || !device_id[0])
        return;
    Forbid();
    for (i = 0; i < OFFERED_MAX; i++)
        if (g_offers[i].id[0] &&
            strcmp(g_offers[i].device_id, device_id) == 0)
            g_stale[i] = 1;
    Permit();
}

void offered_note(const char *device_id, const char *device_name,
                  const char *id, const char *label)
{
    int i, free_slot = -1;

    if (!id || !id[0] || !device_id || !device_id[0])
        return;
    /* Both strings come off the wire in the peer's ClusterConfig, and accepting
     * an offer writes them into amisync.conf verbatim (the id IS the folder id,
     * which must match the peer's exactly, so neither can be sanitised into
     * shape). An offer we could not represent is one we could never accept:
     * drop it here rather than show the user a row that would corrupt the
     * config, and quietly - a hostile peer re-sends its CC freely. */
    if (!text_field_safe(id) || (label && !text_field_safe(label)))
        return;

    Forbid();
    for (i = 0; i < OFFERED_MAX; i++) {
        if (!g_offers[i].id[0]) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (strcmp(g_offers[i].id, id) == 0 &&
            strcmp(g_offers[i].device_id, device_id) == 0)
            break;                         /* refresh in place */
    }
    if (i == OFFERED_MAX) {
        if (free_slot < 0) {
            Permit();                      /* table full: drop silently */
            return;
        }
        i = free_slot;
        scopy(g_offers[i].id,        id,        sizeof(g_offers[i].id));
        scopy(g_offers[i].device_id, device_id, sizeof(g_offers[i].device_id));
    }
    scopy(g_offers[i].label,  label,       sizeof(g_offers[i].label));
    scopy(g_offers[i].device_name, device_name, sizeof(g_offers[i].device_name));
    g_stale[i] = 0;
    Permit();
}

void offered_end(const char *device_id)
{
    int i;

    if (!device_id || !device_id[0])
        return;
    Forbid();
    for (i = 0; i < OFFERED_MAX; i++)
        if (g_offers[i].id[0] && g_stale[i] &&
            strcmp(g_offers[i].device_id, device_id) == 0) {
            g_offers[i].id[0] = '\0';     /* tombstone: slot index stays */
            g_stale[i] = 0;
        }
    Permit();
}

int offered_get(int i, OfferedFolder *out)
{
    int ok = 0;

    Forbid();
    if (i >= 0 && i < OFFERED_MAX) {
        *out = g_offers[i];                /* possibly tombstoned: id empty */
        ok = 1;
    }
    Permit();
    return ok;
}
