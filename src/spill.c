/* spill.c - the wanted files that did not fit in the want queue
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * See spill.h for why this exists. The format is ours alone and lives for one
 * session, so it is a plain big-endian record stream rather than anything
 * negotiated - but every scalar is written a byte at a time, because a spill
 * written by the 060 build and read after a crash by the 020 one must not
 * depend on how either lays out a struct.
 */

#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include "spill.h"
#include "log.h"

#define SPILL_MAGIC   0x414D5350UL     /* "AMSP" */
#define SPILL_FORMAT  1
#define SPILL_HDR     8                /* magic + format */
/* Fixed part of a record, ahead of the name, content hash, version counters
 * and block hashes. Writer and reader MUST agree: they did not, once, and a
 * reader eight bytes adrift produced records with empty names that were then
 * requested from the peer, which closed the connection on the spot. */
#define SPILL_HEAD    60
/* A record is a name, some scalars, a version vector and the block hashes.
 * The cap is a sanity bound for the reader, not a design limit. */
#define SPILL_HASH_CAP (2048 * BEP_HASH_LEN)
#define SPILL_REC_MAX  (BEP_PATH_MAX + 256 + SPILL_HASH_CAP)

/* ---- byte-order-independent scalars ---------------------------------- */

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void put64(unsigned char *p, uint64_t v)
{
    put32(p, (uint32_t)(v >> 32));
    put32(p + 4, (uint32_t)v);
}

static uint64_t get64(const unsigned char *p)
{
    return ((uint64_t)get32(p) << 32) | (uint64_t)get32(p + 4);
}

/* FNV-1a, 16 hex digits - the same trick folder.c uses to turn an arbitrary
 * id into a filename that every filesystem will accept. */
static void fnv16(const char *s, char *out)
{
    unsigned long long h = 14695981039346656037ULL;
    int i;

    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    for (i = 0; i < 16; i++) {
        int nib = (int)((h >> ((15 - i) * 4)) & 0xF);
        out[i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    out[16] = '\0';
}

int spill_path(const char *statedir, const char *folder_id, const char *peer_id,
               uint32_t uniq, const char *ext, char *out, int cap)
{
    char fh[17], ph[17];
    int  n;

    if (!statedir || !folder_id || !out)
        return 0;
    fnv16(folder_id, fh);
    fnv16(peer_id ? peer_id : "", ph);
    /* FFS truncates a filename at 30 characters, silently. Two 16-digit
     * hashes, a separator and an extension come to 37, so the wanted-files
     * spill and the deletions spill of one (folder, peer) pair - which differ
     * ONLY in that extension - both became the same file. Measured on the
     * A4000 the moment a rename needed both at once: the second create failed
     * against the first, still open, and the folder fell back to the
     * reconnect-per-batch behaviour the spill exists to remove.
     *
     * 12 digits each brings it to 29. That is still 96 bits of hash across the
     * pair, for a handful of folders times a handful of peers. */
    fh[12] = '\0';
    ph[12] = '\0';
    {   /* Fold the caller's per-worker value into the peer half, so the two
         * workers one peer can have - our dial and its inbound connection -
         * do not land on the same file. Written over hex digits rather than
         * appended, because the name has to stay inside FFS's 30. */
        static const char hexd[] = "0123456789abcdef";
        int i;
        for (i = 0; i < 8; i++)
            ph[11 - i] = hexd[(uniq >> (i * 4)) & 0xf];
    }

    n = (int)strlen(statedir);
    if (n + 40 >= cap)
        return 0;
    strcpy(out, statedir);
    if (n && out[n - 1] != ':' && out[n - 1] != '/')
        strcat(out, "/");
    strcat(out, fh);
    strcat(out, "-");
    strcat(out, ph);
    strcat(out, ext ? ext : ".spl");
    return 1;
}

/* ---- lifecycle -------------------------------------------------------- */

int spill_reset(SpillFile *sp, const char *path)
{
    unsigned char hdr[SPILL_HDR];
    BPTR          fh;

    if (!sp || !path)
        return 0;
    spill_close(sp);                       /* whatever was there is stale */

    memset(sp, 0, sizeof(*sp));
    strncpy(sp->path, path, sizeof(sp->path) - 1);

    fh = Open((STRPTR)path, MODE_NEWFILE);
    if (!fh) {
        /* Latched, because the caller asks once per record: a folder that
         * cannot spill logged this several hundred times a second on the
         * A4000, which buried the reason it was failing. */
        sp->failed = 1;
        log_printf(LOG_WARN, "spill: cannot create '%s' - a big index will "
                   "fall back to reconnecting for the remainder", path);
        return 0;
    }
    put32(hdr, SPILL_MAGIC);
    put32(hdr + 4, SPILL_FORMAT);
    if (Write(fh, hdr, SPILL_HDR) != SPILL_HDR) {
        Close(fh);
        DeleteFile((STRPTR)path);
        sp->failed = 1;
        return 0;
    }
    sp->fh   = (void *)fh;
    sp->roff = SPILL_HDR;
    sp->woff = SPILL_HDR;
    sp->ok   = 1;
    return 1;
}

void spill_close(SpillFile *sp)
{
    if (!sp)
        return;
    if (sp->fh) {
        Close((BPTR)sp->fh);
        sp->fh = NULL;
    }
    if (sp->path[0]) {
        DeleteFile((STRPTR)sp->path);       /* session-scoped: never outlives */
        sp->path[0] = '\0';
    }
    sp->ok = sp->roff = sp->woff = 0;
}

int spill_pending(const SpillFile *sp)
{
    return sp && sp->ok && sp->roff < sp->woff;
}

void spill_rewind(SpillFile *sp)
{
    if (sp && sp->ok) {
        sp->roff  = SPILL_HDR;
        sp->woff  = SPILL_HDR;
        sp->nleft = 0;
        /* Hand the space back rather than sitting on a third of a megabyte
         * for the rest of the session; the file itself stays open, because
         * deleting and re-creating it per burst is what the rewind avoids.
         * Best-effort: a filesystem that will not truncate loses nothing but
         * the space. */
        if (sp->fh)
            SetFileSize((BPTR)sp->fh, SPILL_HDR, OFFSET_BEGINNING);
    }
}

int spill_count(const SpillFile *sp)
{
    return (sp && sp->ok && sp->nleft > 0) ? sp->nleft : 0;
}

/* ---- writing ---------------------------------------------------------- */

int spill_append(SpillFile *sp, const BepFileInfo *fi,
                 const unsigned char (*hashes)[BEP_HASH_LEN], int nb,
                 int conflict)
{
    unsigned char head[128];
    int           nlen, i, p = 0;
    uint32_t      body;
    BPTR          fh;

    if (!sp || !sp->ok || !sp->fh || !fi)
        return 0;
    if (nb < 0)
        nb = 0;
    nlen = (int)strlen(fi->name);
    if (nlen <= 0 || nlen >= BEP_PATH_MAX)
        return 0;
    if (fi->version.num_counters < 0 || fi->version.num_counters > BEP_MAX_COUNTERS)
        return 0;

    /* head: everything except the name and the hashes, whose lengths it
     * carries. body = the whole record after the length field itself. */
    put32(head + p, 0); p += 4;                        /* body, filled below */
    head[p++] = (unsigned char)(nlen >> 8);
    head[p++] = (unsigned char)nlen;
    head[p++] = (unsigned char)fi->type;
    head[p++] = (unsigned char)(fi->deleted ? 1 : 0);
    head[p++] = (unsigned char)(fi->invalid ? 1 : 0);
    head[p++] = (unsigned char)(conflict ? 1 : 0);
    head[p++] = (unsigned char)(fi->has_content_hash ? 1 : 0);
    head[p++] = (unsigned char)fi->version.num_counters;
    put32(head + p, fi->permissions);            p += 4;
    put32(head + p, (uint32_t)fi->block_size);   p += 4;
    put32(head + p, (uint32_t)fi->modified_ns);  p += 4;
    put32(head + p, (uint32_t)nb);               p += 4;
    put64(head + p, (uint64_t)fi->size);         p += 8;
    put64(head + p, (uint64_t)fi->modified_s);   p += 8;
    put64(head + p, fi->modified_by);            p += 8;
    put64(head + p, (uint64_t)fi->sequence);     p += 8;

    if (p != SPILL_HEAD)                   /* the reader reads exactly this */
        return 0;
    body = (uint32_t)(p - 4) + (uint32_t)nlen + BEP_HASH_LEN +
           (uint32_t)fi->version.num_counters * 16 +
           (uint32_t)nb * BEP_HASH_LEN;
    put32(head, body);

    fh = (BPTR)sp->fh;
    if (Seek(fh, sp->woff, OFFSET_BEGINNING) < 0)
        goto fail;
    if (Write(fh, head, p) != p)
        goto fail;
    if (Write(fh, (APTR)fi->name, nlen) != nlen)
        goto fail;
    if (Write(fh, (APTR)fi->content_hash, BEP_HASH_LEN) != BEP_HASH_LEN)
        goto fail;
    for (i = 0; i < fi->version.num_counters; i++) {
        unsigned char c[16];
        put64(c, fi->version.counters[i].id);
        put64(c + 8, fi->version.counters[i].value);
        if (Write(fh, c, 16) != 16)
            goto fail;
    }
    for (i = 0; i < nb; i++)
        if (Write(fh, (APTR)hashes[i], BEP_HASH_LEN) != BEP_HASH_LEN)
            goto fail;

    sp->woff += 4 + (long)body;
    sp->nleft++;
    return 1;

fail:
    /* Out of space or a write error: stop using the spill entirely rather
     * than leaving a half record behind. The caller falls back to the old
     * behaviour for the rest of this index. */
    log_printf(LOG_WARN, "spill: write failed; falling back to reconnecting "
               "for the remainder of this index");
    sp->ok = 0;
    return 0;
}

/* ---- reading ---------------------------------------------------------- */

int spill_next(SpillFile *sp, long *next, BepFileInfo *fi,
               unsigned char (*hashes)[BEP_HASH_LEN], int max_blocks,
               int *nb, int *conflict)
{
    unsigned char head[128];
    int           nlen, ncnt, n, i, p = 0;
    uint32_t      body;
    BPTR          fh;

    if (!sp || !sp->ok || !sp->fh || !fi || !next)
        return 0;
    if (sp->roff >= sp->woff)
        return 0;                                    /* nothing queued */

    fh = (BPTR)sp->fh;
    if (Seek(fh, sp->roff, OFFSET_BEGINNING) < 0)
        return -1;
    if (Read(fh, head, SPILL_HEAD) != SPILL_HEAD)
        return -1;

    body = get32(head + p); p += 4;
    nlen = (head[p] << 8) | head[p + 1]; p += 2;
    memset(fi, 0, sizeof(*fi));
    fi->type             = head[p++];
    fi->deleted          = head[p++];
    fi->invalid          = head[p++];
    *conflict            = head[p++];
    fi->has_content_hash = head[p++];
    ncnt                 = head[p++];
    fi->permissions  = get32(head + p);           p += 4;
    fi->block_size   = (int32_t)get32(head + p);  p += 4;
    fi->modified_ns  = (int32_t)get32(head + p);  p += 4;
    n                = (int)get32(head + p);      p += 4;
    fi->size         = (int64_t)get64(head + p);  p += 8;
    fi->modified_s   = (int64_t)get64(head + p);  p += 8;
    fi->modified_by  = get64(head + p);           p += 8;
    fi->sequence     = (int64_t)get64(head + p);  p += 8;

    if (nlen <= 0 || nlen >= BEP_PATH_MAX || ncnt < 0 ||
        ncnt > BEP_MAX_COUNTERS || n < 0 || body > (uint32_t)SPILL_REC_MAX)
        return -1;
    if (n > max_blocks)
        return -1;                                   /* caller cannot hold it */

    if (Read(fh, fi->name, nlen) != nlen)
        return -1;
    fi->name[nlen] = '\0';
    if (Read(fh, fi->content_hash, BEP_HASH_LEN) != BEP_HASH_LEN)
        return -1;
    fi->version.num_counters = ncnt;
    for (i = 0; i < ncnt; i++) {
        unsigned char c[16];
        if (Read(fh, c, 16) != 16)
            return -1;
        fi->version.counters[i].id    = get64(c);
        fi->version.counters[i].value = get64(c + 8);
    }
    for (i = 0; i < n; i++)
        if (Read(fh, hashes[i], BEP_HASH_LEN) != BEP_HASH_LEN)
            return -1;

    fi->num_blocks = n;
    *nb            = n;
    *next          = sp->roff + 4 + (long)body;
    return 1;
}

void spill_commit(SpillFile *sp, long next)
{
    if (sp && next > sp->roff) {
        sp->roff = next;
        if (sp->nleft > 0)
            sp->nleft--;
    }
}
