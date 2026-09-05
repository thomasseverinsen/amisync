/* version.h - amisync version string
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 */

#ifndef AMISYNC_VERSION_H
#define AMISYNC_VERSION_H

/* Bump BOTH on every release: AMISYNC_VERTAG below splices them into one
 * $VER: cookie, so a version without its date ships claiming the old one. */
#define AMISYNC_VERSION  "0.9.4"
#define AMISYNC_DATE     "05.09.2026"   /* dd.mm.yyyy */

/* CPU variant this binary was built for, from the per-variant -m flags (the
 * Makefile builds 020/040/060 objects separately). For the startup banner. */
#if defined(__mc68060__)
#define AMISYNC_CPU "68060"
#elif defined(__mc68040__)
#define AMISYNC_CPU "68040"
#elif defined(__mc68020__)
#define AMISYNC_CPU "68020"
#else
#define AMISYNC_CPU "68k"               /* baseline 68000 build */
#endif

/* Product name for user-visible branding (status reports, requesters, the
 * Tools menu, the BEP Hello client name). File names, paths, the ARexx port
 * and the $VER cookie stay lowercase "amisync" - the name users type. */
#define AMISYNC_NAME     "AmiSync"

/* What peers see in Hello, and index under. Separate from AMISYNC_NAME so a
 * product rename doesn't change our identity on the wire. */
#define AMISYNC_CLIENT   AMISYNC_NAME

/* AmigaOS version cookie. The `Version` command (and our VERSION ARexx verb)
 * read a "$VER: <name> <ver> (<dd.mm.yyyy>)" string embedded in the binary.
 * Embed it once per executable with AMISYNC_VERTAG(progname); see main.c and
 * amisync-genid.c. */
#define AMISYNC_VERTAG(prog)  "$VER: " prog " " AMISYNC_VERSION " (" AMISYNC_DATE ")"

#endif /* AMISYNC_VERSION_H */
