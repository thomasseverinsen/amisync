# Makefile for amisync - Syncthing-compatible sync daemon for AmigaOS 3.x
# Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
#
# Cross-compiled with Bebbo's amiga-gcc (expects /opt/amiga13/bin in PATH).
#
# Targets:
#   make all      - the release 020, 040 and 060 binaries
#   make tests    - host-side unit checks (plain cc, no AmiSSL)
#   make fuzz     - host-side ASan/UBSan smoke pass
#   make package  - assemble dist/Amisync, the install drawer
#   make lha      - and archive it
#   make clean    - remove everything built
# Individual variants (amisync_060, amisync_040_debug, test-bep, ...) build on
# their own; .PHONY below is the full list.

CC = m68k-amigaos-gcc

# Dependency locations - override on the command line or environment if yours
# differ, e.g.:  make AMISSL_SDK=$HOME/amissl-sdk all
AMISSL_SDK ?= /opt/amissl-sdk
SDI_INC    ?= /opt/sdi-headers

SRCDIR   = src
INCDIR   = include
BUILDDIR = build
DISTDIR  = dist

# The release version, taken from the single source of truth in version.h.
VERSION := $(shell sed -n 's/^\#define AMISYNC_VERSION *"\(.*\)"/\1/p' \
                   $(INCDIR)/version.h)

# Source files (in $(SRCDIR)). Add new modules here.
SRCS = main.c daemon.c log.c config.c arexx.c appicon.c statuswin.c offered.c \
       device_id.c ssl.c netbase.c net.c pbuf.c bep.c lz4.c ignore.c \
       pathsafe.c folder.c \
       syncmodel.c foldstate.c index_store.c scanner.c wreg.c spill.c worker.c \
       peer.c listener.c disco.c

# Warning set validated against the AmiSSL toolchain.
WARN = -Wall -Wno-pointer-sign -Wno-attributes -Wno-int-conversion

# Include paths.
INCLUDES = -I$(INCDIR) -I$(AMISSL_SDK)/include -I$(SDI_INC)

# Flags common to every variant. -noixemul = native AmigaOS, no ixemul.
DEPFLAGS = -MMD -MP
COMMON   = -noixemul $(WARN) $(INCLUDES) $(DEPFLAGS)

# COMMON without -MMD: the one-shot check/selftest builds leave no .d files.
CHECKFLAGS = -noixemul $(WARN) $(INCLUDES)

# The 020 build is soft-float so it runs on FPU-less 68020/68030 machines.
# Nothing here does floating-point maths, so that costs nothing.
CPU_020 = -m68020
CPU_040 = -m68040 -mhard-float
CPU_060 = -m68060 -mhard-float

# Release vs debug configuration flags.
REL_FLAGS = -O2 -DNDEBUG
DBG_FLAGS = -O0 -g -DDEBUG

# Link configuration.
LIBDIR  = -L$(AMISSL_SDK)/lib/AmigaOS3
LDFLAGS = -noixemul $(LIBDIR)

# The daemon does TLS/BEP, so it links the AmiSSL stub library.
# bsdsocket is reached through the inline library calls (proto/bsdsocket.h)
# and needs no link library of its own.
LIBS = -lamisslstubs

# ---------------------------------------------------------------------------
# Build-variant template.
#   $(call BUILD_VARIANT, tag, cpuflags, cfgflags, output-name)
# Creates a per-variant object dir and link rule so the four configurations
# never share .o files.
# ---------------------------------------------------------------------------
define BUILD_VARIANT
OBJS_$(1) = $$(addprefix $$(BUILDDIR)/$(1)/,$$(SRCS:.c=.o))

$$(BUILDDIR)/$(1):
	mkdir -p $$@

$$(BUILDDIR)/$(1)/%.o: $$(SRCDIR)/%.c | $$(BUILDDIR)/$(1)
	$$(CC) $(2) $(3) $$(COMMON) -c $$< -o $$@

$$(DISTDIR)/$(4): $$(OBJS_$(1)) | $$(DISTDIR)
	$$(CC) $(2) $$(LDFLAGS) $$(OBJS_$(1)) $$(LIBS) -o $$@
	@echo "  built $$@"
endef

$(eval $(call BUILD_VARIANT,020,$(CPU_020),$(REL_FLAGS),amisync_020))
$(eval $(call BUILD_VARIANT,040,$(CPU_040),$(REL_FLAGS),amisync_040))
$(eval $(call BUILD_VARIANT,060,$(CPU_060),$(REL_FLAGS),amisync_060))
$(eval $(call BUILD_VARIANT,040d,$(CPU_040),$(DBG_FLAGS),amisync_040.debug))
$(eval $(call BUILD_VARIANT,060d,$(CPU_060),$(DBG_FLAGS),amisync_060.debug))

# ---------------------------------------------------------------------------
# Phony convenience targets
# ---------------------------------------------------------------------------
.PHONY: all clean amisync_020 amisync_040 amisync_060 amisync_040_debug amisync_060_debug \
        test test-pbuf test-bep test-disco test-syncmodel test-foldstate \
        test-foldsync test-index-store test-ignore test-pathsafe test-converge tests \
        device_id-check ssl-selftest genid package icon lha

all: amisync_020 amisync_040 amisync_060 genid

# Needs python3 + Pillow + rsvg-convert on the host, so it is kept out of 'all':
# the daemon must still build without them.
icon: $(DISTDIR)/amisync.info

$(DISTDIR)/amisync.info: tools/genglowicon.py assets/syncthing-logo.svg | $(DISTDIR)
	python3 tools/genglowicon.py assets/syncthing-logo.svg $@

PKGDIR = $(DISTDIR)/Amisync
package: amisync_020 amisync_040 amisync_060 genid icon
	rm -rf $(PKGDIR)
	mkdir -p $(PKGDIR)
	cp install/Install              $(PKGDIR)/Install
	cp $(DISTDIR)/amisync_020       $(PKGDIR)/amisync.020
	cp $(DISTDIR)/amisync_040       $(PKGDIR)/amisync.040
	cp $(DISTDIR)/amisync_060       $(PKGDIR)/amisync.060
	cp $(DISTDIR)/amisync-genid     $(PKGDIR)/amisync-genid
	cp $(DISTDIR)/amisync.info      $(PKGDIR)/appicon.info
	cp config/amisync.conf.example  $(PKGDIR)/
	cp install/amisync.guide        $(PKGDIR)/amisync.guide
	cp README.md                    $(PKGDIR)/README
	cp BUILDING.md                  $(PKGDIR)/BUILDING
	cp LICENSE                      $(PKGDIR)/
	cp THIRD-PARTY.md               $(PKGDIR)/THIRD-PARTY
	@if [ -f install/Install.info ]; then cp install/Install.info $(PKGDIR)/; \
	 else echo "  note: no install/Install.info icon - add one for double-click, or run 'Installer Install'"; fi
	@if [ -f install/Amisync.info ]; then cp install/Amisync.info $(DISTDIR)/Amisync.info; \
	 else echo "  note: no install/Amisync.info drawer icon (optional - lets the drawer open from Workbench)"; fi
	@echo "  packaged $(PKGDIR)"

# An archive packed here carries Unix mode bits, not AmigaOS protection bits,
# so everything extracts as rwed. That is fine for a GitHub asset - the
# package tolerates it, and Install re-protects what it copies - but an Aminet
# upload wants conventional attributes, so re-pack on the Amiga:
#     LhA -r -e a amisync.lha Amisync Amisync.info
#
# Debian's 'lha' (lhasa) only extracts; jlha creates. Override: make LHA=<tool>
LHA ?= $(shell command -v jlha 2>/dev/null || echo lha)

lha: package
	rm -f $(DISTDIR)/amisync-$(VERSION).lha
	cd $(DISTDIR) && $(LHA) a amisync-$(VERSION).lha Amisync \
	    $$( [ -f Amisync.info ] && echo Amisync.info )
	@echo "  built $(DISTDIR)/amisync-$(VERSION).lha"

amisync_020:       $(DISTDIR)/amisync_020
amisync_040:       $(DISTDIR)/amisync_040
amisync_060:       $(DISTDIR)/amisync_060
amisync_040_debug: $(DISTDIR)/amisync_040.debug
amisync_060_debug: $(DISTDIR)/amisync_060.debug

$(DISTDIR):
	mkdir -p $@

clean:
	rm -rf $(BUILDDIR)/020 $(BUILDDIR)/040 $(BUILDDIR)/060 $(BUILDDIR)/040d $(BUILDDIR)/060d
	rm -rf $(PKGDIR)
	rm -f  $(DISTDIR)/amisync_020 $(DISTDIR)/amisync_040 $(DISTDIR)/amisync_060 \
	       $(DISTDIR)/amisync_040.debug $(DISTDIR)/amisync_060.debug \
	       $(DISTDIR)/amisync.info $(DISTDIR)/amisync-*.lha \
	       $(BUILDDIR)/test_device_id $(BUILDDIR)/test_pbuf \
	       $(BUILDDIR)/test_bep $(BUILDDIR)/test_disco \
	       $(BUILDDIR)/test_syncmodel $(BUILDDIR)/test_foldstate \
	       $(BUILDDIR)/test_foldsync $(BUILDDIR)/test_index_store \
	       $(BUILDDIR)/test_ignore $(BUILDDIR)/test_config $(BUILDDIR)/test_pathsafe \
	       $(BUILDDIR)/test_converge \
	       $(BUILDDIR)/fuzz_all $(BUILDDIR)/fuzz_config \
	       $(BUILDDIR)/device_id_040.o $(BUILDDIR)/device_id_060.o \
	       $(BUILDDIR)/ssl_selftest_040 $(BUILDDIR)/ssl_selftest_060 \
	       $(BUILDDIR)/ssl_bench_040 $(BUILDDIR)/ssl_bench_060 \
	       $(DISTDIR)/amisync-genid

# ---------------------------------------------------------------------------
# Host-side unit checks
# ---------------------------------------------------------------------------
# Built with the host cc, not the cross-compiler, and with no AmiSSL: these
# cover the logic that does not need an Amiga to be wrong.
tests: test test-pbuf test-bep test-disco test-syncmodel test-foldstate \
       test-foldsync test-index-store test-ignore test-config test-pathsafe \
       test-converge

test: $(BUILDDIR)/test_device_id
	@$(BUILDDIR)/test_device_id

test-pathsafe: $(BUILDDIR)/test_pathsafe
	@$(BUILDDIR)/test_pathsafe

# Randomized two-device convergence property test. The default run is a
# quick pass; for a longer campaign give it a scenario count and seed, e.g.
#   build/test_converge 200000 0xDEADBEEF
test-converge: $(BUILDDIR)/test_converge
	@$(BUILDDIR)/test_converge

test-pbuf: $(BUILDDIR)/test_pbuf
	@$(BUILDDIR)/test_pbuf

test-bep: $(BUILDDIR)/test_bep
	@$(BUILDDIR)/test_bep

test-disco: $(BUILDDIR)/test_disco
	@$(BUILDDIR)/test_disco

test-syncmodel: $(BUILDDIR)/test_syncmodel
	@$(BUILDDIR)/test_syncmodel

test-foldstate: $(BUILDDIR)/test_foldstate
	@$(BUILDDIR)/test_foldstate

test-foldsync: $(BUILDDIR)/test_foldsync
	@$(BUILDDIR)/test_foldsync

test-index-store: $(BUILDDIR)/test_index_store
	@$(BUILDDIR)/test_index_store

test-ignore: $(BUILDDIR)/test_ignore
	@$(BUILDDIR)/test_ignore

test-config: $(BUILDDIR)/test_config
	@$(BUILDDIR)/test_config

$(BUILDDIR)/test_device_id: tests/test_device_id.c src/device_id.c include/device_id.h
	cc -Wall -I$(INCDIR) tests/test_device_id.c -o $@

$(BUILDDIR)/test_pathsafe: tests/test_pathsafe.c src/pathsafe.c include/pathsafe.h
	cc -Wall -I$(INCDIR) tests/test_pathsafe.c src/pathsafe.c -o $@

$(BUILDDIR)/test_converge: tests/test_converge.c src/syncmodel.c include/syncmodel.h
	cc -Wall -I$(INCDIR) tests/test_converge.c src/syncmodel.c -o $@

$(BUILDDIR)/test_pbuf: tests/test_pbuf.c src/pbuf.c include/pbuf.h
	cc -Wall -I$(INCDIR) tests/test_pbuf.c -o $@

$(BUILDDIR)/test_bep: tests/test_bep.c src/bep.c src/pbuf.c src/lz4.c include/bep.h
	cc -Wall -DBEP_HOST_TEST -I$(INCDIR) tests/test_bep.c src/bep.c src/pbuf.c src/lz4.c -o $@

$(BUILDDIR)/test_disco: tests/test_disco.c src/disco.c src/pbuf.c include/disco.h
	cc -Wall -I$(INCDIR) tests/test_disco.c src/pbuf.c -o $@

$(BUILDDIR)/test_syncmodel: tests/test_syncmodel.c src/syncmodel.c include/syncmodel.h
	cc -Wall -I$(INCDIR) tests/test_syncmodel.c src/syncmodel.c -o $@

$(BUILDDIR)/test_foldstate: tests/test_foldstate.c src/foldstate.c include/foldstate.h
	cc -Wall -DFOLDSTATE_HOST_TEST -I$(INCDIR) tests/test_foldstate.c src/foldstate.c -o $@

$(BUILDDIR)/test_foldsync: tests/test_foldsync.c src/foldstate.c src/syncmodel.c \
                           include/foldstate.h include/syncmodel.h
	cc -Wall -DFOLDSTATE_HOST_TEST -I$(INCDIR) tests/test_foldsync.c \
	   src/foldstate.c src/syncmodel.c -o $@

$(BUILDDIR)/test_index_store: tests/test_index_store.c src/index_store.c \
                              src/foldstate.c src/pbuf.c include/index_store.h
	cc -Wall -DFOLDSTATE_HOST_TEST -I$(INCDIR) tests/test_index_store.c \
	   src/index_store.c src/foldstate.c src/pbuf.c -o $@

$(BUILDDIR)/test_ignore: tests/test_ignore.c src/ignore.c include/ignore.h
	cc -Wall -I$(INCDIR) tests/test_ignore.c src/ignore.c -o $@

$(BUILDDIR)/test_config: tests/test_config.c src/config.c src/device_id.c \
                         src/pathsafe.c include/config.h
	cc -Wall -DDEVICE_ID_HOST_TEST -I$(INCDIR) tests/test_config.c \
	   src/config.c src/device_id.c src/pathsafe.c -o $@

# ---------------------------------------------------------------------------
# Host-side fuzzers (ASan/UBSan)
# ---------------------------------------------------------------------------
# Everything that parses untrusted or on-disk input. 'make fuzz' is a smoke
# pass; for a real campaign run a binary directly with a count and seed:
#   build/fuzz_all 3000000 0xF00DFACE1234

FUZZFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

fuzz: $(BUILDDIR)/fuzz_all $(BUILDDIR)/fuzz_config
	@$(BUILDDIR)/fuzz_all 200000
	@$(BUILDDIR)/fuzz_config 50000

$(BUILDDIR)/fuzz_all: tests/fuzz_all.c src/bep.c src/pbuf.c src/lz4.c \
                      src/foldstate.c src/index_store.c src/disco.c
	cc $(FUZZFLAGS) -Wall -DBEP_HOST_TEST -DFOLDSTATE_HOST_TEST -I$(INCDIR) \
	   tests/fuzz_all.c src/bep.c src/pbuf.c src/lz4.c src/foldstate.c \
	   src/index_store.c -o $@

$(BUILDDIR)/fuzz_config: tests/fuzz_config.c src/config.c src/device_id.c \
                         src/pathsafe.c
	cc $(FUZZFLAGS) -Wall -DDEVICE_ID_HOST_TEST -I$(INCDIR) \
	   tests/fuzz_config.c src/config.c src/device_id.c src/pathsafe.c -o $@

# Cross-compile sanity for the device_id module alone: object only, no link.
device_id-check:
	$(CC) $(CPU_040) $(REL_FLAGS) $(CHECKFLAGS) -c $(SRCDIR)/device_id.c \
	      -o $(BUILDDIR)/device_id_040.o
	$(CC) $(CPU_060) $(REL_FLAGS) $(CHECKFLAGS) -c $(SRCDIR)/device_id.c \
	      -o $(BUILDDIR)/device_id_060.o
	@echo "  device_id.c cross-compiles for 040 and 060"

# ---------------------------------------------------------------------------
# ssl selftest
# ---------------------------------------------------------------------------
# Must be RUN on the Amiga to prove anything: building it only proves it
# links against the AmiSSL stubs.
SSL_LIBS = -lamisslstubs

ssl-selftest: $(BUILDDIR)/ssl_selftest_040 $(BUILDDIR)/ssl_selftest_060

# Symmetric-crypto throughput on the target (see tools/ssl_bench.c).
ssl-bench: $(BUILDDIR)/ssl_bench_040 $(BUILDDIR)/ssl_bench_060

$(BUILDDIR)/ssl_bench_%: tools/ssl_bench.c src/ssl.c src/netbase.c \
                          include/ssl.h include/netbase.h
	$(CC) $(CPU_$*) $(REL_FLAGS) $(CHECKFLAGS) tools/ssl_bench.c src/ssl.c \
	      src/netbase.c $(LDFLAGS) $(SSL_LIBS) -o $@
	@echo "  built $@"

$(BUILDDIR)/ssl_selftest_%: tools/ssl_selftest.c src/ssl.c src/netbase.c \
                            include/ssl.h include/netbase.h
	$(CC) $(CPU_$*) $(REL_FLAGS) $(CHECKFLAGS) tools/ssl_selftest.c src/ssl.c \
	      src/netbase.c $(LDFLAGS) $(SSL_LIBS) -o $@
	@echo "  built $@"

# ---------------------------------------------------------------------------
# amisync-genid tool
# ---------------------------------------------------------------------------
GENID_SRCS = tools/amisync-genid.c src/device_id.c src/ssl.c src/netbase.c src/log.c
GENID_HDRS = include/device_id.h include/ssl.h include/netbase.h include/log.h
GENID_LIBS = -lamisslstubs

genid: $(DISTDIR)/amisync-genid

$(DISTDIR)/amisync-genid: $(GENID_SRCS) $(GENID_HDRS) | $(DISTDIR)
	$(CC) $(CPU_020) $(REL_FLAGS) $(CHECKFLAGS) $(GENID_SRCS) \
	      $(LDFLAGS) $(GENID_LIBS) -o $@
	@echo "  built $@"

# Auto-generated header dependencies (-MMD).
-include $(wildcard $(BUILDDIR)/*/*.d)
