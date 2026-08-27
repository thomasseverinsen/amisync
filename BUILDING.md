# Building AmiSync

AmiSync is cross-compiled on Linux (or WSL2) with
[Bebbo's amiga-gcc](https://franke.ms/amiga/amiga-gcc.wiki).

## Toolchain

- amiga-gcc at `/opt/amiga13/` (its `bin/` on `PATH`)
- [AmiSSL SDK](https://github.com/jens-maus/amissl/releases) 5.x at
  `/opt/amissl-sdk/` (link libraries in `lib/AmigaOS3/`)
- [SDI headers](https://github.com/adtools/SDI) at `/opt/sdi-headers/`

The AmiSSL SDK and SDI header locations can be overridden without editing
the Makefile:

```sh
make AMISSL_SDK=$HOME/amissl-sdk SDI_INC=$HOME/sdi-headers all
```

Two toolchain notes:

- The build requires amiga-gcc's patched `ndk-include` — in particular
  `m68k-amigaos/ndk-include/inline/macros.h`, which carries the `LP*FP`
  variants AmiSSL needs. Do not replace it with a stock NDK copy.
- The networking headers amiga-gcc bundles (Roadshow's freely-distributable
  netinclude) compile AmiSync as shipped. If you ever hit missing bsdsocket
  declarations, update them from a newer Roadshow SDK.

## Build

```sh
make all                 # release builds (daemon 020/040/060 + amisync-genid)
make amisync_020         # release, 68020/68030 (soft-float, no FPU needed)
make amisync_040         # release, 68040
make amisync_060         # release, 68060
make amisync_040_debug   # debug build, 68040
make amisync_060_debug   # debug build, 68060
make genid               # the amisync-genid identity tool (one 68020 build)
make icon                # regenerate the icon file (python3 + Pillow + rsvg-convert)
make clean               # remove build artifacts and binaries
```

Binaries land in `dist/`; object files under `build/<variant>/`.

## Tests and analysis

Host-side, plain `cc`, no Amiga toolchain needed:

```sh
make tests               # unit checks: device IDs, codecs, framing, discovery,
                         #   sync logic, index store, ignores, config, path safety,
                         #   and two-device convergence
make fuzz                # ASan/UBSan mutation-fuzz smoke pass over every parser
```

For a longer fuzz campaign, run the fuzzer binaries directly with an
iteration count and RNG seed, e.g. `build/fuzz_all 3000000 0xF00DFACE1234`.

## Packaging

```sh
make package             # assembles the install drawer in dist/Amisync/
make lha                 # dist/amisync-<version>.lha release archive
```

`dist/Amisync/` is the ready-to-distribute drawer: all three CPU builds of the
daemon, the single `amisync-genid` binary, the icon file, the example config, the
AmigaGuide manual, the docs and the Commodore Installer script. Note that
`package` (and therefore `lha`) depends on the `icon` target, so it needs
python3, Pillow and rsvg-convert as well as the cross-compiler. See the note above the `lha` target in the
[Makefile](Makefile) about attribute limitations of host-made LhA archives.

## Layout

```
src/        daemon + module source
include/    public headers
tools/      standalone tools (amisync-genid, ssl_selftest, icon generator)
tests/      host-side unit checks and fuzzers
config/     example configuration
install/    Installer script, AmigaGuide manual, Aminet .readme, icons
assets/     Syncthing logo source (see Third-party content in the README)
build/      object files (per build variant)
dist/       linked binaries and the assembled package
```
