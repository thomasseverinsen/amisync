# Third-party content

AmiSync itself is MIT licensed (see [LICENSE](LICENSE)). The files listed
below are **not** — they came from other projects and keep the licences
their authors gave them. Anyone redistributing AmiSync, in source or as a
built archive, is redistributing these too.

## LZ4 — BSD 2-Clause

- `src/lz4.c`
- `include/lz4.h`

Vendored verbatim from [LZ4](https://github.com/lz4/lz4), Copyright (C)
2011–2023 Yann Collet. The full licence text is at the top of both files.
Used for BEP message compression.

## Syncthing logo — MPL-2.0

- `assets/syncthing-logo.svg` — the logo as published by the Syncthing project
- `install/Amisync.info` — Amiga icon converted from it
- `install/Install.info` — Amiga icon converted from it

From [Syncthing](https://github.com/syncthing/syncthing), Copyright (C) the
Syncthing Authors, licensed under the [Mozilla Public
License 2.0](https://mozilla.org/MPL/2.0/). The conversion to Amiga icon
format changes the encoding only; no other change was made and no copyright
is asserted over the conversion. MPL-2.0 is a per-file licence, so these
files remain MPL-2.0 inside this otherwise-MIT project — which the MPL
explicitly permits for a "Larger Work".

Syncthing is a trademark of the Syncthing Foundation. AmiSync is an
independent project, not affiliated with or endorsed by Syncthing.

## Not bundled

These are build- or run-time dependencies, obtained separately, and no part
of them is included in this repository:

- **AmiSSL** — TLS at runtime. https://github.com/jens-maus/amissl
- **amiga-gcc** (Bebbo) with libnix, and the SDI headers — build only.
  See [BUILDING.md](BUILDING.md).

SHA-256 comes from AmiSSL at runtime; no hash implementation is vendored.
