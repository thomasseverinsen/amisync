#!/usr/bin/env python3
"""Render the official Syncthing logo SVG into an AmigaOS .info icon file.

The SVG (assets/syncthing-logo.svg) is assets/logo-only.svg from
https://github.com/syncthing/syncthing, MPL-2.0; see "Third-party content"
in the README.

Output is a dual-format icon:
  * classic planar part (struct DiskObject + 2-bitplane 4-colour image) that
    any icon.library since OS 2.x can render - pens 0/1/2/3 of the standard
    Workbench palette;
  * appended IFF "FORM ICON" (the OS 3.5 / GlowIcons format, understood by
    icon.library V44+, i.e. OS 3.5/3.9/3.2, PeterK's replacement, OS4/MorphOS)
    with two 256-colour palette-mapped states (normal + brightened when
    selected), quantized from a Lanczos-downscaled high-resolution rasterize
    of the SVG. Antialiased edges are pre-composited against Workbench grey
    (the format has a single transparent index, no alpha channel).

Usage: genglowicon.py <logo.svg> <out.info> [<preview-dir>]

Requires: Pillow, rsvg-convert. Deliberately writes both IMAG chunks
uncompressed (the format's compression field is 0): simpler and
unambiguous, and the whole file is still only ~7 KB.
"""
import io
import struct
import subprocess
import sys

from PIL import Image, ImageEnhance

SIZE      = 46                  # icon edge, GlowIcons-conventional
SUPER     = 8                   # rasterize at SIZE*SUPER then Lanczos down
WB_GREY   = (170, 170, 170)     # backdrop colour antialiased edges blend to
SEL_BOOST = 1.35                # brightness factor for the selected state

# Classic 4-colour Workbench palette for the planar fallback image.
WB4 = ((170, 170, 170), (0, 0, 0), (255, 255, 255), (102, 136, 187))

NO_ICON_POSITION = 0x80000000

LANCZOS = getattr(getattr(Image, "Resampling", Image), "LANCZOS")


def rasterize(svg_path):
    """SVG -> RGBA Image at SIZE x SIZE via supersampled rsvg + Lanczos."""
    hi = SIZE * SUPER
    png = subprocess.run(
        ["rsvg-convert", "-w", str(hi), "-h", str(hi), svg_path],
        capture_output=True, check=True).stdout
    return Image.open(io.BytesIO(png)).convert("RGBA").resize(
        (SIZE, SIZE), LANCZOS)


def flatten(rgba):
    """Composite over Workbench grey; return (RGB image, alpha mask)."""
    rgb = Image.new("RGB", rgba.size, WB_GREY)
    rgb.paste(rgba, mask=rgba.split()[3])
    return rgb, rgba.split()[3]


def quantize_states(normal_rgb, selected_rgb):
    """Joint 255-colour quantize (index 0 is reserved for transparency).
    Returns (palette bytes: 256 RGB triples, normal indices, selected
    indices) with all indices shifted up by one."""
    combo = Image.new("RGB", (SIZE * 2, SIZE))
    combo.paste(normal_rgb, (0, 0))
    combo.paste(selected_rgb, (SIZE, 0))
    q = combo.quantize(colors=255)
    pal = q.getpalette()[:255 * 3]
    pal += [0] * (255 * 3 - len(pal))
    palette = bytes(WB_GREY) + bytes(pal)          # entry 0: unused/grey
    qpx = q.load()
    normal = [[qpx[x, y] + 1 for x in range(SIZE)] for y in range(SIZE)]
    sel = [[qpx[x + SIZE, y] + 1 for x in range(SIZE)] for y in range(SIZE)]
    return palette, normal, sel


def apply_transparency(indices, alpha):
    """Force index 0 wherever the source pixel was (mostly) transparent."""
    a = alpha.load()
    for y in range(SIZE):
        for x in range(SIZE):
            if a[x, y] < 128:
                indices[y][x] = 0


def planar_fallback(normal_rgb, alpha):
    """Map the flattened render onto WB pens 0..3, planar-encoded, 2 planes."""
    rgb = normal_rgb.load()
    a = alpha.load()
    pens = [[0] * SIZE for _ in range(SIZE)]
    for y in range(SIZE):
        for x in range(SIZE):
            if a[x, y] < 128:
                continue                            # pen 0: background
            r, g, b = rgb[x, y]
            best = min(range(4), key=lambda i: (r - WB4[i][0]) ** 2 +
                       (g - WB4[i][1]) ** 2 + (b - WB4[i][2]) ** 2)
            pens[y][x] = best
    words_per_row = (SIZE + 15) // 16
    data = bytearray()
    for plane in range(2):
        for y in range(SIZE):
            for wx in range(words_per_row):
                w = 0
                for bit in range(16):
                    x = wx * 16 + bit
                    if x < SIZE and (pens[y][x] >> plane) & 1:
                        w |= 1 << (15 - bit)
                data += struct.pack(">H", w)
    return bytes(data), pens


# ---------------------------------------------------------------------------
# Classic .info writer (struct DiskObject et al., big-endian m68k layout)
# ---------------------------------------------------------------------------

def classic_info(planar):
    gadget = struct.pack(">IhhhhHHHIIIiIHI",
                         0,                    # NextGadget
                         0, 0, SIZE, SIZE,     # LeftEdge/TopEdge/Width/Height
                         0x0004,               # Flags: GFLG_GADGIMAGE (+GADGHCOMP)
                         0x0003,               # Activation: RELVERIFY|IMMEDIATE
                         0x0001,               # GadgetType: BOOLGADGET
                         1,                    # GadgetRender: non-NULL flag
                         0,                    # SelectRender: none (complement)
                         0, 0, 0, 0,           # GadgetText/MutualExclude/SpecialInfo/GadgetID
                         1)                    # UserData: WB_DISKREVISION
    dobj = struct.pack(">HH", 0xE310, 1)       # do_Magic, do_Version
    dobj += gadget
    dobj += struct.pack(">BxIIiiIIi",
                        3,                     # do_Type: WBTOOL (+ pad byte)
                        0, 0,                  # DefaultTool, ToolTypes: none
                        NO_ICON_POSITION - (1 << 32),   # do_CurrentX (signed)
                        NO_ICON_POSITION - (1 << 32),   # do_CurrentY
                        0, 0,                  # DrawerData, ToolWindow
                        # do_StackSize: a Workbench double-click runs the
                        # daemon in THIS process, on exactly this stack, so it
                        # must match DAEMON_STACK in src/main.c. The old 8192
                        # was under half of what answering a single STATUS
                        # needs. main() now refuses (and relaunches) rather
                        # than overflow, but a correct icon means it never has
                        # to.
                        131072)                # do_StackSize
    assert len(dobj) == 78, len(dobj)
    image = struct.pack(">hhhhhIBBI",
                        0, 0, SIZE, SIZE, 2,   # LeftEdge/TopEdge/W/H/Depth
                        1,                     # ImageData: non-NULL flag
                        0x03, 0x00,            # PlanePick, PlaneOnOff
                        0)                     # NextImage
    assert len(image) == 20, len(image)
    return dobj + image + planar


# ---------------------------------------------------------------------------
# OS 3.5 "FORM ICON" writer
# ---------------------------------------------------------------------------

def chunk(ckid, payload):
    data = ckid + struct.pack(">I", len(payload)) + payload
    if len(payload) & 1:
        data += b"\0"                          # IFF chunks are even-padded
    return data


def imag_chunk(indices, palette):
    pixels = bytes(indices[y][x] for y in range(SIZE) for x in range(SIZE))
    payload = struct.pack(">BBBBBBHH",
                          0,                   # transparent colour index
                          255,                 # colours - 1 (256)
                          0x03,                # flags: transparent + palette
                          0, 0,                # image/palette: uncompressed
                          8,                   # depth: 8 bits per pixel
                          len(pixels) - 1,
                          len(palette) - 1)
    return chunk(b"IMAG", payload + pixels + palette)


def form_icon(normal, selected, palette):
    face = chunk(b"FACE", struct.pack(">BBBBH",
                                      SIZE - 1, SIZE - 1,
                                      0,                 # flags: bordered
                                      0x11,              # aspect 1:1
                                      len(palette) - 1))
    body = b"ICON" + face + imag_chunk(normal, palette) \
                         + imag_chunk(selected, palette)
    return b"FORM" + struct.pack(">I", len(body)) + body


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    svg_path, out_path = sys.argv[1], sys.argv[2]
    preview_dir = sys.argv[3] if len(sys.argv) > 3 else None

    rgba = rasterize(svg_path)
    normal_rgb, alpha = flatten(rgba)
    selected_rgb = ImageEnhance.Brightness(normal_rgb).enhance(SEL_BOOST)

    palette, normal, selected = quantize_states(normal_rgb, selected_rgb)
    apply_transparency(normal, alpha)
    apply_transparency(selected, alpha)
    planar, pens = planar_fallback(normal_rgb, alpha)

    data = classic_info(planar) + form_icon(normal, selected, palette)
    with open(out_path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes: classic %d + FORM ICON %d)" %
          (out_path, len(data), len(classic_info(planar)),
           len(form_icon(normal, selected, palette))))

    if preview_dir:
        def render(indices):
            im = Image.new("RGB", (SIZE, SIZE))
            p = im.load()
            for y in range(SIZE):
                for x in range(SIZE):
                    i = indices[y][x]
                    p[x, y] = WB_GREY if i == 0 else tuple(
                        palette[i * 3:i * 3 + 3])
            return im.resize((SIZE * 6, SIZE * 6), Image.NEAREST)
        render(normal).save(preview_dir + "/preview-normal.png")
        render(selected).save(preview_dir + "/preview-selected.png")
        fb = Image.new("RGB", (SIZE, SIZE))
        p = fb.load()
        for y in range(SIZE):
            for x in range(SIZE):
                p[x, y] = WB4[pens[y][x]]
        fb.resize((SIZE * 6, SIZE * 6), Image.NEAREST).save(
            preview_dir + "/preview-fallback.png")
        print("previews in", preview_dir)


if __name__ == "__main__":
    main()
