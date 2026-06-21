"""Generate the tray icons from git-compare.svg (Hugeicons, MIT), themed for
light/dark taskbars, as multi-resolution .ico files.

  git-dark.ico   periwinkle glyph, for DARK taskbars
  git-light.ico  deep-indigo glyph, for LIGHT taskbars

Rasterizes with the `resvg` CLI (pure-Rust, no native deps): `cargo install resvg`.
Then `python generate.py` (needs Pillow). Outputs next to this file.
Source SVG: Hugeicons "git-compare" (MIT); see NOTICE.md.
"""

import os
import subprocess
import tempfile
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SVG = os.path.join(HERE, "git-compare.svg")
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
RENDER = 1024  # rasterize large, then downsample for crisp small sizes

# Match native Windows notification-area icons: monochrome, contrasting with the
# taskbar - white on a dark taskbar, near-black on a light one.
DARK_TASKBAR = "#ffffff"   # white, for a dark taskbar
LIGHT_TASKBAR = "#1c1c1c"  # near-black, for a light taskbar


def themed_svg(color):
    # Hugeicons strokes with currentColor; bind it to the theme color so resvg
    # (which renders currentColor as black) draws the glyph in our color.
    with open(SVG, encoding="utf-8") as f:
        return f.read().replace("currentColor", color)


def write_ico(color, name):
    with tempfile.TemporaryDirectory() as td:
        svg_path = os.path.join(td, "in.svg")
        png_path = os.path.join(td, "out.png")
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(themed_svg(color))
        subprocess.run(["resvg", "--width", str(RENDER), svg_path, png_path], check=True)
        master = Image.open(png_path).convert("RGBA").resize((256, 256), Image.LANCZOS)
    out = os.path.join(HERE, name)
    master.save(out, format="ICO", sizes=[(s, s) for s in SIZES])
    print("wrote", out)


if __name__ == "__main__":
    write_ico(DARK_TASKBAR, "git-dark.ico")
    write_ico(LIGHT_TASKBAR, "git-light.ico")
