"""Generate assets/nightrelay.ico -- a neon mark for the NightRelay window.

Run once; the .ico is committed next to the build script.

    python assets/make_icon.py
"""

from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

OUT = Path(__file__).resolve().parent / "nightrelay.ico"
SIZE = 512

VIOLET = (139, 92, 246)
CYAN = (34, 211, 238)
BG_TOP = (12, 12, 22)
BG_BOTTOM = (6, 6, 11)


def gradient(size: int, top: tuple, bottom: tuple) -> Image.Image:
    img = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        img.putpixel((0, y), tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return img.resize((size, size))


def diagonal(size: int, a: tuple, b: tuple) -> Image.Image:
    """Diagonal violet->cyan wash used for the glow and the rule."""
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1))
            px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return img


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("arialbd.ttf", "seguisb.ttf", "segoeuib.ttf", "calibrib.ttf"):
        path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / name
        if path.is_file():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def main() -> None:
    base = gradient(SIZE, BG_TOP, BG_BOTTOM).convert("RGBA")

    # rounded mask
    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, SIZE - 1, SIZE - 1), radius=int(SIZE * 0.22), fill=255)
    base.putalpha(mask)

    # outer glow
    glow = diagonal(SIZE, VIOLET, CYAN).convert("RGBA")
    ring = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(ring).rounded_rectangle(
        (int(SIZE * 0.035), int(SIZE * 0.035), SIZE - int(SIZE * 0.035), SIZE - int(SIZE * 0.035)),
        radius=int(SIZE * 0.2),
        outline=255,
        width=int(SIZE * 0.028),
    )
    glow.putalpha(ring.filter(ImageFilter.GaussianBlur(SIZE * 0.012)))
    base = Image.alpha_composite(base, glow)

    # relay chevrons behind the mark
    layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    for i, offset in enumerate((0.30, 0.44, 0.58)):
        alpha = 70 - i * 18
        x = int(SIZE * offset)
        draw.line(
            [(x, int(SIZE * 0.34)), (x + int(SIZE * 0.10), int(SIZE * 0.5)), (x, int(SIZE * 0.66))],
            fill=(*CYAN, max(alpha, 12)),
            width=int(SIZE * 0.016),
            joint="curve",
        )
    base = Image.alpha_composite(base, layer)

    # monogram
    text = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    tdraw = ImageDraw.Draw(text)
    font = load_font(int(SIZE * 0.40))
    label = "NR"
    box = tdraw.textbbox((0, 0), label, font=font)
    tdraw.text(
        ((SIZE - (box[2] - box[0])) / 2 - box[0], (SIZE - (box[3] - box[1])) / 2 - box[1] - SIZE * 0.01),
        label,
        font=font,
        fill=(255, 255, 255, 240),
        stroke_width=int(SIZE * 0.006),
        stroke_fill=(20, 12, 40, 255),
    )
    base = Image.alpha_composite(base, text)

    base.save(OUT, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    base.resize((256, 256), Image.LANCZOS).save(OUT.with_suffix(".png"))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
