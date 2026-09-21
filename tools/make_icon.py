"""Generates assets/icon.ico + assets/icon.png (needs Pillow: pip install pillow).

    python tools/make_icon.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

S = 1024
OUT = Path(__file__).resolve().parent.parent / "assets"


def vgradient(size, top, bottom):
    w, h = size
    img = Image.new("RGBA", size)
    px = img.load()
    for y in range(h):
        t = y / max(h - 1, 1)
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,)
        for x in range(w):
            px[x, y] = c
    return img


def rounded_mask(size, box, radius):
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).rounded_rectangle(box, radius=radius, fill=255)
    return m


def build() -> Image.Image:
    # background tile
    tile = vgradient((S, S), (22, 31, 50), (9, 13, 22))
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    canvas.paste(tile, (0, 0), rounded_mask((S, S), (24, 24, S - 24, S - 24), 230))

    # soft amber glow behind the lock
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((222, 250, 802, 830), fill=(242, 181, 68, 95))
    glow = glow.filter(ImageFilter.GaussianBlur(70))
    canvas = Image.alpha_composite(canvas, glow)

    lock = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    amber_top, amber_bot = (255, 214, 130), (226, 152, 36)
    grad = vgradient((S, S), amber_top, amber_bot)

    # body
    body = rounded_mask((S, S), (262, 458, 762, 838), 78)
    lock.paste(grad, (0, 0), body)

    # open shackle: PIL draws arc thickness inwards from the bbox, so work with the outer radius
    sh = Image.new("L", (S, S), 0)
    d = ImageDraw.Draw(sh)
    w = 62
    cx, cy, ro = 512, 384, 176
    d.arc((cx - ro, cy - ro, cx + ro, cy + ro), 180, 360, fill=255, width=w)
    d.rectangle((cx - ro, cy, cx - ro + w, 500), fill=255)                        # left leg -> into body
    d.rectangle((cx + ro - w, cy, cx + ro, cy + 46), fill=255)                    # right leg (lifted, short)
    d.ellipse((cx + ro - w, cy + 46 - w // 2, cx + ro, cy + 46 + w // 2), fill=255)
    lock.paste(grad, (0, 0), sh)

    # keyhole cut in ink colour
    kd = ImageDraw.Draw(lock)
    ink = (13, 19, 32, 255)
    kd.ellipse((512 - 50, 594 - 50, 512 + 50, 594 + 50), fill=ink)
    kd.polygon([(512 - 30, 618), (512 + 30, 618), (512 + 46, 730), (512 - 46, 730)], fill=ink)

    canvas = Image.alpha_composite(canvas, lock)

    # teal "layer" bars under the lock: the peeled encodings
    tk = ImageDraw.Draw(canvas)
    teal = (79, 209, 197, 255)
    for i, wd in enumerate((330, 220, 120)):
        y = 872 + i * 34
        tk.rounded_rectangle((512 - wd // 2, y, 512 + wd // 2, y + 16), radius=8, fill=teal)
    # thin ring
    ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(ring).rounded_rectangle((24, 24, S - 24, S - 24), radius=230, outline=(242, 181, 68, 120), width=6)
    return Image.alpha_composite(canvas, ring)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    big = build()
    big.resize((512, 512), Image.LANCZOS).save(OUT / "icon.png")
    big.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("wrote", OUT / "icon.ico", "and", OUT / "icon.png")
