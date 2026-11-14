"""Turn the screenshots from shoot.js into docs/maze-demo.gif and docs/maze-journey.png.

usage: python tools/demo/compose.py <frames-dir> <out-dir>   (needs Pillow and the Inter font)
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FRAMES = Path(sys.argv[1])
OUT = Path(sys.argv[2])
FONT_DIR = "/usr/share/fonts/opentype/inter/"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def font(weight, size):
    return ImageFont.truetype(FONT_DIR + f"Inter-{weight}.otf", size)


INK = (24, 27, 34)
MUTED = (95, 102, 118)
ACCENT = (110, 86, 207)      # violet: the maze
DANGER = (209, 36, 47)
CHROME = (232, 234, 238)
BG = (246, 247, 249)

# (frame, step title, what the attacker typed or did, what it means)
STEPS = [
    ("1-start", "An attacker finds a login page", None, "Nothing marks it as a trap."),
    ("2-wrong", "First guess", "123456", "Wrong. Every failure makes the next reply slower: 1, 2, 4, 8 s."),
    ("3-decoy1", "A password from a leaked list", "admin123", "It is a decoy: “First password found.” It seems to work."),
    ("4-decoy2", "Another decoy", "SuperSecret99", "Stage 3 of 3. One password to go…"),
    ("5-final-wrong", "The final stage", "root!2024", "Only the real password opens it, and every guess takes the same time."),
    ("6-exit", "The attacker tries to leave", None, "The “exit” asks to confirm the passwords found so far."),
    ("7-back", "Confirms them", "admin123 | SuperSecret99", "Back to Stage 1. Every move was logged for the Minator report."),
]


def crop_card(path):
    """The page is a centered card; keep it with a margin (screenshots are 1120x1040 at 2x)."""
    image = Image.open(path).convert("RGB")
    return image.crop((96, 64, 1024, 1000))


def browser(card, width):
    """A plain browser window around the page: tab strip and address bar."""
    scale = width / card.width
    card = card.resize((width, round(card.height * scale)), Image.LANCZOS)
    bar = 56
    window = Image.new("RGB", (width, card.height + bar), BG)
    draw = ImageDraw.Draw(window)
    draw.rectangle((0, 0, width, bar), fill=CHROME)
    for i, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        draw.ellipse((18 + i * 22, 21, 32 + i * 22, 35), fill=color)
    draw.rounded_rectangle((100, 13, width - 20, bar - 13), radius=15, fill=(255, 255, 255))
    draw.text((118, bar // 2), "http://portal.example/", fill=MUTED, font=font("Regular", 16), anchor="lm")
    window.paste(card, (0, bar))
    return window


def frame(index, step, width=760):
    name, title, typed, meaning = step
    shot = browser(crop_card(FRAMES / f"{name}.png"), width - 48)
    header = 150
    canvas = Image.new("RGB", (width, header + shot.height + 64), (255, 255, 255))
    draw = ImageDraw.Draw(canvas)
    # step badge
    draw.ellipse((24, 26, 64, 66), fill=ACCENT)
    draw.text((44, 46), str(index + 1), fill=(255, 255, 255), font=font("SemiBold", 20), anchor="mm")
    draw.text((80, 32), title, fill=INK, font=font("SemiBold", 26))
    y = 78
    if typed:
        label = "types "
        draw.text((80, y), label, fill=MUTED, font=font("Regular", 19))
        x = 80 + draw.textlength(label, font=font("Regular", 19))
        mono = ImageFont.truetype(MONO, 18)
        w = draw.textlength(typed, font=mono)
        draw.rounded_rectangle((x - 2, y - 3, x + w + 14, y + 27), radius=6, fill=(241, 238, 252))
        draw.text((x + 6, y + 1), typed, fill=ACCENT, font=mono)
        y += 36
    draw.text((80, y), meaning, fill=MUTED, font=font("Regular", 19))
    # window with a soft border
    top = header
    canvas.paste(shot, (24, top))
    draw.rounded_rectangle((23, top - 1, 24 + shot.width, top + shot.height), radius=10, outline=(216, 219, 226), width=2)
    # progress dots
    dots_y = top + shot.height + 32
    total = len(STEPS)
    start = width // 2 - (total - 1) * 11
    for i in range(total):
        cx = start + i * 22
        fill = ACCENT if i == index else (216, 219, 226)
        draw.ellipse((cx - 5, dots_y - 5, cx + 5, dots_y + 5), fill=fill)
    return canvas


frames = [frame(i, s) for i, s in enumerate(STEPS)]
height = max(f.height for f in frames)
frames = [f if f.height == height else f.crop((0, 0, f.width, height)) for f in frames]
durations = [2600, 2400, 2800, 2400, 3200, 2600, 3600]
gif_frames = [f.convert("P", palette=Image.ADAPTIVE, colors=256) for f in frames]
gif_frames[0].save(OUT / "maze-demo.gif", save_all=True, append_images=gif_frames[1:], duration=durations,
                   loop=0, optimize=True, disposal=2)

# Storyboard: 4 + 3 panels, small, with the arrow of the journey.
thumb_w = 380
thumbs = [f.resize((thumb_w, round(f.height * thumb_w / f.width)), Image.LANCZOS) for f in frames]
gap = 18
cols = 4
rows = 2
th = thumbs[0].height
board = Image.new("RGB", (cols * thumb_w + (cols + 1) * gap, rows * th + (rows + 1) * gap + 70), (255, 255, 255))
d = ImageDraw.Draw(board)
d.text((gap, 22), "An attacker's walk through Maze", fill=INK, font=font("SemiBold", 28))
d.text((gap + 470, 30), "real screenshots, demo decoys", fill=MUTED, font=font("Regular", 18))
for i, t in enumerate(thumbs):
    r, c = divmod(i, cols)
    x = gap + c * (thumb_w + gap)
    y = 70 + gap + r * (th + gap)
    board.paste(t, (x, y))
    d.rounded_rectangle((x - 1, y - 1, x + thumb_w, y + th), radius=8, outline=(216, 219, 226), width=2)
# last cell: what the defender gets
x = gap + 3 * (thumb_w + gap)
y = 70 + gap + th + gap
d.rounded_rectangle((x, y, x + thumb_w, y + th), radius=8, fill=(246, 244, 253), outline=ACCENT, width=2)
lines = [("SemiBold", 24, INK, "Meanwhile, the defender"),
         ("Regular", 19, MUTED, "gets every guess, decoy and exit"),
         ("Regular", 19, MUTED, "attempt in the log, and a Minator"),
         ("Regular", 19, MUTED, "report: who, how long they were"),
         ("Regular", 19, MUTED, "kept busy, bot or human, which"),
         ("Regular", 19, MUTED, "wordlist they used."),
         ("SemiBold", 19, ACCENT, "python -m app.report")]
ty = y + 40
for weight, size, color, text in lines:
    f = ImageFont.truetype(MONO, 17) if text.startswith("python") else font(weight, size)
    d.text((x + 24, ty), text, fill=color, font=f)
    ty += 40 if size > 20 else 30
board.save(OUT / "maze-journey.png", optimize=True)
print("gif", (OUT / "maze-demo.gif").stat().st_size // 1024, "KB", frames[0].size,
      "| board", (OUT / "maze-journey.png").stat().st_size // 1024, "KB", board.size)
