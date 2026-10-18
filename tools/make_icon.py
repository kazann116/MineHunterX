"""Генерирует иконку MineHunter X (src/App/MineHunter.ico): щит с лупой.

Каждый размер рисуется отдельно (а не уменьшается из 256 px), чтобы маленькие
значки в трее и заголовке окна оставались чёткими.
Запуск: python tools/make_icon.py
"""
import os
import struct
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'src', 'App', 'MineHunter.ico')
SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]

SHIELD = (22, 101, 192, 255)      # синий
SHIELD_EDGE = (12, 60, 120, 255)
LENS = (255, 255, 255, 255)
ACCENT = (255, 170, 0, 255)       # оранжевый — «находка»


def draw(size: int) -> Image.Image:
    scale = 4  # рисуем с запасом и уменьшаем — сглаживание краёв
    s = size * scale
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = s * 0.06
    w = s - 2 * pad
    top = pad
    # Щит: прямоугольная верхняя часть и заострённый низ.
    shield = [
        (pad, top + w * 0.08), (s / 2, top), (s - pad, top + w * 0.08),
        (s - pad, top + w * 0.52), (s / 2, s - pad), (pad, top + w * 0.52),
    ]
    edge = max(scale, s * 0.035)
    d.polygon(shield, fill=SHIELD, outline=SHIELD_EDGE, width=int(edge))
    # Лупа: кольцо и ручка; для мелких размеров линии толще.
    thick = s * (0.11 if size <= 24 else 0.085)
    cx, cy, r = s * 0.45, s * 0.43, s * 0.19
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=LENS, width=int(thick))
    hx, hy = cx + r * 0.72, cy + r * 0.72
    d.line([(hx, hy), (s * 0.73, s * 0.72)], fill=LENS, width=int(thick * 1.15))
    # Оранжевая точка внутри лупы — найденный «самородок».
    rr = r * 0.42
    d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=ACCENT)
    return img.resize((size, size), Image.LANCZOS)


def dib(img: Image.Image) -> bytes:
    """Изображение в формате DIB для ICO: BITMAPINFOHEADER, 32-битный BGRA снизу вверх, маска AND.
    Компилятор ресурсов RAD Studio (cgrc) не принимает значки, сжатые в PNG."""
    w, h = img.size
    header = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    px = img.load()
    rows = []
    for y in range(h - 1, -1, -1):
        row = bytearray()
        for x in range(w):
            r, g, b, a = px[x, y]
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    mask_stride = ((w + 31) // 32) * 4
    mask = bytes(mask_stride * h)  # прозрачность задаёт альфа-канал
    return header + b''.join(rows) + mask


def main():
    images = [draw(s) for s in SIZES]
    blobs = [dib(im) for im in images]
    out = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, blob in zip(SIZES, blobs):
        dim = 0 if size >= 256 else size
        out += struct.pack('<BBBBHHII', dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    out += b''.join(blobs)
    with open(OUT, 'wb') as f:
        f.write(out)
    images[-1].save(os.path.join(ROOT, 'docs', 'icon.png'))
    print('icon:', OUT, len(out), 'bytes')


if __name__ == '__main__':
    main()
