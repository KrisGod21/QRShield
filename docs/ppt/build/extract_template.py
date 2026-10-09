"""Extract clean background + header assets from the CodeAstra 2.0 template PDF.

Outputs into build/assets/:
  bg_title.jpg     - page 1 dawn-sky background (no text)
  bg_content.jpg   - page 2 starry background (pages 2-6 share it)
  header_mct.png   - "MCT / Manjara Charitable Trust / RGIT Mumbai" header (RGBA)
  codeastra.png    - CODEASTRA 2.0 wordmark (page 1 only, RGBA)
  logo_abit.png    - ABIT logo (RGBA)
  logo_synergy.png - SYNERGY logo (RGBA)
and prints each image's placement rect (PDF points, page = 1440 x 810).
"""
import hashlib
import os
import sys

import pymupdf

HERE = os.path.dirname(os.path.abspath(__file__))
PDF = os.path.join(HERE, "..", "..", "codeastra_template.pdf")
OUT = os.path.join(HERE, "assets")
os.makedirs(OUT, exist_ok=True)

doc = pymupdf.open(PDF)


def save_rgba(xref, smask, path):
    pix = pymupdf.Pixmap(doc, xref)
    if smask:
        mask = pymupdf.Pixmap(doc, smask)
        pix = pymupdf.Pixmap(pix, mask)
    if pix.colorspace and pix.colorspace.n not in (1, 3):
        pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
    pix.save(path)


def save_raw(xref, path):
    info = doc.extract_image(xref)
    with open(path, "wb") as f:
        f.write(info["image"])
    return hashlib.md5(info["image"]).hexdigest()


# page 1
p1 = doc[0]
imgs = {im[0]: im for im in p1.get_images(full=True)}
by_size = {(im[2], im[3]): im for im in imgs.values()}
save_raw(by_size[(1600, 900)][0], os.path.join(OUT, "bg_title.jpg"))
for size, name in [((2260, 334), "header_mct.png"), ((1076, 717), "codeastra.png"),
                   ((444, 443), "logo_abit.png"), ((204, 226), "logo_synergy.png")]:
    im = by_size[size]
    save_rgba(im[0], im[1], os.path.join(OUT, name))
    print(name, p1.get_image_rects(im[0])[0])

# content pages 2-6: check whether backgrounds are identical
hashes = []
for i in range(1, 6):
    pg = doc[i]
    for im in pg.get_images(full=True):
        if (im[2], im[3]) == (1672, 940):
            h = save_raw(im[0], os.path.join(OUT, f"bg_page{i+1}.jpg"))
            hashes.append(h)
print("content bg hashes:", hashes)
if len(set(hashes)) == 1:
    os.replace(os.path.join(OUT, "bg_page2.jpg"), os.path.join(OUT, "bg_content.jpg"))
    for i in range(3, 7):
        os.remove(os.path.join(OUT, f"bg_page{i}.jpg"))
    print("all content backgrounds identical -> bg_content.jpg")
else:
    print("backgrounds differ; kept per-page files", file=sys.stderr)
