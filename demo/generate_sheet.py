"""Generate demo/sheet.html: a printable A4 sheet of all demo QR codes."""
import html
import pathlib
import sys

import segno

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from samples import SAMPLES, SHOP_GENUINE, SHOP_SWAPPED  # noqa: E402

COL = {"SAFE": "#16a34a", "CAUTION": "#d97706", "DANGER": "#dc2626", "SHOP": "#0d9488"}


def svg(payload: str) -> str:
    return segno.make(payload, error="m").svg_inline(scale=4, border=2)


cards = []
items = [(i, t, p, it, v, n) for i, t, p, it, v, n in SAMPLES if i != "D11"]
items += [("SH1", "Shop: genuine sticker", SHOP_GENUINE, "", "SHOP", "Register this in My Shop tab"),
          ("SH2", "Shop: SWAPPED sticker", SHOP_SWAPPED, "", "SHOP", "Then scan this: 'NOT your QR!'")]
for sid, title, payload, intent, verdict, note in items:
    cards.append(f"""<div class="card"><div class="qr">{svg(payload)}</div>
<div class="id" style="background:{COL[verdict]}">{sid}</div><b>{html.escape(title)}</b>
<small>Expected: <span style="color:{COL[verdict]}">{verdict if verdict != 'SHOP' else 'shop mode'}</span></small>
<p>{html.escape(note)}</p></div>""")

page = f"""<!doctype html><html><head><meta charset="utf-8"><title>QR Shield demo sheet</title>
<style>
@page {{ size: A4; margin: 10mm; }}
body {{ font: 12px system-ui, Segoe UI, sans-serif; margin: 0; color: #111; }}
h1 {{ font-size: 18px; margin: 0 0 4px; }} .sub {{ color: #555; margin: 0 0 10px; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }}
.card {{ border: 1px solid #ccc; border-radius: 8px; padding: 6px; text-align: center; break-inside: avoid; position: relative; }}
.qr svg {{ width: 100%; height: auto; max-width: 150px; }}
.id {{ position: absolute; top: 4px; left: 4px; color: #fff; font-weight: 700; padding: 1px 6px; border-radius: 4px; }}
b {{ display: block; font-size: 12px; }} small {{ display: block; font-weight: 600; }} p {{ margin: 3px 0 0; color: #444; font-size: 10px; }}
</style></head><body>
<h1>QR Shield — live demo sheet</h1>
<p class="sub">Malicious samples use reserved <code>.test</code> domains and fake UPI IDs (DEMO_MODE). D11: choose “Receiving money”, then scan S2.</p>
<div class="grid">{''.join(cards)}</div></body></html>"""
out = pathlib.Path(__file__).parent / "sheet.html"
out.write_text(page, encoding="utf-8")
print("wrote", out)
