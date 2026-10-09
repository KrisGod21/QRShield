"""End-to-end check: POST every demo QR to a running server and compare verdicts.

Usage: python demo/verify_demo.py [base_url]   (default http://127.0.0.1:8000)
"""
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from samples import SAMPLES, SHOP_GENUINE, SHOP_SWAPPED  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


fails = 0
for sid, title, payload, intent, expected, _ in SAMPLES:
    r = post("/api/analyze", {"payload": payload, "intent": intent, "source": "camera"})
    ok = r["verdict"] == expected
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {sid:4} {title:42} {r['verdict']:8} score={r['score']:3} {r['elapsed_ms']:4} ms")

shop = post("/api/shop/register", {"payload": SHOP_GENUINE, "shop_name": "Ramesh Kirana"})
good = post("/api/shop/verify", {"payload": SHOP_GENUINE, "shop_code": shop["shop_code"]})
bad = post("/api/shop/verify", {"payload": SHOP_SWAPPED, "shop_code": shop["shop_code"]})
for name, res, want in (("SH1 genuine sticker", good, True), ("SH2 swapped sticker", bad, False)):
    ok = res["match"] is want
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name:47} match={res['match']}")
print("\nALL PASS" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
