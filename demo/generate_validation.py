"""Generate scanner test images. Output is dev-only and excluded from Vite builds."""
import json
from pathlib import Path
import segno
from samples import SAMPLES

directory = Path(__file__).resolve().parents[1] / 'frontend' / 'tests' / 'fixtures'
directory.mkdir(parents=True, exist_ok=True)
cases = [dict(id=s[0], payload=s[2], intent=s[3], expected=s[4]) for s in SAMPLES]
cases.extend([
    dict(id='M1', payload='upi://mandate?pa=subscription@ybl&pn=Music%20Subscription&am=99&recur=MONTHLY&rev=Y', intent='check', expected='CAUTION'),
    dict(id='U1', payload='https://', intent='check', expected='CAUTION'),
    dict(id='X1', payload='javascript:alert(1)', intent='check', expected='DANGER'),
    dict(id='S4', payload='upi://pay?pa=shop@okaxis&pn=Corner%20Store&mc=5411&am=250&cu=INR', intent='pay_shop', expected='SAFE'),
    dict(id='T1', payload='https://onlinesbi.sbi.bank.in/?next=/a&next=/b', intent='check', expected='CAUTION'),
    dict(id='T2', payload='https://example.test/?next=https%253A%252F%252Fdownload.test%252Fpayload.apk', intent='check', expected='DANGER'),
    dict(id='T3', payload='upi://pay?pa=shop@ybl&pn=Shop&mc=ABCD', intent='pay_shop', expected='CAUTION'),
    dict(id='T4', payload='upi://pay?pa=shop@ybl&pn=Shop&am=10&mam=20', intent='pay_shop', expected='CAUTION'),
    dict(id='T5', payload='upi://pay?pa=shop@ybl&pn=Shop&pa=attacker@axl', intent='pay_shop', expected='CAUTION'),
    dict(id='T6', payload='upi://pay?pa=shop@ybl&pn=Shop%E2%80%AE', intent='pay_shop', expected='CAUTION'),
])
for i, entry in enumerate(cases):
    segno.make(entry['payload'], micro=False, error='m').save(directory / f"{entry['id']}.png", scale=[3, 5, 8][i % 3], border=4)
(directory / 'cases.json').write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Generated {len(cases)} validation QRs at {directory}')
