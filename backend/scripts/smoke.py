import asyncio, json, sys
from app.config import Settings
from app.db import DB
from app.engine import analyze
from app import demo_fixtures
s = Settings(demo_mode=True, online_checks=False, feeds=False)
db = DB(":memory:"); demo_fixtures.seed(db)
samples = [
 ("https://onlinesbi.sbi.bank.in/", "check"),
 ("upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store", "pay_shop"),
 ("upi://pay?pa=refund.desk2291@ybl&pn=Amazon%20Refund%20Dept&am=4999.00&cu=INR&tn=Scan%20to%20receive%20your%20refund", "check"),
 ("upi://pay?pa=sbi.kyc.update@okaxisbank&pn=SBI%20KYC%20Helpdesk&am=10&tn=KYC%20verification%20fee%20to%20unblock%20account", "check"),
 ("upi://mandate?pa=subs.collect@ybl&pn=Cashback%20Activation&am=9999&amrule=MAX&recur=ASPRESENTED&validitystart=09102026&validityend=09102036&rev=N&purpose=14&mode=13&txnType=CREATE&tn=Activate%20cashback", "check"),
 ("https://onlinesbl.test/kyc-update/login", "check"),
 ("http://qrs.test/x7Kp", "check"),
 ("https://echallan-parivahan.test/pay/mParivahan.apk", "check"),
 ("WIFI:S:RailWire_Free;T:nopass;;", "check"),
 ("WIFI:S:Sharma_Home;T:WPA;P:secret123;;", "check"),
 ("tel:*401*9876543210#", "check"),
 ("https://onlinesbі.test/login", "check"),
 ("upi://pay?pa=kbc.lottery.dept@axl&pn=KBC%20Lottery%20Winner&am=12500&tn=GST%20charge%20to%20release%20prize%20Rs%2025%20lakh", "check"),
 ("http://free-recharge-offer.test/jio-399-free", "check"),
 ("upi://pay?pa=qrshield.demo.kirana@ybl&pn=Ramesh%20Kirana%20Store", "receive"),
 ("https://www.irctc.co.in/nget/train-search", "check"),
 ("Hello, meet at 5pm", "check"),
]
async def main():
    for p, intent in samples:
        r = await analyze(p, intent, "camera", db, s)
        print(f"{r['verdict']:8} {r['score']:3}  {r['kind']:12} {p[:60]}")
        for sig in r['signals']:
            print(f"           {sig['weight']:4} {sig['code']}")
asyncio.run(main())
