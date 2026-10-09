"""Known UPI PSP handles (the part after '@' in a VPA).

Sources and tiering: docs/research/02_upi_spec.md section 5.
Tier A / A2 come from NPCI's own 3rd-party-app and PPI lists, tier B from the
NPCI/SEBI "UPI apps live on IPO" list, tier C from aggregators and legacy banks.
"""

TIER_A_TPAP = set("""
abcdicici apl rapl yapl abfspay bpunity jarunity cqaxis yescred axisb yescurie yesfam fvaxis
fkaxis freoicici gsaxis okaxis okhdfcbank okicici oksbi yesg hfaxis inhdfc jpyes jupiteraxis
goaxb kbaxis kphdfc ikwik mbkns mvhdfc mlyes naviaxis nyes nvdcb lxaxis oneyes paytm ptyes
pthdfc ptsbi ptaxis ybl ibl axl yespop rpaxis rfunity rmrbl pingpay seyes pnyes tlaxis
shriramhdfcbank smyes sfunity superyes tapicici tnaxis timecosmos axisbank waicici icici waaxis
wahdfcbank wasbi ztrbl
""".split())

TIER_A2_PPI = set("""
pockets idfcpay amazonpay spicepay omni dhani bpaywallet trans fam pinelabs mbk digikhata liv
paymoni nye payu ebixcash tbl paulpay obopay phonepe yesgo mufin topay payworld tapay pzw cred
jupiter imoney zokudo revolut makash thecardco mswipe yourisg enkash
""".split())

TIER_B_BANK_APPS = set("""
upi barodampay idbi aubank bandhan dlb indus indie kbl federal pnb sbi uco citi citigold dbs
freecharge hsbc indianbank allbank kotak unionbankofindia uboi unionbank pz sib yespay tmb slc
""".split())

TIER_C_AGGREGATOR = set("""
hdfcbank yesbank rbl boi cnrb centralbank mahb iob psb jkb kvb equitas finobank airtel mairtel
jio csbpay scb s2b jsb tjsb dcb kmbl kaypay myicici zoicici hdfcbankjd rmhdfcbank axisgo
sliceaxis fbl nsdl postbank barodamp bob okhdfc fifederal idfcbank icic fbpe unitype
andb denabank lvb obc syndicate united ubi utbi vijb
""".split())

KNOWN_HANDLES = TIER_A_TPAP | TIER_A2_PPI | TIER_B_BANK_APPS | TIER_C_AGGREGATOR

# Consumer app handles: anyone can create a VPA here in seconds, so an
# "official" name on one of these is a red flag.
CONSUMER_HANDLES = TIER_A_TPAP | TIER_A2_PPI | {"upi"}

# Real, official collection VPAs that scammers imitate (PM CARES lookalikes were
# documented in 2020: docs/research/01_scam_patterns.md pattern 11).
OFFICIAL_VPAS = {
    "pmcares@sbi": "PM CARES Fund",
    "pmnrf@sbi": "PM National Relief Fund",
}


def handle_tier(handle: str) -> str | None:
    h = handle.lower()
    if h in TIER_A_TPAP or h in TIER_A2_PPI:
        return "npci"
    if h in TIER_B_BANK_APPS:
        return "bank"
    if h in TIER_C_AGGREGATOR:
        return "aggregator"
    if h.startswith("valid") and len(h) > 5 and h[5:].isalpha():
        return "sebi_valid"
    return None
