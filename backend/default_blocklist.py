"""
AutoRed — Default Blocklist Seeder
====================================
Seeds the scope_blocklist table with Malaysian critical
infrastructure, government, banking, healthcare, and private
IP ranges that should be blocked by default.

Sources referenced:
  - Bank Negara Malaysia (BNM) — Licensed financial institutions
    https://www.bnm.gov.my/list-of-licensed-financial-institutions
  - Securities Commission Malaysia (SC)
    https://www.sc.com.my
  - National Cyber Security Agency Malaysia (NACSA)
    https://www.nacsa.gov.my
  - Malaysian Communications and Multimedia Commission (MCMC)
    https://www.mcmc.gov.my
  - Ministry of Health Malaysia (MOH)
    https://www.moh.gov.my
  - RFC 1918 — Private IP address ranges
    https://tools.ietf.org/html/rfc1918

All entries use wildcard (*.domain) format so subdomains
are also blocked. Users can override any entry by adding
the specific target to the Authorized Targets list.

This seeder runs once on first install via scope.py _migrate().
It uses INSERT OR IGNORE so existing entries are never
overwritten — users who manually remove an entry won't
have it re-added on restart.
"""

DEFAULT_BLOCKLIST = [

    # ── Private / Reserved IP Ranges (RFC 1918) ───────────────
    # These are internal network ranges. Scanning them without
    # explicit authorization could disrupt internal systems.
    ("10.0.0.0/8",       "Private network range (RFC 1918) — requires explicit authorization"),
    ("172.16.0.0/12",    "Private network range (RFC 1918) — requires explicit authorization"),
    ("192.168.0.0/16",   "Private network range (RFC 1918) — requires explicit authorization"),
    ("127.0.0.0/8",      "Loopback address range — requires explicit authorization"),
    ("169.254.0.0/16",   "Link-local address range (RFC 3927) — requires explicit authorization"),
    ("0.0.0.0/8",        "Reserved IP range — scanning not permitted"),
    ("100.64.0.0/10",    "Shared address space (RFC 6598) — requires explicit authorization"),

    # ── Malaysian Federal Government (gov.my) ─────────────────
    # Source: Malaysian Government official domain structure
    # https://www.malaysia.gov.my
    ("*.gov.my",         "Malaysian government institution — written authorization required per NACSA guidelines"),
    ("*.mil.my",         "Malaysian Armed Forces — unauthorized scanning is a criminal offence under the Computer Crimes Act 1997"),
    ("*.edu.my",         "Malaysian public educational institution — requires institutional authorization"),
    ("*.net.my",         "Malaysian national network infrastructure — requires explicit authorization"),

    # ── Royal Malaysian Police (PDRM) ─────────────────────────
    ("*.polis.gov.my",   "Royal Malaysian Police (PDRM) — unauthorized scanning is a criminal offence"),
    ("polis.gov.my",     "Royal Malaysian Police (PDRM) — unauthorized scanning is a criminal offence"),

    # ── Malaysian Armed Forces ────────────────────────────────
    ("*.army.mil.my",    "Malaysian Army — unauthorized scanning is a criminal offence under the Computer Crimes Act 1997"),
    ("*.navy.mil.my",    "Royal Malaysian Navy — unauthorized scanning is a criminal offence"),
    ("*.airforce.mil.my","Royal Malaysian Air Force — unauthorized scanning is a criminal offence"),
    ("mindef.gov.my",    "Ministry of Defence Malaysia — unauthorized scanning is a criminal offence"),
    ("*.mindef.gov.my",  "Ministry of Defence Malaysia — unauthorized scanning is a criminal offence"),

    # ── Bank Negara Malaysia & Financial Regulators ───────────
    # Source: BNM — https://www.bnm.gov.my
    # Source: SC  — https://www.sc.com.my
    ("bnm.gov.my",       "Bank Negara Malaysia (Central Bank) — critical financial infrastructure, unauthorized scanning prohibited"),
    ("*.bnm.gov.my",     "Bank Negara Malaysia (Central Bank) — critical financial infrastructure, unauthorized scanning prohibited"),
    ("sc.com.my",        "Securities Commission Malaysia — financial regulator, unauthorized scanning prohibited"),
    ("*.sc.com.my",      "Securities Commission Malaysia — financial regulator, unauthorized scanning prohibited"),
    ("*.lofsa.gov.my",   "Labuan FSA — financial regulator, unauthorized scanning prohibited"),

    # ── Licensed Malaysian Banks (BNM Regulated) ──────────────
    # Source: BNM List of Licensed Financial Institutions
    # https://www.bnm.gov.my/list-of-licensed-financial-institutions
    ("maybank.com.my",        "Malayan Banking Berhad (Maybank) — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.maybank.com.my",      "Malayan Banking Berhad (Maybank) — licensed bank under BNM, unauthorized scanning prohibited"),
    ("cimb.com",              "CIMB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.cimb.com",            "CIMB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("cimb.com.my",           "CIMB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.cimb.com.my",         "CIMB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("publicbank.com.my",     "Public Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.publicbank.com.my",   "Public Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("rhbbank.com.my",        "RHB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.rhbbank.com.my",      "RHB Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("hongleongbank.com",     "Hong Leong Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.hongleongbank.com",   "Hong Leong Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("ambank.com.my",         "AmBank Group — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.ambank.com.my",       "AmBank Group — licensed bank under BNM, unauthorized scanning prohibited"),
    ("affinbank.com.my",      "Affin Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.affinbank.com.my",    "Affin Bank Berhad — licensed bank under BNM, unauthorized scanning prohibited"),
    ("alliancebank.com.my",   "Alliance Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.alliancebank.com.my", "Alliance Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("bankislam.com.my",      "Bank Islam Malaysia Berhad — licensed Islamic bank under BNM, unauthorized scanning prohibited"),
    ("*.bankislam.com.my",    "Bank Islam Malaysia Berhad — licensed Islamic bank under BNM, unauthorized scanning prohibited"),
    ("bankrakyat.com.my",     "Bank Rakyat — licensed cooperative bank, unauthorized scanning prohibited"),
    ("*.bankrakyat.com.my",   "Bank Rakyat — licensed cooperative bank, unauthorized scanning prohibited"),
    ("bsn.com.my",            "Bank Simpanan Nasional (BSN) — national savings bank, unauthorized scanning prohibited"),
    ("*.bsn.com.my",          "Bank Simpanan Nasional (BSN) — national savings bank, unauthorized scanning prohibited"),
    ("agbank.com.my",         "Agrobank — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.agbank.com.my",       "Agrobank — licensed bank under BNM, unauthorized scanning prohibited"),
    ("muamalat.com.my",       "Bank Muamalat Malaysia — licensed Islamic bank under BNM, unauthorized scanning prohibited"),
    ("*.muamalat.com.my",     "Bank Muamalat Malaysia — licensed Islamic bank under BNM, unauthorized scanning prohibited"),
    ("islamicbankers.com.my", "Malaysian Islamic banking institution — unauthorized scanning prohibited"),
    ("mbsb.com.my",           "Malaysia Building Society Berhad — licensed financial institution, unauthorized scanning prohibited"),
    ("*.mbsb.com.my",         "Malaysia Building Society Berhad — licensed financial institution, unauthorized scanning prohibited"),
    ("ocbc.com.my",           "OCBC Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.ocbc.com.my",         "OCBC Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("hsbc.com.my",           "HSBC Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.hsbc.com.my",         "HSBC Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("standardchartered.com.my", "Standard Chartered Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("citibank.com.my",       "Citibank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("uob.com.my",            "United Overseas Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("*.uob.com.my",          "United Overseas Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),
    ("deutschebank.com.my",   "Deutsche Bank Malaysia — licensed bank under BNM, unauthorized scanning prohibited"),

    # ── Malaysian E-Wallet & Payment Providers ────────────────
    ("touchngo.com.my",       "Touch n Go — licensed e-money issuer under BNM, unauthorized scanning prohibited"),
    ("*.touchngo.com.my",     "Touch n Go — licensed e-money issuer under BNM, unauthorized scanning prohibited"),
    ("boost.com.my",          "Boost — licensed e-money issuer under BNM, unauthorized scanning prohibited"),
    ("*.boost.com.my",        "Boost — licensed e-money issuer under BNM, unauthorized scanning prohibited"),
    ("grabpay.com",           "GrabPay — licensed e-money issuer, unauthorized scanning prohibited"),
    ("fpx.com.my",            "Financial Process Exchange (FPX) — national payment gateway, unauthorized scanning prohibited"),
    ("*.fpx.com.my",          "Financial Process Exchange (FPX) — national payment gateway, unauthorized scanning prohibited"),
    ("meps.com.my",           "Malaysian Electronic Payment System (MEPS) — national financial infrastructure, unauthorized scanning prohibited"),
    ("paynet.my",             "Payments Network Malaysia (PayNet) — national payment infrastructure, unauthorized scanning prohibited"),
    ("*.paynet.my",           "Payments Network Malaysia (PayNet) — national payment infrastructure, unauthorized scanning prohibited"),

    # ── Malaysian Hospitals & Healthcare ──────────────────────
    # Source: MOH Malaysia — https://www.moh.gov.my
    ("moh.gov.my",            "Ministry of Health Malaysia — government healthcare institution, unauthorized scanning prohibited"),
    ("*.moh.gov.my",          "Ministry of Health Malaysia — government healthcare institution, unauthorized scanning prohibited"),
    ("kpj.com.my",            "KPJ Healthcare — private hospital group, unauthorized scanning prohibited"),
    ("*.kpj.com.my",          "KPJ Healthcare — private hospital group, unauthorized scanning prohibited"),
    ("pantai.com.my",         "Pantai Hospital Group — private hospital, unauthorized scanning prohibited"),
    ("*.pantai.com.my",       "Pantai Hospital Group — private hospital, unauthorized scanning prohibited"),
    ("gleneagles.com.my",     "Gleneagles Hospital Malaysia — private hospital, unauthorized scanning prohibited"),
    ("*.gleneagles.com.my",   "Gleneagles Hospital Malaysia — private hospital, unauthorized scanning prohibited"),
    ("imc.com.my",            "International Medical Centre — private hospital, unauthorized scanning prohibited"),
    ("*.imc.com.my",          "International Medical Centre — private hospital, unauthorized scanning prohibited"),
    ("columbiaasiahospitals.com", "Columbia Asia Hospitals — private hospital group, unauthorized scanning prohibited"),
    ("*.columbiaasiahospitals.com", "Columbia Asia Hospitals — private hospital group, unauthorized scanning prohibited"),
    ("sunwaymedical.com",     "Sunway Medical Centre — private hospital, unauthorized scanning prohibited"),
    ("*.sunwaymedical.com",   "Sunway Medical Centre — private hospital, unauthorized scanning prohibited"),
    ("princesscourt.com.my",  "Prince Court Medical Centre — private hospital, unauthorized scanning prohibited"),
    ("tmclife.com",           "TMC Life Sciences — private healthcare group, unauthorized scanning prohibited"),
    ("hukm.ukm.my",           "Hospital UKM — public university hospital, unauthorized scanning prohibited"),
    ("ummc.edu.my",           "University Malaya Medical Centre — public university hospital, unauthorized scanning prohibited"),

    # ── Malaysian Critical Infrastructure ────────────────────
    ("tenaga.com.my",         "Tenaga Nasional Berhad (TNB) — national electricity utility, critical infrastructure"),
    ("*.tenaga.com.my",       "Tenaga Nasional Berhad (TNB) — national electricity utility, critical infrastructure"),
    ("petronas.com.my",       "PETRONAS — national oil and gas company, critical infrastructure"),
    ("*.petronas.com.my",     "PETRONAS — national oil and gas company, critical infrastructure"),
    ("telekom.com.my",        "Telekom Malaysia (TM) — national telecommunications infrastructure"),
    ("*.telekom.com.my",      "Telekom Malaysia (TM) — national telecommunications infrastructure"),
    ("maxis.com.my",          "Maxis — major telecommunications provider, unauthorized scanning prohibited"),
    ("*.maxis.com.my",        "Maxis — major telecommunications provider, unauthorized scanning prohibited"),
    ("digi.com.my",           "Digi Telecommunications — telecommunications provider, unauthorized scanning prohibited"),
    ("*.digi.com.my",         "Digi Telecommunications — telecommunications provider, unauthorized scanning prohibited"),
    ("celcom.com.my",         "Celcom — telecommunications provider, unauthorized scanning prohibited"),
    ("*.celcom.com.my",       "Celcom — telecommunications provider, unauthorized scanning prohibited"),
    ("airportmalaysia.com.my","Malaysia Airports Holdings Berhad — national airport infrastructure, critical infrastructure"),
    ("*.airportmalaysia.com.my","Malaysia Airports Holdings Berhad — national airport infrastructure, critical infrastructure"),
    ("mas.com.my",            "Malaysia Airlines (MAS) — national airline, unauthorized scanning prohibited"),
    ("*.mas.com.my",          "Malaysia Airlines (MAS) — national airline, unauthorized scanning prohibited"),
    ("airasia.com",           "AirAsia — major airline, unauthorized scanning prohibited"),
    ("*.airasia.com",         "AirAsia — major airline, unauthorized scanning prohibited"),
    ("lrt.com.my",            "LRT Malaysia — public transportation infrastructure, unauthorized scanning prohibited"),
    ("prasarana.com.my",      "Prasarana Malaysia — public transportation infrastructure, unauthorized scanning prohibited"),
    ("*.prasarana.com.my",    "Prasarana Malaysia — public transportation infrastructure, unauthorized scanning prohibited"),
    ("mrt.com.my",            "MRT Corp Malaysia — public transportation infrastructure, unauthorized scanning prohibited"),
    ("petrochemical.com.my",  "Malaysian petrochemical infrastructure — critical infrastructure, unauthorized scanning prohibited"),
    ("gasmalaysia.com",       "Gas Malaysia — national gas distribution, critical infrastructure"),
    ("*.gasmalaysia.com",     "Gas Malaysia — national gas distribution, critical infrastructure"),

    # ── Malaysian Cyber Security Agencies ────────────────────
    # Source: NACSA — https://www.nacsa.gov.my
    ("nacsa.gov.my",          "National Cyber Security Agency (NACSA) — government cybersecurity agency, unauthorized scanning prohibited"),
    ("*.nacsa.gov.my",        "National Cyber Security Agency (NACSA) — government cybersecurity agency, unauthorized scanning prohibited"),
    ("cybersecurity.my",      "CyberSecurity Malaysia — government cybersecurity body, unauthorized scanning prohibited"),
    ("*.cybersecurity.my",    "CyberSecurity Malaysia — government cybersecurity body, unauthorized scanning prohibited"),
    ("mcmc.gov.my",           "Malaysian Communications and Multimedia Commission (MCMC) — government regulator, unauthorized scanning prohibited"),
    ("*.mcmc.gov.my",         "Malaysian Communications and Multimedia Commission (MCMC) — government regulator, unauthorized scanning prohibited"),

    # ── International Critical Infrastructure ─────────────────
    ("8.8.8.8",               "Google Public DNS — do not scan critical public DNS infrastructure"),
    ("8.8.4.4",               "Google Public DNS — do not scan critical public DNS infrastructure"),
    ("1.1.1.1",               "Cloudflare Public DNS — do not scan critical public DNS infrastructure"),
    ("1.0.0.1",               "Cloudflare Public DNS — do not scan critical public DNS infrastructure"),
    ("*.google.com",          "Google infrastructure — unauthorized scanning prohibited"),
    ("*.microsoft.com",       "Microsoft infrastructure — unauthorized scanning prohibited"),
    ("*.amazonaws.com",       "Amazon Web Services infrastructure — unauthorized scanning prohibited"),
    ("*.cloudflare.com",      "Cloudflare infrastructure — unauthorized scanning prohibited"),
]


def seed_default_blocklist():
    """
    Insert all default blocklist entries into the
    scope_blocklist table. Uses INSERT OR IGNORE so
    existing entries (including those manually removed
    by the user) are never overwritten.
    Called once from scope.py _migrate() on first run.
    """
    from backend.db import get_connection
    from datetime import datetime

    conn   = get_connection()
    cursor = conn.cursor()

    added   = 0
    skipped = 0

    for target, reason in DEFAULT_BLOCKLIST:
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO scope_blocklist "
                "(target, reason, added_on) VALUES (?, ?, ?)",
                (
                    target,
                    reason,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                )
            )
            if cursor.rowcount:
                added += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"[!] Blocklist seed error for {target}: {e}")

    conn.commit()
    conn.close()

    print(
        f"[+] Default blocklist seeded: "
        f"{added} added, {skipped} already existed"
    )


def is_blocklist_seeded():
    """
    Returns True if the default blocklist has already
    been seeded (checks for the presence of at least
    one known default entry).
    """
    from backend.db import get_connection
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM scope_blocklist "
        "WHERE target IN ('*.gov.my', '10.0.0.0/8')"
    )
    count = cursor.fetchone()[0]
    conn.close()
    return count >= 2
