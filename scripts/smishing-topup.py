"""
smishing-topup.py
Injects 75 new SMISHING_TOPUP patterns into pattern-engine.ts.
"""

import re
import sys

TARGET_FILE = r"C:\Users\moham\OneDrive\Documents\claude code\scamshield\src\lib\algorithms\pattern-engine.ts"

# ── 75 new smishing patterns ──────────────────────────────────────────────────
SMISHING_TOPUP_PATTERNS = [
    # bank_alert (8)
    ("smishing", "bank_alert", "your card has been blocked call now", 18, "critical"),
    ("smishing", "bank_alert", "unusual login detected verify identity", 17, "critical"),
    ("smishing", "bank_alert", "bank account suspended click to restore", 18, "critical"),
    ("smishing", "bank_alert", "fraud alert confirm recent transaction", 17, "critical"),
    ("smishing", "bank_alert", "your debit card was charged review now", 16, "high"),
    ("smishing", "bank_alert", "wire transfer pending approve or deny", 17, "critical"),
    ("smishing", "bank_alert", "chase security team account restricted", 17, "critical"),
    ("smishing", "bank_alert", "low balance alert add funds avoid fee", 14, "high"),

    # package_delivery (8)
    ("smishing", "package_delivery", "usps package held customs fee due", 17, "high"),
    ("smishing", "package_delivery", "fedex delivery failed reschedule now", 16, "high"),
    ("smishing", "package_delivery", "your parcel awaits pay small duty fee", 17, "high"),
    ("smishing", "package_delivery", "amazon package undeliverable update address", 16, "high"),
    ("smishing", "package_delivery", "dhl shipment detained click to release", 17, "high"),
    ("smishing", "package_delivery", "tracking number updated reconfirm delivery", 15, "high"),
    ("smishing", "package_delivery", "ups package returned provide new address", 16, "high"),
    ("smishing", "package_delivery", "delivery attempted no one home reschedule", 15, "high"),

    # prize_win (6)
    ("smishing", "prize_win", "you won free iphone claim before midnight", 18, "critical"),
    ("smishing", "prize_win", "congratulations selected for cash reward", 17, "critical"),
    ("smishing", "prize_win", "walmart loyalty winner claim gift card", 17, "critical"),
    ("smishing", "prize_win", "you are our monthly lucky winner reply", 16, "critical"),
    ("smishing", "prize_win", "free vacation prize claim expires today", 17, "critical"),
    ("smishing", "prize_win", "500 dollar gift card waiting for you", 16, "critical"),

    # otp_theft (7)
    ("smishing", "otp_theft", "enter code we sent verify account", 17, "critical"),
    ("smishing", "otp_theft", "your verification code share with agent", 18, "critical"),
    ("smishing", "otp_theft", "confirm otp to unlock your account now", 18, "critical"),
    ("smishing", "otp_theft", "one time passcode required to proceed", 17, "critical"),
    ("smishing", "otp_theft", "read back the code we just sent you", 18, "critical"),
    ("smishing", "otp_theft", "security code sent please confirm by text", 17, "critical"),
    ("smishing", "otp_theft", "two factor code needed reply with it", 17, "critical"),

    # account_verify (6)
    ("smishing", "account_verify", "your account has been locked verify now", 17, "critical"),
    ("smishing", "account_verify", "reconfirm your details to keep access", 16, "high"),
    ("smishing", "account_verify", "paypal account limited click to verify", 17, "critical"),
    ("smishing", "account_verify", "apple id suspended verify information", 17, "critical"),
    ("smishing", "account_verify", "google account unusual sign in verify", 16, "high"),
    ("smishing", "account_verify", "netflix billing issue update payment now", 15, "high"),

    # gov_impersonate (6)
    ("smishing", "gov_impersonate", "irs final notice pay or face arrest", 19, "critical"),
    ("smishing", "gov_impersonate", "social security number suspended call now", 19, "critical"),
    ("smishing", "gov_impersonate", "government stimulus payment release pending", 17, "critical"),
    ("smishing", "gov_impersonate", "dmv license suspension notice respond today", 17, "critical"),
    ("smishing", "gov_impersonate", "medicare benefit expiring update now", 16, "high"),
    ("smishing", "gov_impersonate", "court summons issued reply to dispute", 18, "critical"),

    # crypto_sms (5)
    ("smishing", "crypto_sms", "your bitcoin wallet requires verification", 16, "high"),
    ("smishing", "crypto_sms", "crypto withdrawal initiated confirm now", 17, "critical"),
    ("smishing", "crypto_sms", "coinbase account locked tap to recover", 17, "critical"),
    ("smishing", "crypto_sms", "double your crypto investment limited slots", 16, "high"),
    ("smishing", "crypto_sms", "nft drop claim your free token today", 15, "high"),

    # job_offer (4)
    ("smishing", "job_offer", "work from home earn 500 daily apply", 15, "high"),
    ("smishing", "job_offer", "part time online job no experience needed", 14, "high"),
    ("smishing", "job_offer", "hiring remote workers start today 800 week", 15, "high"),
    ("smishing", "job_offer", "easy task online job pay daily cash", 14, "high"),

    # romance_sms (3)
    ("smishing", "romance_sms", "hi i found your number hope we can talk", 13, "high"),
    ("smishing", "romance_sms", "wrong number but you seem interesting reply", 13, "high"),
    ("smishing", "romance_sms", "i think we met before want to reconnect", 13, "high"),

    # delivery_fee (4)
    ("smishing", "delivery_fee", "small customs fee required release package", 17, "high"),
    ("smishing", "delivery_fee", "pay 1 99 to reschedule your delivery", 16, "high"),
    ("smishing", "delivery_fee", "your order held pay shipping balance now", 17, "high"),
    ("smishing", "delivery_fee", "release fee required collect parcel today", 16, "high"),

    # subscription (4)
    ("smishing", "subscription", "your netflix subscription about to cancel", 15, "high"),
    ("smishing", "subscription", "renew now before account permanently deleted", 16, "high"),
    ("smishing", "subscription", "payment failed update card keep subscription", 15, "high"),
    ("smishing", "subscription", "auto renewal failed resubscribe to continue", 15, "high"),

    # covid_sms (3)
    ("smishing", "covid_sms", "covid relief fund claim your 1200 now", 16, "critical"),
    ("smishing", "covid_sms", "free covid test kit register to receive", 14, "high"),
    ("smishing", "covid_sms", "health department exposure alert tap link", 16, "high"),

    # gift_card_sms (4)
    ("smishing", "gift_card_sms", "buy itunes gift card send codes urgent", 18, "critical"),
    ("smishing", "gift_card_sms", "pay with google play card to avoid arrest", 19, "critical"),
    ("smishing", "gift_card_sms", "amazon gift card needed settle overdue balance", 18, "critical"),
    ("smishing", "gift_card_sms", "steam wallet gift card send now required", 17, "critical"),

    # fake_refund (4)
    ("smishing", "fake_refund", "tax refund ready confirm account to receive", 17, "critical"),
    ("smishing", "fake_refund", "overpayment refund pending verify details", 16, "high"),
    ("smishing", "fake_refund", "insurance refund awaiting your confirmation", 15, "high"),
    ("smishing", "fake_refund", "bank refund issued click link to accept", 17, "critical"),

    # toll_fee (3)
    ("smishing", "toll_fee", "unpaid toll balance due avoid penalty now", 17, "high"),
    ("smishing", "toll_fee", "e zpass account past due pay online today", 16, "high"),
    ("smishing", "toll_fee", "toll violation notice pay within 48 hours", 16, "high"),
]

assert len(SMISHING_TOPUP_PATTERNS) == 75, f"Expected 75 patterns, got {len(SMISHING_TOPUP_PATTERNS)}"

# ── Build the const block ─────────────────────────────────────────────────────
def build_const() -> str:
    lines = ["const SMISHING_TOPUP: PatternEntry[] = ["]
    for group, cat, text, weight, severity in SMISHING_TOPUP_PATTERNS:
        lines.append(f"  p('{group}', '{cat}', '{text}', {weight}, '{severity}'),")
    lines.append("];")
    return "\n".join(lines)

# ── Main injection logic ──────────────────────────────────────────────────────
def main():
    with open(TARGET_FILE, "r", encoding="utf-8") as fh:
        content = fh.read()

    # Guard: already patched?
    if "SMISHING_TOPUP" in content:
        print("SKIP: SMISHING_TOPUP already present in pattern-engine.ts")
        sys.exit(0)

    const_block = build_const()

    # ── 1. Insert const BEFORE the Round-3 separator comment ─────────────────
    ROUND3_MARKER = (
        "// ═══════════════════════════════════════════════════════════════════════════\n"
        "// ROUND 3 EXTENSIONS"
    )
    if ROUND3_MARKER not in content:
        print("ERROR: Could not find Round-3 marker in file.")
        sys.exit(1)

    insertion_block = const_block + "\n\n"
    content = content.replace(ROUND3_MARKER, insertion_block + ROUND3_MARKER, 1)
    print("OK: Inserted SMISHING_TOPUP const before Round-3 marker.")

    # ── 2. Add spread into MASTER_PATTERNS after ...P200_SMISHING_NEW ────────
    SPREAD_AFTER = "  ...P200_SMISHING_NEW,"
    if SPREAD_AFTER in content:
        content = content.replace(
            SPREAD_AFTER,
            SPREAD_AFTER + "\n  ...SMISHING_TOPUP,",
            1,
        )
        print("OK: Added ...SMISHING_TOPUP after ...P200_SMISHING_NEW in MASTER_PATTERNS.")
    else:
        # Fallback: insert before the closing bracket of MASTER_PATTERNS
        # Find last '...something,' line before the first '];' after MASTER_PATTERNS
        master_start = content.find("export const MASTER_PATTERNS: PatternEntry[] = [")
        if master_start == -1:
            print("ERROR: Cannot find MASTER_PATTERNS declaration.")
            sys.exit(1)
        # Find the closing ]; of MASTER_PATTERNS
        close_idx = content.find("\n];", master_start)
        if close_idx == -1:
            print("ERROR: Cannot find closing ]; of MASTER_PATTERNS.")
            sys.exit(1)
        content = content[:close_idx] + "\n  ...SMISHING_TOPUP," + content[close_idx:]
        print("WARN: P200_SMISHING_NEW not found; inserted ...SMISHING_TOPUP before MASTER_PATTERNS closing bracket.")

    with open(TARGET_FILE, "w", encoding="utf-8") as fh:
        fh.write(content)

    print(f"DONE: pattern-engine.ts updated with 75 new smishing patterns.")

if __name__ == "__main__":
    main()
