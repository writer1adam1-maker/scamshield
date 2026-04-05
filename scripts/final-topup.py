#!/usr/bin/env python3
"""Final top-up to bring remaining 9 groups to 150+."""

ENGINE = r"c:\Users\moham\OneDrive\Documents\claude code\scamshield\src\lib\algorithms\pattern-engine.ts"

TOPUP2 = """
// ═══════════════════════════════════════════════════════════════════════════
// FINAL TOP-UP — brings all remaining groups to 150+
// ═══════════════════════════════════════════════════════════════════════════

const FINAL_TOPUP: PatternEntry[] = [
  // elder_fraud (130 → 150+, need 22)
  p('elder_fraud', 'grandparent', 'grandson arrested needs bail wired', 19, 'critical'),
  p('elder_fraud', 'grandparent', 'do not tell your children please', 18, 'critical'),
  p('elder_fraud', 'grandparent', 'family emergency keep secret now', 18, 'critical'),
  p('elder_fraud', 'grandparent', 'grandchild stranded abroad needs help', 18, 'critical'),
  p('elder_fraud', 'grandparent', 'lawyer calling about your grandchild', 17, 'critical'),
  p('elder_fraud', 'pension', 'guaranteed pension growth no risk', 17, 'critical'),
  p('elder_fraud', 'pension', 'rollover retirement account safe investment', 17, 'critical'),
  p('elder_fraud', 'pension', 'annuity guaranteed income retirement plan', 16, 'high'),
  p('elder_fraud', 'pension', 'free retirement planning seminar lunch', 15, 'high'),
  p('elder_fraud', 'tech', 'computer broken grandchild fix remotely', 16, 'high'),
  p('elder_fraud', 'tech', 'microsoft calling about senior account', 17, 'critical'),
  p('elder_fraud', 'romance', 'online companion senior widow widower', 15, 'high'),
  p('elder_fraud', 'romance', 'lonely senior dating companion available', 14, 'high'),
  p('elder_fraud', 'caregiver', 'caregiver stealing from elderly patient', 18, 'critical'),
  p('elder_fraud', 'caregiver', 'trusted helper taking advantage elderly', 17, 'critical'),
  p('elder_fraud', 'phone', 'you qualify for senior benefits program', 16, 'high'),
  p('elder_fraud', 'phone', 'senior discount card enrollment required', 15, 'high'),
  p('elder_fraud', 'deed', 'sign over house title for loan', 18, 'critical'),
  p('elder_fraud', 'deed', 'reverse mortgage free money your home', 17, 'high'),
  p('elder_fraud', 'medicare', 'new medicare card requires verification now', 18, 'critical'),
  p('elder_fraud', 'medicare', 'medicare advantage upgrade enroll today', 16, 'high'),
  p('elder_fraud', 'obituary', 'condolences passing loved one estate', 15, 'high'),

  // payment_fraud (130 → 150+, need 22)
  p('payment_fraud', 'overpayment', 'sent too much please refund balance', 17, 'high'),
  p('payment_fraud', 'overpayment', 'check exceeds amount send back difference', 18, 'critical'),
  p('payment_fraud', 'overpayment', 'overpaid by mistake return excess funds', 17, 'high'),
  p('payment_fraud', 'overpayment', 'cashiers check deposit withdraw send back', 18, 'critical'),
  p('payment_fraud', 'fake_confirm', 'payment screenshot verification completed', 16, 'high'),
  p('payment_fraud', 'fake_confirm', 'zelle payment sent check your account', 17, 'high'),
  p('payment_fraud', 'fake_confirm', 'venmo transfer sent confirm receipt now', 16, 'high'),
  p('payment_fraud', 'fake_confirm', 'wire confirmation number attached please', 16, 'high'),
  p('payment_fraud', 'card_test', 'small test charge verify card works', 16, 'high'),
  p('payment_fraud', 'card_test', 'micro deposit verify your account now', 15, 'high'),
  p('payment_fraud', 'refund', 'refund to different card account please', 17, 'high'),
  p('payment_fraud', 'refund', 'original payment method no longer valid', 16, 'high'),
  p('payment_fraud', 'gift_card', 'pay with google play gift card', 18, 'critical'),
  p('payment_fraud', 'gift_card', 'itunes gift card payment required now', 18, 'critical'),
  p('payment_fraud', 'gift_card', 'steam wallet cards for payment accepted', 17, 'critical'),
  p('payment_fraud', 'gift_card', 'scratch gift card read numbers aloud', 18, 'critical'),
  p('payment_fraud', 'wire', 'wire transfer only accepted payment method', 18, 'critical'),
  p('payment_fraud', 'wire', 'international wire transfer fees apply now', 17, 'high'),
  p('payment_fraud', 'chargeback', 'dispute charge claim item not received', 15, 'high'),
  p('payment_fraud', 'crypto', 'bitcoin atm deposit address provided here', 18, 'critical'),
  p('payment_fraud', 'crypto', 'send crypto payment no chargebacks possible', 17, 'critical'),
  p('payment_fraud', 'invoice', 'invoice due immediately late fees apply', 16, 'high'),

  // health_fraud (149 → 150+, need 2)
  p('health_fraud', 'fake_cure', 'all natural cure doctors hate this', 15, 'high'),
  p('health_fraud', 'supplement', 'clinically proven weight loss supplement now', 14, 'high'),

  // insurance_scam (144 → 150+, need 7)
  p('insurance_scam', 'fake_health', 'limited time health plan enroll now', 16, 'high'),
  p('insurance_scam', 'fake_health', 'obamacare marketplace special enrollment period', 15, 'high'),
  p('insurance_scam', 'auto', 'your auto insurance expired renew now', 16, 'high'),
  p('insurance_scam', 'medicare', 'medicare open enrollment deadline approaching', 17, 'high'),
  p('insurance_scam', 'life', 'no medical exam life insurance today', 15, 'high'),
  p('insurance_scam', 'ghost_broker', 'cheap insurance certificate instant download', 16, 'high'),
  p('insurance_scam', 'identity', 'free insurance quote provide ssn', 17, 'critical'),

  // money_mule (147 → 150+, need 4)
  p('money_mule', 'recruitment', 'financial assistant process client transfers daily', 17, 'critical'),
  p('money_mule', 'reshipping', 'package receiving home address needed now', 16, 'critical'),
  p('money_mule', 'crypto', 'buy bitcoin local atm send address', 18, 'critical'),
  p('money_mule', 'account', 'rent your bank account earn commission', 18, 'critical'),

  // quishing (147 → 150+, need 4)
  p('quishing', 'email', 'scan qr email attachment verify identity', 17, 'high'),
  p('quishing', 'physical', 'qr code sticker placed over legitimate', 18, 'critical'),
  p('quishing', 'payment', 'scan qr pay invoice now securely', 16, 'high'),
  p('quishing', 'crypto', 'bitcoin atm qr code scan deposit', 18, 'critical'),

  // rental_fraud (142 → 150+, need 9)
  p('rental_fraud', 'fake_listing', 'beautiful property wire deposit hold it', 18, 'critical'),
  p('rental_fraud', 'absentee', 'keys mailed after deposit received confirmation', 17, 'critical'),
  p('rental_fraud', 'off_platform', 'contact landlord directly avoid platform fees', 17, 'high'),
  p('rental_fraud', 'fake_listing', 'below market price urgent quick move', 16, 'high'),
  p('rental_fraud', 'vacation', 'airbnb not available contact owner direct', 17, 'critical'),
  p('rental_fraud', 'student', 'student housing deposit secures your room', 16, 'high'),
  p('rental_fraud', 'absentee', 'military deployment cannot show apartment currently', 17, 'critical'),
  p('rental_fraud', 'deposit', 'send first last security deposit wire', 18, 'critical'),
  p('rental_fraud', 'fake_listing', 'rental photos stolen from real listing', 17, 'critical'),

  // pig_butchering (143 → 150+, need 8)
  p('pig_butchering', 'trust_building', 'wrong number sorry new friend here', 14, 'medium'),
  p('pig_butchering', 'platform_lure', 'exclusive trading app family uses profits', 18, 'critical'),
  p('pig_butchering', 'small_win', 'look my account grew this week', 17, 'critical'),
  p('pig_butchering', 'escalation', 'invest more before window closes today', 18, 'critical'),
  p('pig_butchering', 'locked_funds', 'funds locked need more to unlock', 19, 'critical'),
  p('pig_butchering', 'fee_to_withdraw', 'pay tax fee before withdrawal processed', 18, 'critical'),
  p('pig_butchering', 'exit_scam', 'platform down temporarily funds safe here', 18, 'critical'),
  p('pig_butchering', 'romance_investment_hybrid', 'my financial advisor can help you', 16, 'critical'),

  // sim_swap (146 → 150+, need 5)
  p('sim_swap', 'social_eng', 'call carrier authorize number port today', 18, 'critical'),
  p('sim_swap', 'social_eng', 'sim card damaged need replacement port', 17, 'critical'),
  p('sim_swap', 'social_eng', 'carrier pin number verify your account', 17, 'critical'),
  p('sim_swap', 'consequence', 'all texts calls routed hijacked number', 18, 'critical'),
  p('sim_swap', 'indicator', 'no cell signal suddenly service lost', 16, 'high'),
];
"""

def main():
    with open(ENGINE, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'FINAL_TOPUP' in content:
        print("FINAL_TOPUP already exists — skipping.")
        return

    # Insert before the Round 2 extensions section
    marker = "// ═══════════════════════════════════════════════════════════════════════════\n// ROUND 2 EXTENSIONS"
    if marker not in content:
        marker = "// ═══════════════════════════════════════════════════════════════════════════\n// TOP-UP EXTENSIONS"
    if marker not in content:
        marker = "// ═══════════════════════════════════════════════════════════════════════════\n// PATTERN EXTENSIONS (auto-generated)"

    content = content.replace(marker, TOPUP2.strip() + "\n\n" + marker)

    # Add spread to MASTER_PATTERNS — find the last ...TOPUP_EXT or last spread
    for anchor in ['  ...TOPUP_EXT,\n', '  ...ATO_TU,\n']:
        if anchor in content:
            content = content.replace(anchor, anchor + '  ...FINAL_TOPUP,\n')
            break

    with open(ENGINE, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Done! FINAL_TOPUP injected.")

if __name__ == '__main__':
    main()
