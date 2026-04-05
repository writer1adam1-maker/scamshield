#!/usr/bin/env python3
"""Add top-up patterns for 9 groups still under 100."""
import re

ENGINE = r"c:\Users\moham\OneDrive\Documents\claude code\scamshield\src\lib\algorithms\pattern-engine.ts"

# New patterns to bring each group to 100+
TOPUP = """
// ═══════════════════════════════════════════════════════════════════════════
// TOP-UP EXTENSIONS — brings all groups to 100+ patterns
// ═══════════════════════════════════════════════════════════════════════════

const TOPUP_EXT: PatternEntry[] = [
  // url_malware (needs 40+)
  p('url_malware', 'c2', 'command control server beacon', 18, 'critical'),
  p('url_malware', 'c2', 'botnet command endpoint', 18, 'critical'),
  p('url_malware', 'c2', 'reverse shell callback url', 19, 'critical'),
  p('url_malware', 'c2', 'malware c2 panel access', 19, 'critical'),
  p('url_malware', 'c2', 'rat remote access trojan server', 18, 'critical'),
  p('url_malware', 'c2', 'zombie bot infected machine', 17, 'critical'),
  p('url_malware', 'c2', 'trojan dropper payload url', 18, 'critical'),
  p('url_malware', 'c2', 'loader stage one download', 17, 'critical'),
  p('url_malware', 'c2', 'beacon checkin interval set', 16, 'critical'),
  p('url_malware', 'c2', 'exfiltration endpoint collector', 18, 'critical'),
  p('url_malware', 'drive_by', 'exploit kit landing page', 19, 'critical'),
  p('url_malware', 'drive_by', 'browser exploit java vulnerability', 18, 'critical'),
  p('url_malware', 'drive_by', 'iframe injection redirect', 17, 'high'),
  p('url_malware', 'drive_by', 'malvertising infected ad redirect', 18, 'critical'),
  p('url_malware', 'drive_by', 'rig exploit kit gate', 19, 'critical'),
  p('url_malware', 'drive_by', 'nuclear exploit pack download', 19, 'critical'),
  p('url_malware', 'drive_by', 'magnitude exploit kit redirect', 18, 'critical'),
  p('url_malware', 'drive_by', 'angler exploit kit landing', 19, 'critical'),
  p('url_malware', 'download', 'free software crack serial key', 15, 'high'),
  p('url_malware', 'download', 'download keygen patch free full', 15, 'high'),
  p('url_malware', 'download', 'warez crack download site', 16, 'high'),
  p('url_malware', 'download', 'torrent malware infected download', 16, 'high'),
  p('url_malware', 'download', 'pirated software download link', 15, 'high'),
  p('url_malware', 'download', 'free premium account generator download', 16, 'high'),
  p('url_malware', 'download', 'cheat engine game hack download', 14, 'high'),
  p('url_malware', 'extension', 'malicious browser extension install', 17, 'critical'),
  p('url_malware', 'extension', 'chrome extension steal passwords', 18, 'critical'),
  p('url_malware', 'extension', 'fake update browser plugin', 17, 'critical'),
  p('url_malware', 'extension', 'adware bundled software installer', 15, 'high'),
  p('url_malware', 'extension', 'pup potentially unwanted program install', 14, 'high'),
  p('url_malware', 'payload', 'powershell encoded payload execute', 19, 'critical'),
  p('url_malware', 'payload', 'vbs script wscript execute payload', 19, 'critical'),
  p('url_malware', 'payload', 'macro enabled document download', 18, 'critical'),
  p('url_malware', 'payload', 'fileless malware memory injection', 19, 'critical'),
  p('url_malware', 'payload', 'dll side loading technique', 17, 'critical'),
  p('url_malware', 'payload', 'process hollowing injection attack', 18, 'critical'),
  p('url_malware', 'payload', 'living off land lolbas attack', 17, 'critical'),
  p('url_malware', 'payload', 'mshta wscript cscript abuse', 18, 'critical'),
  p('url_malware', 'domain', 'domain generation algorithm dga host', 16, 'critical'),
  p('url_malware', 'domain', 'fast flux dns malware hosting', 17, 'critical'),
  p('url_malware', 'domain', 'bulletproof hosting malware server', 17, 'critical'),
  p('url_malware', 'domain', 'newly registered domain suspicious', 13, 'high'),

  // quishing (needs 18+)
  p('quishing', 'delivery', 'scan qr code to verify identity', 17, 'high'),
  p('quishing', 'delivery', 'qr code payment link below', 16, 'high'),
  p('quishing', 'delivery', 'scan here to claim your reward', 17, 'high'),
  p('quishing', 'delivery', 'qr code required to continue process', 16, 'high'),
  p('quishing', 'delivery', 'scan qr code confirm delivery address', 17, 'high'),
  p('quishing', 'delivery', 'qr code login bypass two factor', 18, 'critical'),
  p('quishing', 'delivery', 'use phone camera scan qr access', 15, 'high'),
  p('quishing', 'fake_bill', 'invoice qr code scan to pay', 17, 'high'),
  p('quishing', 'fake_bill', 'utility bill qr scan payment', 16, 'high'),
  p('quishing', 'fake_bill', 'parking fine qr code payment link', 17, 'high'),
  p('quishing', 'parking', 'fake parking ticket qr pay online', 18, 'high'),
  p('quishing', 'parking', 'parking meter qr code phishing', 17, 'high'),
  p('quishing', 'gov', 'government qr code verify benefits', 17, 'critical'),
  p('quishing', 'gov', 'irs qr code scan refund claim', 18, 'critical'),
  p('quishing', 'gov', 'social security qr code verify now', 18, 'critical'),
  p('quishing', 'crypto', 'crypto wallet qr code send funds', 18, 'critical'),
  p('quishing', 'crypto', 'bitcoin address qr code receive', 17, 'high'),
  p('quishing', 'crypto', 'scan qr donate crypto wallet', 16, 'high'),

  // ato (needs 15+)
  p('ato', 'credential', 'your password has been compromised change', 16, 'high'),
  p('ato', 'credential', 'account credentials leaked dark web', 17, 'critical'),
  p('ato', 'credential', 'login attempt from unknown device', 15, 'high'),
  p('ato', 'credential', 'suspicious sign in detected verify', 16, 'high'),
  p('ato', 'credential', 'account accessed from new location', 14, 'high'),
  p('ato', 'session', 'session hijacking token stolen', 18, 'critical'),
  p('ato', 'session', 'cookie theft session replay attack', 18, 'critical'),
  p('ato', 'session', 'man in middle session intercept', 18, 'critical'),
  p('ato', 'takeover', 'account recovery email changed', 17, 'critical'),
  p('ato', 'takeover', 'phone number removed from account', 17, 'critical'),
  p('ato', 'takeover', 'backup code used for account access', 16, 'high'),
  p('ato', 'takeover', 'security questions reset to unknown', 17, 'critical'),
  p('ato', 'brute_force', 'multiple failed login attempts detected', 15, 'high'),
  p('ato', 'brute_force', 'password spray attack on accounts', 16, 'high'),
  p('ato', 'brute_force', 'credential stuffing attack blocked', 16, 'high'),

  // fake_vpn (needs 13+)
  p('fake_vpn', 'data_harvest', 'vpn logs all your traffic sells', 18, 'critical'),
  p('fake_vpn', 'data_harvest', 'free vpn monetizes browsing data', 17, 'high'),
  p('fake_vpn', 'data_harvest', 'vpn service sells user data third party', 18, 'critical'),
  p('fake_vpn', 'malware', 'vpn app contains trojan malware', 19, 'critical'),
  p('fake_vpn', 'malware', 'fake vpn installs adware on device', 18, 'critical'),
  p('fake_vpn', 'malware', 'vpn client keylogger installed silently', 19, 'critical'),
  p('fake_vpn', 'impersonation', 'fake nordvpn expressvpn clone site', 18, 'critical'),
  p('fake_vpn', 'impersonation', 'counterfeit vpn brand imitation app', 17, 'critical'),
  p('fake_vpn', 'impersonation', 'vpn impersonator phishing credentials', 18, 'critical'),
  p('fake_vpn', 'leak', 'vpn dns leak exposes real ip', 17, 'high'),
  p('fake_vpn', 'leak', 'webrtc leak despite vpn connection', 16, 'high'),
  p('fake_vpn', 'scam', 'vpn subscription fraud recurring charge', 17, 'high'),
  p('fake_vpn', 'scam', 'lifetime vpn deal scam no refund', 16, 'high'),

  // sim_swap (needs 8+)
  p('sim_swap', 'social_eng', 'port your number to new carrier now', 17, 'critical'),
  p('sim_swap', 'social_eng', 'request sim card transfer immediately', 18, 'critical'),
  p('sim_swap', 'social_eng', 'carrier account pin verify transfer', 17, 'critical'),
  p('sim_swap', 'social_eng', 'phone number porting authorization code', 17, 'critical'),
  p('sim_swap', 'consequence', 'sim swap crypto exchange drained', 18, 'critical'),
  p('sim_swap', 'consequence', 'sim hijack two factor bypass attack', 18, 'critical'),
  p('sim_swap', 'consequence', 'phone number takeover bank account', 18, 'critical'),
  p('sim_swap', 'indicator', 'lost cell service suddenly sim swapped', 17, 'critical'),

  // stalkerware (needs 7+)
  p('stalkerware', 'install', 'install monitoring app without knowing', 18, 'critical'),
  p('stalkerware', 'install', 'hidden spy app install remotely', 19, 'critical'),
  p('stalkerware', 'install', 'invisible tracking app no icon shown', 18, 'critical'),
  p('stalkerware', 'feature', 'reads all text messages secretly', 18, 'critical'),
  p('stalkerware', 'feature', 'secretly activates microphone camera', 19, 'critical'),
  p('stalkerware', 'feature', 'real time gps location tracking stealth', 17, 'critical'),
  p('stalkerware', 'feature', 'records calls without consent illegal', 18, 'critical'),

  // crypto_drainer (needs 6+)
  p('crypto_drainer', 'wallet_connect', 'connect wallet to claim airdrop now', 19, 'critical'),
  p('crypto_drainer', 'wallet_connect', 'approve token spend unlimited access', 19, 'critical'),
  p('crypto_drainer', 'wallet_connect', 'sign transaction to receive nft drop', 18, 'critical'),
  p('crypto_drainer', 'wallet_connect', 'metamask signature request drain wallet', 19, 'critical'),
  p('crypto_drainer', 'fake_project', 'fake defi protocol liquidity drain', 18, 'critical'),
  p('crypto_drainer', 'fake_project', 'rug pull exit scam defi project', 18, 'critical'),

  // health_fraud (needs 6+)
  p('health_fraud', 'billing', 'unbundling medical procedure billing fraud', 18, 'critical'),
  p('health_fraud', 'billing', 'upcoding diagnosis higher reimbursement', 18, 'critical'),
  p('health_fraud', 'billing', 'phantom billing nonexistent services', 19, 'critical'),
  p('health_fraud', 'fake_cure', 'miracle cure cancer treatment scam', 17, 'high'),
  p('health_fraud', 'fake_cure', 'unauthorized experimental drug treatment', 17, 'high'),
  p('health_fraud', 'identity', 'medical identity theft insurance claim', 18, 'critical'),

  // impersonation (needs 5+)
  p('impersonation', 'executive', 'ceo urgent wire transfer request', 19, 'critical'),
  p('impersonation', 'executive', 'cfo requesting immediate payment approval', 19, 'critical'),
  p('impersonation', 'executive', 'executive email compromise payment fraud', 18, 'critical'),
  p('impersonation', 'brand', 'exact copy of official website scam', 17, 'critical'),
  p('impersonation', 'brand', 'lookalike domain brand impersonation', 17, 'critical'),
];
"""

def main():
    with open(ENGINE, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'TOPUP_EXT' in content:
        print("TOPUP_EXT already exists — skipping.")
        return

    # Find the MASTER_PATTERNS area comment
    insert_marker = "// ═══════════════════════════════════════════════════════════════════════════\n// PATTERN EXTENSIONS (auto-generated)"
    if insert_marker not in content:
        print("ERROR: Cannot find insertion marker")
        return

    # Insert TOPUP_EXT const before the auto-generated block
    content = content.replace(insert_marker, TOPUP.rstrip() + "\n\n" + insert_marker)

    # Add ...TOPUP_EXT spread before closing ]; of MASTER_PATTERNS
    content = content.replace(
        '  ...IMPERSONATION_B8,\n];',
        '  ...IMPERSONATION_B8,\n  ...TOPUP_EXT,\n];'
    )

    with open(ENGINE, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Done! TOPUP_EXT injected.")

if __name__ == '__main__':
    main()
