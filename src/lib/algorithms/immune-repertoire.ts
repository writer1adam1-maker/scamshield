// ============================================================================
// VERIDICT Layer 4: Adaptive Immune Repertoire
// A collection of micro-detector "antibodies" that match known scam patterns.
// Uses clonal selection: successful detections boost affinity, misses mutate.
// Gated by danger signals from Layers 1 and 2.
// ============================================================================

import {
  Antibody,
  AntibodyMatch,
  AntibodyCluster,
  ImmuneRepertoireResult,
  ThreatCategory,
} from './types';

// ---------------------------------------------------------------------------
// The antibody repertoire: 55+ pre-built scam pattern detectors
// ---------------------------------------------------------------------------
const ANTIBODY_REPERTOIRE: Antibody[] = [
  // ==================== PACKAGE DELIVERY SCAMS (1-7) ====================
  {
    id: 'PKG-001',
    name: 'USPS delivery failure',
    pattern: /\b(usps|us\s*postal)\b.{0,60}\b(deliver|package|parcel|shipment)\b.{0,40}\b(fail|unable|attempt|reschedul|hold|pending)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'USPS-impersonating delivery failure scam',
  },
  {
    id: 'PKG-002',
    name: 'USPS tracking link',
    pattern: /\b(usps|postal)\b.{0,40}(track|status|updat).{0,30}(https?:\/\/(?!usps\.com)[^\s]+)/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'USPS tracking with non-USPS link',
  },
  {
    id: 'PKG-003',
    name: 'FedEx delivery scam',
    pattern: /\b(fedex|fed\s*ex)\b.{0,60}\b(deliver|package|parcel|shipment)\b.{0,40}\b(fail|unable|address|reschedul|verify)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'FedEx-impersonating delivery scam',
  },
  {
    id: 'PKG-004',
    name: 'UPS delivery notification scam',
    pattern: /\b(ups)\b.{0,60}\b(deliver|package|parcel)\b.{0,40}\b(fail|unable|pending|update\s*(your|delivery)\s*address)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'UPS-impersonating delivery notification scam',
  },
  {
    id: 'PKG-005',
    name: 'DHL customs fee scam',
    pattern: /\b(dhl)\b.{0,60}\b(customs?|duty|fee|charge|tax)\b.{0,40}\b(pay|clear|process)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'DHL customs fee payment scam',
  },
  {
    id: 'PKG-006',
    name: 'Generic package redelivery fee',
    pattern: /\b(package|parcel|delivery)\b.{0,40}\b(small|nominal|redelivery)?\s*(fee|charge|payment)\b.{0,30}\$?\d/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'Package redelivery fee scam',
  },
  {
    id: 'PKG-007',
    name: 'Amazon delivery issue',
    pattern: /\b(amazon)\b.{0,60}\b(deliver|package|order)\b.{0,40}\b(issue|problem|fail|unable|cannot)\b/i,
    affinity: 0.86,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'Amazon delivery issue scam',
  },

  // ==================== BANK/FINANCIAL PHISHING (8-17) ====================
  {
    id: 'BNK-001',
    name: 'Bank account suspended',
    pattern: /\b(bank|chase|wells\s*fargo|citi|boa|bank\s*of\s*america)\b.{0,60}\b(account)\b.{0,30}\b(suspend|restrict|limit|lock|frozen?|block)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.PHISHING,
    description: 'Bank account suspension phishing',
  },
  {
    id: 'BNK-002',
    name: 'Bank unusual activity',
    pattern: /\b(bank|financial\s*institution)\b.{0,60}\b(unusual|suspicious|unauthori[sz]ed|fraudulent)\s*(activity|transaction|login|access)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Bank unusual activity alert phishing',
  },
  {
    id: 'BNK-003',
    name: 'Verify bank account',
    pattern: /\b(verify|confirm|validate)\s*(your\s*)?(bank|checking|savings)\s*(account|details?|information)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Bank account verification phishing',
  },
  {
    id: 'BNK-004',
    name: 'Wire transfer request',
    pattern: /\b(wire\s*transfer|bank\s*transfer)\b.{0,40}\b(urgent|immediate|today|now|asap)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Urgent wire transfer request scam',
  },
  {
    id: 'BNK-005',
    name: 'PayPal account limited',
    pattern: /\b(paypal)\b.{0,60}\b(account|access)\b.{0,30}\b(limit|restrict|suspend|unusual|verify)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PHISHING,
    description: 'PayPal account limitation phishing',
  },
  {
    id: 'BNK-006',
    name: 'PayPal payment received',
    pattern: /\b(paypal)\b.{0,40}\b(payment|money|transfer)\b.{0,30}\b(received|sent|pending|waiting)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.PHISHING,
    description: 'Fake PayPal payment notification',
  },
  {
    id: 'BNK-007',
    name: 'Zelle/Venmo scam',
    pattern: /\b(zelle|venmo|cashapp|cash\s*app)\b.{0,40}\b(payment|transfer|money|sent|received|request)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.PHISHING,
    description: 'Peer-to-peer payment app scam',
  },
  {
    id: 'BNK-008',
    name: 'Credit card charge dispute',
    pattern: /\b(credit\s*card|visa|mastercard|amex)\b.{0,40}\b(charge|transaction|purchase)\b.{0,30}\b(unauthori[sz]ed|suspicious|dispute|fraud)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.PHISHING,
    description: 'Credit card fraud alert phishing',
  },
  {
    id: 'BNK-009',
    name: 'Gift card payment demand',
    pattern: /\b(pay|send|purchase)\b.{0,30}\b(gift\s*cards?|itunes?\s*cards?|google\s*play\s*cards?|steam\s*cards?|amazon\s*cards?)\b/i,
    affinity: 0.95,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Gift card payment demand — classic scam payment method',
  },
  {
    id: 'BNK-010',
    name: 'Refund overpayment scam',
    pattern: /\b(refund|overpay|overpaid|overcharg)\b.{0,60}\b(return|send\s*back|wire|transfer)\b.{0,30}\b(differ|excess|extra|remain)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Overpayment refund scam',
  },

  // ==================== AMAZON / E-COMMERCE SCAMS (18-23) ====================
  {
    id: 'ECM-001',
    name: 'Amazon account verification',
    pattern: /\b(amazon)\b.{0,60}\b(verify|confirm|update)\b.{0,30}\b(account|payment|billing|information|details)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PHISHING,
    description: 'Amazon account verification phishing',
  },
  {
    id: 'ECM-002',
    name: 'Amazon order you didnt place',
    pattern: /\b(amazon)\b.{0,40}\b(order|purchase)\b.{0,60}\b(you\s*(did\s*not|didn'?t)|cancel|unauthori[sz]ed)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Fake Amazon unauthorized order notification',
  },
  {
    id: 'ECM-003',
    name: 'Amazon Prime renewal',
    pattern: /\b(amazon\s*prime)\b.{0,40}\b(renew|expir|cancel|charg|bill)\b/i,
    affinity: 0.84,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.PHISHING,
    description: 'Amazon Prime subscription renewal scam',
  },
  {
    id: 'ECM-004',
    name: 'Netflix subscription scam',
    pattern: /\b(netflix)\b.{0,60}\b(account|subscription|payment|membership)\b.{0,30}\b(suspend|cancel|expir|fail|update|verify)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Netflix subscription scam',
  },
  {
    id: 'ECM-005',
    name: 'Apple ID locked',
    pattern: /\b(apple\s*id|icloud)\b.{0,40}\b(lock|disable|suspend|verify|confirm|unusual)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.PHISHING,
    description: 'Apple ID / iCloud account lockout phishing',
  },
  {
    id: 'ECM-006',
    name: 'Microsoft account alert',
    pattern: /\b(microsoft|outlook|office\s*365)\b.{0,60}\b(account|sign[- ]in|login|password)\b.{0,30}\b(unusual|suspicious|block|verify|expire)\b/i,
    affinity: 0.86,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Microsoft account security alert phishing',
  },

  // ==================== CRYPTO / INVESTMENT SCAMS (24-31) ====================
  {
    id: 'CRY-001',
    name: 'Crypto guaranteed returns',
    pattern: /\b(bitcoin|btc|crypto|ethereum|eth)\b.{0,60}\b(guaranteed|assured|certain)\b.{0,30}\b(return|profit|income|gain)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.CRYPTO,
    description: 'Cryptocurrency guaranteed returns scam',
  },
  {
    id: 'CRY-002',
    name: 'Crypto doubling scam',
    pattern: /\b(send|transfer|deposit)\b.{0,30}\b(bitcoin|btc|eth|crypto)\b.{0,40}\b(double|triple|10x|100x|return|back)\b/i,
    affinity: 0.95,
    generation: 1,
    falsePositiveRate: 0.01,
    category: ThreatCategory.CRYPTO,
    description: 'Send crypto to double it scam',
  },
  {
    id: 'CRY-003',
    name: 'Crypto wallet verification',
    pattern: /\b(crypto|bitcoin|wallet|metamask)\b.{0,40}\b(verify|validate|sync|connect|confirm)\b.{0,30}\b(wallet|seed|phrase|key)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.CRYPTO,
    description: 'Crypto wallet/seed phrase phishing',
  },
  {
    id: 'CRY-004',
    name: 'Crypto airdrop scam',
    pattern: /\b(airdrop|free\s*(token|coin|crypto|nft))\b.{0,40}\b(claim|collect|receive|connect\s*wallet)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.CRYPTO,
    description: 'Fake crypto airdrop / free token scam',
  },
  {
    id: 'CRY-005',
    name: 'Crypto investment platform',
    pattern: /\b(invest|trading)\b.{0,30}\b(platform|bot|system|algorithm)\b.{0,40}\b(\d+%|guaranteed|daily\s*(return|profit|income))\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.CRYPTO,
    description: 'Fake crypto investment platform scam',
  },
  {
    id: 'CRY-006',
    name: 'NFT scam',
    pattern: /\b(nft|non[- ]fungible)\b.{0,60}\b(free|mint|claim|exclusive|limited|airdrop)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.CRYPTO,
    description: 'NFT minting / airdrop scam',
  },
  {
    id: 'CRY-007',
    name: 'Pig butchering setup',
    pattern: /\b(wrong\s*number|sorry|hi\s+there)\b.{0,100}\b(invest|trading|bitcoin|crypto|forex)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.CRYPTO,
    description: 'Pig butchering (wrong number → crypto investment) setup',
  },
  {
    id: 'CRY-008',
    name: 'Crypto recovery scam',
    pattern: /\b(recover|retriev|get\s*back)\b.{0,30}\b(stolen|lost|scammed?)\b.{0,30}\b(crypto|bitcoin|funds?|money)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.CRYPTO,
    description: 'Crypto/funds recovery scam (scamming scam victims)',
  },

  // ==================== IRS / GOVERNMENT SCAMS (32-38) ====================
  {
    id: 'GOV-001',
    name: 'IRS tax debt threat',
    pattern: /\b(irs|internal\s*revenue)\b.{0,60}\b(owe|debt|tax|lien|levy|garnish|seiz)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.IRS_GOV,
    description: 'IRS tax debt / levy threat scam',
  },
  {
    id: 'GOV-002',
    name: 'IRS arrest warrant',
    pattern: /\b(irs|tax)\b.{0,40}\b(arrest|warrant|law\s*enforcement|police|marshal)\b/i,
    affinity: 0.95,
    generation: 1,
    falsePositiveRate: 0.01,
    category: ThreatCategory.IRS_GOV,
    description: 'IRS arrest warrant scam — IRS never threatens arrest by phone/text',
  },
  {
    id: 'GOV-003',
    name: 'SSA benefits suspension',
    pattern: /\b(social\s*security|ssa)\b.{0,60}\b(suspend|terminat|cancel|block|frozen?)\b.{0,30}\b(number|benefits?|account)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.IRS_GOV,
    description: 'Social Security number/benefits suspension scam',
  },
  {
    id: 'GOV-004',
    name: 'Government grant scam',
    pattern: /\b(government|federal|state)\s*(grant|funding|stimulus|benefit)\b.{0,60}\b(you('ve| have)\s*(been\s*)?(selected|approved|eligible|qualify))\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.IRS_GOV,
    description: 'Government grant / free money scam',
  },
  {
    id: 'GOV-005',
    name: 'Tax refund phishing',
    pattern: /\b(tax\s*refund|irs\s*refund)\b.{0,40}\b(claim|receive|pending|verify|update)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.IRS_GOV,
    description: 'Tax refund phishing scam',
  },
  {
    id: 'GOV-006',
    name: 'Immigration threat',
    pattern: /\b(immigration|ice|uscis|visa|deportat)\b.{0,60}\b(problem|issue|revoke|cancel|suspend|violat|illegal)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.IRS_GOV,
    description: 'Immigration status threat scam',
  },
  {
    id: 'GOV-007',
    name: 'Medicare/Medicaid scam',
    pattern: /\b(medicare|medicaid)\b.{0,60}\b(new\s*card|replace|update|verify|free|benefit)\b/i,
    affinity: 0.84,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.IRS_GOV,
    description: 'Medicare/Medicaid card or benefits scam',
  },

  // ==================== ROMANCE SCAMS (39-43) ====================
  {
    id: 'ROM-001',
    name: 'Romance - military deployment',
    pattern: /\b(deployed|military|army|soldier|marine|navy)\b.{0,80}\b(send|wire|transfer|money|help|funds?|emergency)\b/i,
    affinity: 0.83,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.ROMANCE,
    description: 'Military deployment romance scam',
  },
  {
    id: 'ROM-002',
    name: 'Romance - stranded abroad',
    pattern: /\b(stranded|stuck|trapped)\b.{0,40}\b(abroad|overseas|foreign|country|airport|hospital)\b.{0,40}\b(money|help|send|wire|transfer)\b/i,
    affinity: 0.86,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.ROMANCE,
    description: 'Stranded abroad romance scam',
  },
  {
    id: 'ROM-003',
    name: 'Romance - inheritance/widow',
    pattern: /\b(widow|widower|late\s+husband|late\s+wife|inheritance|dying|terminal)\b.{0,80}\b(share|split|transfer|help|trust|fund)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.ROMANCE,
    description: 'Widow/inheritance romance scam',
  },
  {
    id: 'ROM-004',
    name: 'Romance - move to another platform',
    pattern: /\b(let'?s?\s+(move|switch|talk|chat)\s+(to|on))\b.{0,30}\b(whatsapp|telegram|hangouts?|signal|kik|email)\b/i,
    affinity: 0.60,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.ROMANCE,
    description: 'Request to move conversation to unmonitored platform',
  },
  {
    id: 'ROM-005',
    name: 'Romance - medical emergency',
    pattern: /\b(hospital|surgery|operation|medical|doctor)\b.{0,60}\b(need|help|money|pay|send|emergency|urgent)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.ROMANCE,
    description: 'Medical emergency financial request scam',
  },

  // ==================== TECH SUPPORT SCAMS (44-49) ====================
  {
    id: 'TEC-001',
    name: 'Microsoft tech support',
    pattern: /\b(microsoft|windows)\b.{0,40}\b(tech(nical)?\s*support|helpdesk|help\s*desk)\b.{0,30}\b(call|phone|contact|dial)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Fake Microsoft tech support scam',
  },
  {
    id: 'TEC-002',
    name: 'Virus detected popup',
    pattern: /\b(virus|malware|trojan|spyware)\s*(has been\s*)?(detected|found)\b.{0,40}\b(call|contact|dial|remove)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Fake virus detection tech support scam',
  },
  {
    id: 'TEC-003',
    name: 'Computer locked warning',
    pattern: /\b(your\s*)?(computer|pc|mac|device)\s*(has\s*been|is)\s*(lock|block|infect|compromis)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Computer locked/infected warning scam',
  },
  {
    id: 'TEC-004',
    name: 'Remote access request',
    pattern: /\b(remote\s*(access|control|connect|desktop))\b.{0,40}\b(anydesk|teamviewer|logmein|screenconnect|ultraviewer)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Remote access tool installation request scam',
  },
  {
    id: 'TEC-005',
    name: 'Antivirus subscription scam',
    pattern: /\b(norton|mcafee|kaspersky|avast|antivirus)\b.{0,40}\b(subscription|renew|expir|charg|auto[- ]?renew|bill)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Fake antivirus subscription renewal scam',
  },
  {
    id: 'TEC-006',
    name: 'Geek Squad scam',
    pattern: /\b(geek\s*squad|best\s*buy)\b.{0,40}\b(subscription|renew|charg|auto[- ]?renew|invoice|bill|refund)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Geek Squad / Best Buy fake invoice scam',
  },

  // ==================== LOTTERY / PRIZE SCAMS (50-53) ====================
  {
    id: 'LOT-001',
    name: 'Lottery winner notification',
    pattern: /\b(lottery|sweepstakes?|raffle|drawing)\b.{0,40}\b(winner|won|selected|awarded|congratulations)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Lottery/sweepstakes winner notification scam',
  },
  {
    id: 'LOT-002',
    name: 'Prize claim fee',
    pattern: /\b(claim|collect|receive)\b.{0,30}\b(prize|winnings?|reward|award)\b.{0,40}\b(fee|tax|charge|pay|transfer|processing)\b/i,
    affinity: 0.94,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Prize claim requiring advance fee scam',
  },
  {
    id: 'LOT-003',
    name: 'Survey reward scam',
    pattern: /\b(complete|fill\s*(out|in)?)\b.{0,20}\b(survey|questionnaire)\b.{0,30}\b(win|receive|earn|get)\b.{0,20}\b(\$|gift\s*card|prize|reward)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Survey reward / gift card phishing',
  },
  {
    id: 'LOT-004',
    name: 'Inheritance from stranger',
    pattern: /\b(inheritance|estate|beneficiary|next[- ]of[- ]kin|unclaimed\s*funds?)\b.{0,60}\b(million|thousand|\$[\d,.]+|usd|gbp|eur)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Inheritance from unknown person scam (419 advance fee)',
  },

  // ==================== EXTORTION / SEXTORTION (54-56) ====================
  {
    id: 'EXT-001',
    name: 'Sextortion email',
    pattern: /\b(recorded|captured|video|webcam|camera)\b.{0,60}\b(adult|porn|explicit|compromis|embarrass)\b.{0,40}\b(bitcoin|btc|payment|send|pay)\b/i,
    affinity: 0.94,
    generation: 1,
    falsePositiveRate: 0.01,
    category: ThreatCategory.GENERIC,
    description: 'Sextortion email scam',
  },
  {
    id: 'EXT-002',
    name: 'Password in subject/body extortion',
    pattern: /\b(your\s*password\s*(is|was)|i\s*know\s*your\s*password)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.GENERIC,
    description: 'Password reveal extortion scam (from leaked databases)',
  },
  {
    id: 'EXT-003',
    name: 'DDoS/hack threat extortion',
    pattern: /\b(ddos|hack|attack)\b.{0,40}\b(your\s*(website|server|business|company))\b.{0,40}\b(bitcoin|btc|payment|ransom|pay)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.GENERIC,
    description: 'DDoS/hack threat extortion scam',
  },

  // ==================== JOB / EMPLOYMENT SCAMS (57-59) ====================
  {
    id: 'JOB-001',
    name: 'Work from home income scam',
    pattern: /\b(work\s*(from)?\s*home)\b.{0,40}\b(earn|make|income|\$\d+)\b.{0,30}\b(per\s*(day|week|hour|month)|daily|weekly)\b/i,
    affinity: 0.84,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.GENERIC,
    description: 'Work from home income promise scam',
  },
  {
    id: 'JOB-002',
    name: 'Job offer advance fee',
    pattern: /\b(job|position|employment|hiring)\b.{0,60}\b(fee|deposit|equipment|training\s*fee|background\s*check\s*fee|pay\s*upfront)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Job offer requiring upfront payment scam',
  },
  {
    id: 'JOB-003',
    name: 'Mystery shopper scam',
    pattern: /\b(mystery\s*shopp|secret\s*shopp)\b.{0,40}\b(check|money\s*order|wire|deposit|cash)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Mystery shopper check cashing scam',
  },

  // ==================== SOCIAL MEDIA SCAMS (60-69) ====================
  {
    id: 'SOC-001',
    name: 'Instagram verification scam',
    pattern: /\b(instagram|ig)\b.{0,40}\b(verif(y|ied|ication)|blue\s*(check|badge|tick))\b.{0,30}\b(apply|get|claim|form|link)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Instagram verification badge scam',
  },
  {
    id: 'SOC-002',
    name: 'Social media account recovery scam',
    pattern: /\b(account|profile)\s*(hack|compromis|stolen|lock)\b.{0,40}\b(recover|restore|unlock|fix)\b.{0,30}\b(dm|message|contact|link)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Social media account recovery scam',
  },
  {
    id: 'SOC-003',
    name: 'Fake celebrity giveaway',
    pattern: /\b(giveaway|give\s*away)\b.{0,60}\b(follow|like|share|retweet|comment)\b.{0,30}\b(win|chance|selected|drawn)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Fake celebrity/influencer giveaway scam',
  },
  {
    id: 'SOC-004',
    name: 'TikTok/YouTube promotion scam',
    pattern: /\b(tiktok|youtube|twitch)\b.{0,40}\b(promot|boost|grow|followers?|subscribers?|views?)\b.{0,30}\b(guaranteed|fast|instant|cheap|buy)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Social media promotion/follower buying scam',
  },
  {
    id: 'SOC-005',
    name: 'Facebook Marketplace advance payment',
    pattern: /\b(facebook|fb)\s*(marketplace)?\b.{0,40}\b(pay|send|transfer|deposit)\b.{0,30}\b(before|advance|upfront|first)\b/i,
    affinity: 0.83,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Facebook Marketplace advance payment scam',
  },
  {
    id: 'SOC-006',
    name: 'Copyright strike phishing',
    pattern: /\b(copyright|dmca)\s*(strike|violation|claim|notice|infringement)\b.{0,40}\b(appeal|review|verify|login|sign\s*in)\b/i,
    affinity: 0.86,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Fake copyright strike/DMCA notice phishing',
  },
  {
    id: 'SOC-007',
    name: 'Social media sponsorship scam',
    pattern: /\b(brand|sponsor|partnership|collaboration|ambassador)\b.{0,40}\b(offer|opportunity|deal|proposal)\b.{0,30}\b(dm|message|email|click)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Fake brand sponsorship/ambassador offer',
  },
  {
    id: 'SOC-008',
    name: 'WhatsApp group add scam',
    pattern: /\b(whatsapp|telegram)\s*(group|channel)\b.{0,40}\b(invest|trading|forex|crypto|earn|profit)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'WhatsApp/Telegram investment group scam',
  },
  {
    id: 'SOC-009',
    name: 'Twitter/X impersonation scam',
    pattern: /\b(twitter|x\.com)\b.{0,40}\b(support|help|verified|official)\b.{0,30}\b(dm|message|contact|form)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.09,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Twitter/X impersonation support scam',
  },
  {
    id: 'SOC-010',
    name: 'Dating app sextortion',
    pattern: /\b(tinder|bumble|hinge|dating)\b.{0,60}\b(photo|video|nude|explicit|intimate)\b.{0,40}\b(share|send|post|leak|expose)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.SOCIAL_MEDIA,
    description: 'Dating app sextortion scam',
  },

  // ==================== SUBSCRIPTION TRAP SCAMS (70-76) ====================
  {
    id: 'SUB-001',
    name: 'Free trial to paid subscription',
    pattern: /\b(free\s*trial)\b.{0,40}\b(credit\s*card|payment\s*(info|details|method)|billing)\b/i,
    affinity: 0.72,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Free trial requiring payment info — potential subscription trap',
  },
  {
    id: 'SUB-002',
    name: 'Hidden recurring charge',
    pattern: /\b(auto[- ]?renew|recurring\s*(charge|billing|payment))\b.{0,40}\b(cancel|stop|opt[- ]?out|unsubscribe)\b/i,
    affinity: 0.68,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Hidden auto-renewal/recurring charge scheme',
  },
  {
    id: 'SUB-003',
    name: 'Fake antivirus subscription renewal',
    pattern: /\b(subscription|license|plan)\s*(renew|expir|auto[- ]?charg)\b.{0,40}\$[\d,.]+/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Fake subscription renewal with inflated charge',
  },
  {
    id: 'SUB-004',
    name: 'Cancel subscription phishing',
    pattern: /\b(cancel|manage)\s*(your\s*)?(subscription|membership|plan)\b.{0,30}\b(click|login|sign\s*in|verify)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.09,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Subscription cancellation phishing',
  },
  {
    id: 'SUB-005',
    name: 'Streaming service charge scam',
    pattern: /\b(netflix|disney|hulu|spotify|hbo|paramount)\b.{0,40}\b(charg|bill|invoice|payment)\b.{0,30}\$[\d,.]+/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Fake streaming service charge notification',
  },
  {
    id: 'SUB-006',
    name: 'App store charge alert',
    pattern: /\b(app\s*store|google\s*play|itunes)\b.{0,40}\b(purchase|charg|transaction|receipt)\b.{0,30}\$[\d,.]+/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Fake app store purchase notification',
  },
  {
    id: 'SUB-007',
    name: 'Cloud storage upgrade scam',
    pattern: /\b(icloud|google\s*drive|dropbox|onedrive)\b.{0,40}\b(storage\s*(full|limit)|upgrade|expir|payment)\b/i,
    affinity: 0.76,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.SUBSCRIPTION_TRAP,
    description: 'Fake cloud storage upgrade/payment scam',
  },

  // ==================== FAKE CHARITY SCAMS (77-83) ====================
  {
    id: 'CHR-001',
    name: 'Disaster relief charity scam',
    pattern: /\b(hurricane|earthquake|flood|wildfire|tsunami|disaster)\b.{0,60}\b(donat|contribute|help|give|fund)\b/i,
    affinity: 0.65,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Disaster relief donation solicitation — verify charity before donating',
  },
  {
    id: 'CHR-002',
    name: 'Fake charity wire transfer',
    pattern: /\b(charit|foundation|humanitarian|relief)\b.{0,40}\b(wire|transfer|western\s*union|bitcoin|gift\s*card)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Charity requesting untraceable payment method — strong scam indicator',
  },
  {
    id: 'CHR-003',
    name: 'Sick child/medical charity',
    pattern: /\b(sick|dying|cancer|hospital)\s*(child|kid|baby|patient)\b.{0,40}\b(donat|fund|help|save|money|gofundme)\b/i,
    affinity: 0.70,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Sick child/medical donation solicitation',
  },
  {
    id: 'CHR-004',
    name: 'Veteran/military charity scam',
    pattern: /\b(veteran|military|soldier|troops?|wounded\s*warrior)\b.{0,40}\b(donat|fund|contribute|support|help)\b/i,
    affinity: 0.65,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Veteran/military charity solicitation — verify before donating',
  },
  {
    id: 'CHR-005',
    name: 'Tax-deductible donation scam',
    pattern: /\b(tax[- ]?deductible|tax\s*(benefit|write[- ]?off|receipt))\b.{0,40}\b(donat|contribut|give)\b/i,
    affinity: 0.60,
    generation: 1,
    falsePositiveRate: 0.18,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Tax-deductible donation claim — may be fake charity',
  },
  {
    id: 'CHR-006',
    name: 'Charity pressure tactics',
    pattern: /\b(charit|donat)\b.{0,40}\b(match(ing)?|double|triple|deadline|today\s*only|last\s*chance)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Charity using pressure tactics — matching/deadline urgency',
  },
  {
    id: 'CHR-007',
    name: 'GoFundMe/crowdfunding scam',
    pattern: /\b(gofundme|crowdfund|fundrais)\b.{0,40}\b(share|donat|help|urgent|emergency|please)\b/i,
    affinity: 0.55,
    generation: 1,
    falsePositiveRate: 0.20,
    category: ThreatCategory.FAKE_CHARITY,
    description: 'Crowdfunding solicitation — verify authenticity before donating',
  },

  // ==================== RENTAL/HOUSING SCAMS (84-90) ====================
  {
    id: 'RNT-001',
    name: 'Rental deposit before viewing',
    pattern: /\b(rent|rental|apartment|house|room)\b.{0,40}\b(deposit|advance|first\s*(month|payment))\b.{0,30}\b(before|prior|without)\s*(viewing|seeing|visit)/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Rental deposit demanded before viewing — classic rental scam',
  },
  {
    id: 'RNT-002',
    name: 'Rental too good to be true',
    pattern: /\b(rent|rental|apartment|house)\b.{0,40}\b(below\s*market|incredible\s*deal|amazing\s*price|way\s*under|bargain)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Rental listing with too-good-to-be-true pricing',
  },
  {
    id: 'RNT-003',
    name: 'Landlord abroad rental scam',
    pattern: /\b(landlord|owner|property)\b.{0,60}\b(abroad|overseas|travel|out\s*of\s*(town|country|state))\b.{0,40}\b(key|wire|transfer|deposit|mail)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Landlord abroad scam — cannot show property, requests wire transfer',
  },
  {
    id: 'RNT-004',
    name: 'Rental application fee scam',
    pattern: /\b(application|processing|background\s*check)\s*(fee|charge|cost)\b.{0,30}\b(pay|send|wire|transfer|zelle|venmo)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Excessive rental application/processing fee',
  },
  {
    id: 'RNT-005',
    name: 'Rental listing duplicate',
    pattern: /\b(craigslist|zillow|trulia|apartments\.com|realtor)\b.{0,40}\b(copy|duplicate|repost|stolen|fake\s*listing)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Potentially duplicated/stolen rental listing',
  },
  {
    id: 'RNT-006',
    name: 'Security deposit wire transfer',
    pattern: /\b(security\s*deposit|holding\s*deposit|reservation\s*fee)\b.{0,40}\b(wire|western\s*union|bitcoin|gift\s*card|zelle)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Security deposit via untraceable payment — almost certainly a scam',
  },
  {
    id: 'RNT-007',
    name: 'Rental sight-unseen pressure',
    pattern: /\b(many\s*(other\s*)?(applicant|people|tenant)|high\s*demand|won'?t\s*last)\b.{0,40}\b(rent|apartment|house|room|unit)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.RENTAL_HOUSING,
    description: 'Rental pressure to commit sight-unseen due to "high demand"',
  },

  // ==================== STUDENT LOAN SCAMS (91-97) ====================
  {
    id: 'STU-001',
    name: 'Student loan forgiveness scam',
    pattern: /\b(student\s*loan)\b.{0,40}\b(forgiv|cancel|discharg|eliminat|wipe)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Student loan forgiveness offer — verify with official sources',
  },
  {
    id: 'STU-002',
    name: 'Student loan consolidation fee',
    pattern: /\b(student\s*loan|federal\s*loan)\b.{0,40}\b(consolidat|refinanc)\b.{0,30}\b(fee|pay|upfront|advance|processing)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Student loan consolidation with upfront fee scam',
  },
  {
    id: 'STU-003',
    name: 'Student loan urgent deadline',
    pattern: /\b(student\s*loan)\b.{0,40}\b(deadline|expires?|act\s*now|limited\s*time|last\s*chance)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Student loan scam with artificial urgency/deadline',
  },
  {
    id: 'STU-004',
    name: 'Student loan SSN request',
    pattern: /\b(student\s*loan|loan\s*servic)\b.{0,40}\b(ssn|social\s*security|fsa\s*id|password|login)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Student loan service requesting SSN/credentials — likely phishing',
  },
  {
    id: 'STU-005',
    name: 'Department of Education impersonation',
    pattern: /\b(department\s*of\s*education|dept\s*of\s*ed|federal\s*student\s*aid)\b.{0,40}\b(call|contact|verify|login|update)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Department of Education impersonation',
  },
  {
    id: 'STU-006',
    name: 'Student loan payment reduction scam',
    pattern: /\b(lower|reduce|cut)\s*(your\s*)?(student\s*loan|monthly)\s*(payment|bill)\b.{0,30}\b(guaranteed|instant|fast|easy)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.09,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Student loan payment reduction scam',
  },
  {
    id: 'STU-007',
    name: 'Scholarship advance fee scam',
    pattern: /\b(scholarship|grant|financial\s*aid)\b.{0,40}\b(selected|awarded|approved)\b.{0,30}\b(fee|pay|deposit|processing)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.STUDENT_LOAN,
    description: 'Scholarship/grant requiring advance fee payment',
  },

  // ==================== ADDITIONAL HIGH-VALUE ANTIBODIES (98-105) ====================
  {
    id: 'ADD-001',
    name: 'AI-generated deepfake scam',
    pattern: /\b(video\s*call|voice\s*message|audio)\b.{0,40}\b(boss|ceo|cfo|manager|director|executive)\b.{0,30}\b(transfer|wire|send|pay|urgent)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.PHISHING,
    description: 'Potential deepfake/voice clone CEO fraud',
  },
  {
    id: 'ADD-002',
    name: 'QR code payment scam',
    pattern: /\b(scan\s*(this\s*)?(qr|code))\b.{0,40}\b(pay|send|transfer|verify|login|sign\s*in)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.PHISHING,
    description: 'QR code used to redirect to payment/phishing page',
  },
  {
    id: 'ADD-003',
    name: 'Fake invoice/purchase order',
    pattern: /\b(invoice|purchase\s*order|receipt)\s*#?\s*\d+\b.{0,40}\b(attached|enclosed|below|due|overdue|pay)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Fake invoice or purchase order scam',
  },
  {
    id: 'ADD-004',
    name: 'Business email compromise',
    pattern: /\b(ceo|cfo|president|director|managing\s*partner)\b.{0,40}\b(need\s+you\s+to|please\s+(handle|process|take\s+care))\b.{0,30}\b(wire|transfer|payment|invoice)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.PHISHING,
    description: 'Business email compromise (BEC) — executive impersonation',
  },
  {
    id: 'ADD-005',
    name: 'SIM swap preparation',
    pattern: /\b(phone|mobile|cell)\s*(number|carrier|provider)\b.{0,40}\b(verify|confirm|transfer|port|switch)\b/i,
    affinity: 0.70,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.PHISHING,
    description: 'Potential SIM swap attack preparation',
  },
  {
    id: 'ADD-006',
    name: 'Brushing scam indicators',
    pattern: /\b(package|parcel|item)\s*(you\s*)?(did\s*not|didn'?t|never)\s*(order|buy|purchase)\b/i,
    affinity: 0.65,
    generation: 1,
    falsePositiveRate: 0.15,
    category: ThreatCategory.PACKAGE_DELIVERY,
    description: 'Brushing scam — unsolicited package with review/info request',
  },
  {
    id: 'ADD-007',
    name: 'Fake debt collection',
    pattern: /\b(debt\s*collect|collections?\s*agency|past\s*due|outstanding\s*balance)\b.{0,40}\b(pay|settle|arrange|immediately|today|legal\s*action)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.GENERIC,
    description: 'Fake debt collection scam',
  },
  {
    id: 'ADD-008',
    name: 'Jury duty scam',
    pattern: /\b(jury\s*duty|jury\s*service|summons)\b.{0,40}\b(miss|fail|fine|warrant|arrest|pay)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.IRS_GOV,
    description: 'Jury duty scam — threatening arrest for missing jury service',
  },

  // ==================== TOLL / HIGHWAY SCAMS (NEW - 900% increase 2025) ====================
  {
    id: 'TOL-001',
    name: 'Toll road unpaid balance',
    pattern: /(e-zpass|ezpass|sunpass|fastrak|toll|ipass).*(unpaid|balance|owed|due|outstanding)/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.PHISHING,
    description: 'Toll road service impersonation scam — unpaid balance',
  },
  {
    id: 'TOL-002',
    name: 'Toll avoid fee/collections threat',
    pattern: /toll.*(avoid.*(fee|penalt|collect|suspend))/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.PHISHING,
    description: 'Toll scam threatening fees, penalties, or collections',
  },

  // ==================== PIG BUTCHERING / WRONG NUMBER ====================
  {
    id: 'PIG-001',
    name: 'Wrong number seem nice opener',
    pattern: /wrong number.*(seem.nice|nice.talking|what do you do)/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.ROMANCE,
    description: 'Pig butchering "wrong number" opener — seems friendly, leads to investment scam',
  },
  {
    id: 'PIG-002',
    name: 'Reconnect memory with profile/link',
    pattern: /(long time no see|didn.t we meet|remember me).{0,50}(profile|link|website)/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.ROMANCE,
    description: 'Pig butchering reconnect opener leading to external link/profile',
  },
  {
    id: 'PIG-003',
    name: 'Investment guaranteed returns romance',
    pattern: /(investment|crypto|trading).{0,100}(guaranteed|profit|return|100%)/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.CRYPTO,
    description: 'Pig butchering investment pitch — guaranteed returns',
  },

  // ==================== BOSS BEC SCAMS ====================
  {
    id: 'BEC-001',
    name: 'Boss gift card purchase demand',
    pattern: /need you to.{0,50}(gift card|purchase.*gift|buy.*itunes|google play)/i,
    affinity: 0.94,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'BEC scam — executive impersonation requesting gift card purchase',
  },
  {
    id: 'BEC-002',
    name: 'Executive urgent wire transfer',
    pattern: /(ceo|president|director|manager).{0,100}(wire transfer|send money|urgent|confidential)/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'BEC scam — executive impersonation requesting urgent/confidential wire transfer',
  },

  // ==================== DIGITAL ARREST SCAMS (2026 threat) ====================
  {
    id: 'ARR-001',
    name: 'FBI illegal activity arrest threat',
    pattern: /(fbi|federal|arrest|warrant).{0,100}(money laundering|illegal|cooperate|avoid arrest)/i,
    affinity: 0.95,
    generation: 1,
    falsePositiveRate: 0.01,
    category: ThreatCategory.IRS_GOV,
    description: 'Digital arrest scam — impersonating FBI/federal agency threatening arrest',
  },
  {
    id: 'ARR-002',
    name: 'Phone/IP linked to illegal investigation',
    pattern: /your.{0,20}(phone number|ip address|computer).{0,50}(linked|associated|flagged).{0,50}(illegal|crime|investigation)/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.IRS_GOV,
    description: 'Digital arrest scam — claiming device is linked to criminal investigation',
  },

  // ==================== RECOVERY SCAMS ====================
  {
    id: 'REC-001',
    name: 'Recover lost/stolen/scam funds',
    pattern: /(recover|reclaim|get back).{0,50}(lost|stolen|scammed).{0,50}(funds|money|crypto)/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Recovery scam — offering to reclaim lost funds for an upfront fee',
  },
  {
    id: 'REC-002',
    name: 'Victim recovery compensation fee',
    pattern: /victims.{0,50}(recovery|refund|compensation).{0,50}(fee|payment|deposit)/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Recovery scam targeting prior scam victims — requires fee to claim compensation',
  },

  // ==================== PAYMENT METHOD RED FLAGS ====================
  {
    id: 'PAY-001',
    name: 'Gift card as payment demand',
    pattern: /(gift card|google play|itunes|amazon card).{0,100}(payment|send|purchase|buy)/i,
    affinity: 0.95,
    generation: 1,
    falsePositiveRate: 0.01,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Gift card demanded as payment — nearly universal scam indicator',
  },
  {
    id: 'PAY-002',
    name: 'P2P / wire payment request',
    pattern: /(zelle|cashapp|venmo|western union|moneygram).{0,50}(send|transfer|pay)/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.ADVANCE_FEE,
    description: 'Untraceable P2P or wire payment requested — common scam payment method',
  },

  // ==================== MICROSOFT / TECH SUPPORT (EXTENDED) ====================
  {
    id: 'TEC-007',
    name: 'Microsoft support toll-free number',
    pattern: /microsoft.{0,50}(support|helpline|technical).{0,50}(\+?1.{0,5}(844|833|888|855|877))/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Fake Microsoft support number — toll-free scam call center',
  },
  {
    id: 'TEC-008',
    name: 'Windows Defender / Firewall threat popup',
    pattern: /(windows defender|firewall|security).{0,50}(threat detected|compromised|blocked)/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.TECH_SUPPORT,
    description: 'Fake Windows Defender / Firewall threat notification popup',
  },

  // ==================== QR CODE PHISHING ====================
  {
    id: 'QRC-001',
    name: 'QR code verify/claim/access',
    pattern: /scan.{0,30}(qr|code|barcode).{0,50}(verify|confirm|claim|access)/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.PHISHING,
    description: 'QR code phishing — scanning redirects to verification or claim page',
  },

  // ==================== MARKETPLACE FRAUD (v2 expansion) ====================
  {
    id: 'MKT-001',
    name: 'Marketplace advance pay then disappear',
    pattern: /\b(craigslist|facebook\s*marketplace|offerup|letgo|mercari|ebay)\b.{0,60}\b(pay|send|transfer|zelle|cashapp|venmo)\b.{0,30}\b(before|advance|upfront|first|ship)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Online marketplace advance payment before item delivery scam',
  },
  {
    id: 'MKT-002',
    name: 'Overpayment check marketplace',
    pattern: /\b(check|money\s*order|cashier.?s?\s*check)\b.{0,60}\b(overpay|extra|more\s*than|send\s*back|return\s*differ)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Marketplace overpayment scam — sends fake check, asks victim to return difference',
  },
  {
    id: 'MKT-003',
    name: 'Marketplace buyer protection scam',
    pattern: /\b(buyer\s*protection|seller\s*protection|escrow|hold|secure\s*payment)\b.{0,40}\b(click|link|verify|release|confirm)\b/i,
    affinity: 0.86,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Fake buyer/seller protection or escrow service on marketplace',
  },
  {
    id: 'MKT-004',
    name: 'Marketplace outside platform redirect',
    pattern: /\b(move|continue|talk|chat|deal)\b.{0,30}\b(off\s*(platform|site)|outside|private|direct)\b/i,
    affinity: 0.72,
    generation: 1,
    falsePositiveRate: 0.14,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Insistence to move transaction outside the marketplace platform',
  },
  {
    id: 'MKT-005',
    name: 'Ticket resale counterfeit',
    pattern: /\b(ticket|concert|event|game|show)\b.{0,40}\b(resell|resale|transfer|last\s*minute|below\s*face)\b.{0,30}\b(zelle|cashapp|venmo|pay)\b/i,
    affinity: 0.84,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Ticket resale scam — counterfeit or non-existent tickets sold via P2P payment',
  },
  {
    id: 'MKT-006',
    name: 'Marketplace vehicle/car deposit',
    pattern: /\b(car|vehicle|truck|motorcycle|rv)\b.{0,60}\b(deposit|hold|reserve)\b.{0,30}\b(wire|zelle|cashapp|venmo|paypal|money\s*order)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.MARKETPLACE_FRAUD,
    description: 'Vehicle deposit scam via untraceable payment method',
  },

  // ==================== ELDER / GRANDPARENT SCAMS (v2 expansion) ====================
  {
    id: 'ELD-001',
    name: 'Grandparent emergency call',
    pattern: /\b(grandm[ao]|grandp[ao]|nana|papa|grandparents?)\b.{0,40}\b(help|emergency|jail|arrest|accident|hospital|bail)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Grandparent scam — impersonates grandchild in emergency needing money',
  },
  {
    id: 'ELD-002',
    name: 'Lawyer bail money impersonation',
    pattern: /\b(lawyer|attorney|public\s*defender|court\s*official)\b.{0,60}\b(grandchild|grandson|granddaughter|family\s*member)\b.{0,30}\b(bail|bond|fee|release)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Grandparent scam variant — fake lawyer calling about grandchild\'s bail',
  },
  {
    id: 'ELD-003',
    name: 'Senior sweepstakes notification',
    pattern: /\b(senior|retirement|medicare|aarp)\b.{0,60}\b(selected|winner|prize|reward|grant|benefit)\b.{0,30}\b(claim|collect|fee|pay|shipping)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Senior-targeted sweepstakes or prize scam',
  },
  {
    id: 'ELD-004',
    name: 'Caregiver fraud',
    pattern: /\b(caregiv|home\s*(health|care)|nurse|helper|assist)\b.{0,60}\b(power\s*of\s*attorney|bank|account|access|manage)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Caregiver seeking financial control / power of attorney from senior',
  },
  {
    id: 'ELD-005',
    name: 'Grandparent send cash courier',
    pattern: /\b(don.?t\s*tell|keep\s*(it\s*)?secret|just\s*between\s*us)\b.{0,60}\b(cash|envelope|courier|deliver|send)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Cash courier pickup — hallmark of grandparent scam',
  },
  {
    id: 'ELD-006',
    name: 'Elder Medicare identity theft',
    pattern: /\b(medicare|medicaid|social\s*security)\b.{0,40}\b(new\s*card|replacement|benefit\s*(update|change|increas))\b.{0,30}\b(ssn|social\s*security|bank|verify)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.ELDER_SCAM,
    description: 'Medicare/SSA identity theft targeting seniors',
  },

  // ==================== TICKET SCAMS (v2 expansion) ====================
  {
    id: 'TKT-001',
    name: 'Concert ticket last minute deal',
    pattern: /\b(concert|show|festival|event|game|match)\b.{0,40}\b(ticket|seat|pass)\b.{0,30}\b(last\s*minute|tonight|today|urgent|sell\s*fast)\b/i,
    affinity: 0.75,
    generation: 1,
    falsePositiveRate: 0.12,
    category: ThreatCategory.TICKET_SCAM,
    description: 'Last-minute ticket sales — high risk of counterfeit or no-show',
  },
  {
    id: 'TKT-002',
    name: 'Third-party ticket seller non-refundable',
    pattern: /\b(ticket|seat|entry)\b.{0,40}\b(non[- ]?refundable|no\s*refund|all\s*sales\s*final)\b.{0,30}\b(transfer|send|pdf|download|email)\b/i,
    affinity: 0.80,
    generation: 1,
    falsePositiveRate: 0.09,
    category: ThreatCategory.TICKET_SCAM,
    description: 'Non-refundable ticket from third-party — common counterfeit ticket tactic',
  },
  {
    id: 'TKT-003',
    name: 'VIP backstage access scam',
    pattern: /\b(vip|backstage|meet\s*and\s*greet|exclusive\s*(access|pass))\b.{0,40}\b(limited|last\s*few|today\s*only|special\s*price)\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.TICKET_SCAM,
    description: 'Fake VIP / backstage pass scam',
  },
  {
    id: 'TKT-004',
    name: 'Sports ticket barcode reuse scam',
    pattern: /\b(season\s*ticket|playoff|super\s*bowl|world\s*series|championship)\b.{0,40}\b(ticket|seat|pass)\b.{0,30}\b(buy|purchase|get|available|selling)\b/i,
    affinity: 0.72,
    generation: 1,
    falsePositiveRate: 0.13,
    category: ThreatCategory.TICKET_SCAM,
    description: 'High-demand sports ticket — barcode reuse / duplicate ticket risk',
  },

  // ==================== INVESTMENT FRAUD (v2 expansion) ====================
  {
    id: 'INV-001',
    name: 'Ponzi scheme recruitment',
    pattern: /\b(invest|investment)\b.{0,40}\b(friend|family|recruit|refer|bring)\b.{0,30}\b(earn|commission|percentage|bonus|reward)\b/i,
    affinity: 0.83,
    generation: 1,
    falsePositiveRate: 0.07,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'Pyramid / Ponzi scheme — recruitment-based earnings',
  },
  {
    id: 'INV-002',
    name: 'Unregistered securities offer',
    pattern: /\b(pre[- ]IPO|private\s*placement|unregistered|offshore\s*fund|accredited\s*investor)\b.{0,60}\b(invest|opportunity|return|profit|exclusive)\b/i,
    affinity: 0.85,
    generation: 1,
    falsePositiveRate: 0.06,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'Unregistered securities or pre-IPO investment fraud',
  },
  {
    id: 'INV-003',
    name: 'Forex / binary options scam',
    pattern: /\b(forex|fx\s*trading|binary\s*(options?|trade)|spread\s*betting)\b.{0,60}\b(guaranteed|profit|daily|weekly|consistent|returns)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'Fake Forex or binary options trading scam',
  },
  {
    id: 'INV-004',
    name: 'Pump and dump stock',
    pattern: /\b(stock|share|ticker|symbol)\b.{0,40}\b(tip|hot|inside|sure\s*thing|going\s*to\s*(moon|explode|skyrocket))\b/i,
    affinity: 0.82,
    generation: 1,
    falsePositiveRate: 0.08,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'Pump-and-dump stock promotion',
  },
  {
    id: 'INV-005',
    name: 'High yield investment program',
    pattern: /\b(hyip|high[\s-]yield|passive\s*income|autopilot)\b.{0,40}\b(\d+%|per\s*(day|week|month)|daily\s*return|weekly\s*payout)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'High Yield Investment Program (HYIP) scam',
  },
  {
    id: 'INV-006',
    name: 'AI trading bot guaranteed profit',
    pattern: /\b(ai|bot|algorithm|automated|robot)\b.{0,40}\b(trad(e|ing)|invest)\b.{0,30}\b(guaranteed|profit|accurate|winning|success\s*rate)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.INVESTMENT_FRAUD,
    description: 'AI/bot trading scam promising guaranteed profits',
  },

  // ==================== EMPLOYMENT SCAMS (v2 expansion) ====================
  {
    id: 'EMP-001',
    name: 'Reshipping mule job',
    pattern: /\b(package|parcel|shipment)\b.{0,30}\b(reship|re[-\s]ship|forward|receive\s*and\s*send)\b.{0,30}\b(work\s*(from)?\s*home|earn|job|income)\b/i,
    affinity: 0.92,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.EMPLOYMENT_SCAM,
    description: 'Reshipping mule job — used to fence stolen goods',
  },
  {
    id: 'EMP-002',
    name: 'Money mule job',
    pattern: /\b(transfer|wire|move)\b.{0,30}\b(funds?|money|payment)\b.{0,30}\b(work\s*(from)?\s*home|commission|agent|representative)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.EMPLOYMENT_SCAM,
    description: 'Money mule recruitment — handling stolen funds as "agent"',
  },
  {
    id: 'EMP-003',
    name: 'Fake remote job offer credential harvest',
    pattern: /\b(remote\s*(job|work|position)|work\s*from\s*home)\b.{0,60}\b(ssn|social\s*security|bank\s*account|direct\s*deposit|id\s*verification)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.EMPLOYMENT_SCAM,
    description: 'Fake remote job requiring SSN/bank info for "payroll"',
  },
  {
    id: 'EMP-004',
    name: 'Fake check payroll scam',
    pattern: /\b(payroll|check|paycheck)\b.{0,40}\b(deposit|advance|receive\s*first|equipment|training)\b.{0,30}\b(return|send\s*back|reimburse)\b/i,
    affinity: 0.90,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.EMPLOYMENT_SCAM,
    description: 'Fake check payroll scam — sends check then asks for portion back',
  },
  {
    id: 'EMP-005',
    name: 'Unsolicited dream job offer',
    pattern: /\b(offer(ing)?\s*(you\s*)?(a\s*)?)(job|position|opportunit)\b.{0,40}\b(based\s*on\s*your\s*(profile|resume|linkedin)|no\s*(interview|experience)\s*needed)\b/i,
    affinity: 0.78,
    generation: 1,
    falsePositiveRate: 0.10,
    category: ThreatCategory.EMPLOYMENT_SCAM,
    description: 'Unsolicited job offer — common phishing and money mule recruitment opener',
  },

  // ==================== BANK OTP BYPASS SCAMS (v2 expansion) ====================
  {
    id: 'OTP-001',
    name: 'Bank OTP/verification code request',
    pattern: /\b(verification\s*code|one[- ]time\s*(password|code|pin)|otp|2fa\s*code|authentication\s*code)\b.{0,40}\b(share|provide|give|text|send|tell)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.BANK_OTP,
    description: 'OTP/2FA bypass — requesting one-time code from victim\'s bank',
  },
  {
    id: 'OTP-002',
    name: 'Banker impersonation security team',
    pattern: /\b(fraud|security)\s*(department|team|division)\b.{0,60}\b(bank|chase|wellsfargo|citibank|bank\s*of\s*america|hsbc)\b.{0,30}\b(code|verify|confirm)\b/i,
    affinity: 0.91,
    generation: 1,
    falsePositiveRate: 0.03,
    category: ThreatCategory.BANK_OTP,
    description: 'Bank security department impersonation requesting verification code',
  },
  {
    id: 'OTP-003',
    name: 'Bank account locked verification',
    pattern: /\b(account)\b.{0,30}\b(lock|suspend|restrict|freeze)\b.{0,40}\b(verify|confirm|code|otp|text|sent)\b/i,
    affinity: 0.88,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.BANK_OTP,
    description: 'Bank account locked — requesting OTP to "unlock"',
  },
  {
    id: 'OTP-004',
    name: 'Authorized push payment manipulation',
    pattern: /\b(transfer|move|protect)\b.{0,30}\b(your\s*money|your\s*funds|savings)\b.{0,40}\b(safe\s*account|secure\s*account|temporary\s*account)\b/i,
    affinity: 0.93,
    generation: 1,
    falsePositiveRate: 0.02,
    category: ThreatCategory.BANK_OTP,
    description: 'Authorized Push Payment (APP) fraud — moving funds to "safe" account',
  },
  {
    id: 'OTP-005',
    name: 'SIM swap OTP request',
    pattern: /\b(sim|simcard|phone\s*number)\b.{0,40}\b(transfer|port|swap|switch)\b.{0,30}\b(code|pin|verify|account)\b/i,
    affinity: 0.89,
    generation: 1,
    falsePositiveRate: 0.04,
    category: ThreatCategory.BANK_OTP,
    description: 'SIM swap preparation — requesting code to transfer phone number',
  },
  {
    id: 'OTP-006',
    name: 'Vishing transaction reversal',
    pattern: /\b(reverse|cancel|undo|stop)\s*(the\s*)?(transaction|transfer|payment|charge)\b.{0,40}\b(code|verify|confirm|authorize)\b/i,
    affinity: 0.87,
    generation: 1,
    falsePositiveRate: 0.05,
    category: ThreatCategory.BANK_OTP,
    description: 'Vishing scam — fake transaction reversal requiring code authorization',
  },
];

// ---------------------------------------------------------------------------
// Antibody clustering — group related antibodies by category prefix
// ---------------------------------------------------------------------------
const ANTIBODY_CLUSTERS: AntibodyCluster[] = (() => {
  const clusterMap: Record<string, string[]> = {};
  const clusterCategories: Record<string, ThreatCategory> = {};

  for (const ab of ANTIBODY_REPERTOIRE) {
    const prefix = ab.id.split('-')[0];
    if (!clusterMap[prefix]) {
      clusterMap[prefix] = [];
      clusterCategories[prefix] = ab.category;
    }
    clusterMap[prefix].push(ab.id);
  }

  return Object.entries(clusterMap).map(([prefix, ids]) => ({
    clusterId: prefix,
    name: `${prefix} cluster`,
    antibodyIds: ids,
    clusterActivation: 0,
    dominantCategory: clusterCategories[prefix],
  }));
})();

// ---------------------------------------------------------------------------
// Fuzzy matching: generate looser variants of antibody patterns
// When a pattern almost-matches, try simplified versions
// ---------------------------------------------------------------------------
function fuzzyMatch(text: string, antibody: Antibody): { matched: boolean; matchedText: string; reducedAffinity: number } {
  // Try the original pattern first
  const re = new RegExp(antibody.pattern.source, antibody.pattern.flags);
  const directMatch = text.match(re);
  if (directMatch) {
    return { matched: true, matchedText: directMatch[0], reducedAffinity: antibody.affinity };
  }

  // Generate fuzzy variants by relaxing .{0,N} constraints to .{0,N*2}
  // and by making some components optional
  const source = antibody.pattern.source;

  // Variant 1: Double the character gap allowances
  const relaxedGaps = source.replace(/\.\{0,(\d+)\}/g, (_match, n) => `.{0,${Math.min(120, parseInt(n) * 2)}}`);
  if (relaxedGaps !== source) {
    const relaxedRe = new RegExp(relaxedGaps, antibody.pattern.flags);
    const relaxedMatch = text.match(relaxedRe);
    if (relaxedMatch) {
      return { matched: true, matchedText: relaxedMatch[0], reducedAffinity: antibody.affinity * 0.6 };
    }
  }

  // Variant 2: Try matching just the first and last capture groups
  // Split pattern by .{0,N} gaps and try matching the key parts independently
  const parts = source.split(/\.\{0,\d+\}/);
  if (parts.length >= 2) {
    const firstPart = parts[0];
    const lastPart = parts[parts.length - 1];
    try {
      const firstRe = new RegExp(firstPart, antibody.pattern.flags);
      const lastRe = new RegExp(lastPart, antibody.pattern.flags);
      const firstMatch = text.match(firstRe);
      const lastMatch = text.match(lastRe);
      if (firstMatch && lastMatch) {
        // Both key parts present in text, even if not properly connected
        return { matched: true, matchedText: `${firstMatch[0]}...${lastMatch[0]}`, reducedAffinity: antibody.affinity * 0.4 };
      }
    } catch {
      // Invalid regex from splitting — skip this variant
    }
  }

  return { matched: false, matchedText: '', reducedAffinity: 0 };
}

// ---------------------------------------------------------------------------
// Find matching antibodies in text (with fuzzy matching)
// ---------------------------------------------------------------------------
function findMatches(text: string): AntibodyMatch[] {
  const matches: AntibodyMatch[] = [];
  if (!text || text.length < 5) return matches;

  for (const antibody of ANTIBODY_REPERTOIRE) {
    const result = fuzzyMatch(text, antibody);
    if (result.matched) {
      matches.push({
        antibodyId: antibody.id,
        name: antibody.name,
        pattern: antibody.pattern.source,
        affinity: result.reducedAffinity,
        matchedText: result.matchedText,
        category: antibody.category,
      });
    }
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Compute cluster-level activation
// When multiple antibodies in a cluster fire, the cluster is strongly activated
// ---------------------------------------------------------------------------
function computeClusterActivation(matches: AntibodyMatch[]): AntibodyCluster[] {
  const matchedIds = new Set(matches.map(m => m.antibodyId));
  const activatedClusters: AntibodyCluster[] = [];

  for (const cluster of ANTIBODY_CLUSTERS) {
    const activeInCluster = cluster.antibodyIds.filter(id => matchedIds.has(id));
    if (activeInCluster.length > 0) {
      const activation = activeInCluster.length / cluster.antibodyIds.length;
      activatedClusters.push({
        ...cluster,
        clusterActivation: Math.round(activation * 10000) / 10000,
      });
    }
  }

  return activatedClusters;
}

// ---------------------------------------------------------------------------
// Zero-day detection: when multiple weak antibodies partially activate,
// treat as potential new/unknown threat pattern
// ---------------------------------------------------------------------------
function detectZeroDay(matches: AntibodyMatch[], text: string): { isZeroDay: boolean; confidence: number; details: string } {
  // Count weak matches (affinity < 0.7 — these are fuzzy/partial matches)
  const weakMatches = matches.filter(m => m.affinity < 0.7 && m.affinity > 0.2);
  const uniqueCategories = new Set(weakMatches.map(m => m.category));

  // Zero-day conditions:
  // 1. Multiple weak matches (3+) across different categories
  // 2. No strong match (no affinity > 0.85)
  const hasStrongMatch = matches.some(m => m.affinity > 0.85);

  if (weakMatches.length >= 3 && uniqueCategories.size >= 2 && !hasStrongMatch) {
    const confidence = Math.min(0.8, weakMatches.length * 0.15);
    return {
      isZeroDay: true,
      confidence,
      details: `Potential zero-day threat: ${weakMatches.length} weak matches across ${uniqueCategories.size} categories without any strong match — may be a new scam variant`,
    };
  }

  // Also trigger if many partial matches from same category (evolving variant)
  const categoryCounts: Record<string, number> = {};
  for (const m of weakMatches) {
    categoryCounts[m.category] = (categoryCounts[m.category] || 0) + 1;
  }
  for (const [category, count] of Object.entries(categoryCounts)) {
    if (count >= 3) {
      return {
        isZeroDay: true,
        confidence: Math.min(0.7, count * 0.12),
        details: `Potential evolved variant: ${count} weak matches in category ${category} — may be a mutated version of known scam`,
      };
    }
  }

  return { isZeroDay: false, confidence: 0, details: '' };
}

// ---------------------------------------------------------------------------
// Clonal selection: boost affinity of matched antibodies (in-memory only)
// In a production system this would persist to a database
// ---------------------------------------------------------------------------
function clonalSelection(antibodies: Antibody[], matchedIds: Set<string>): void {
  for (const antibody of antibodies) {
    if (matchedIds.has(antibody.id)) {
      // Boost: increase affinity slightly (capped at 0.99)
      antibody.affinity = Math.min(0.99, antibody.affinity + 0.001);
      antibody.generation += 1;
    }
  }
}

// ---------------------------------------------------------------------------
// Run the Immune Repertoire layer
// ---------------------------------------------------------------------------
export function runImmuneRepertoire(
  input: { text?: string; emailBody?: string; smsBody?: string; screenshotOcrText?: string },
  dangerSignalActive: boolean,
): ImmuneRepertoireResult {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  const details: string[] = [];

  // Danger signal gating: only fully activate when another layer flagged something
  if (!dangerSignalActive) {
    // Still run matching but at reduced sensitivity
    details.push('Danger signal NOT active — running in low-sensitivity mode');
  }

  const matchedAntibodies = findMatches(allText);

  if (matchedAntibodies.length === 0) {
    // Even with no matches, check for zero-day using fuzzy partial matches
    details.push('No antibody matches found');

    // Still check for zero-day patterns
    const zeroDayCheck = detectZeroDay(matchedAntibodies, allText);
    if (zeroDayCheck.isZeroDay) {
      details.push(`ZERO-DAY ALERT: ${zeroDayCheck.details}`);
      return {
        score: Math.round(zeroDayCheck.confidence * 30 * 100) / 100,
        matchedAntibodies: [],
        activationGated: !dangerSignalActive,
        details,
      };
    }

    return {
      score: 0,
      matchedAntibodies: [],
      activationGated: !dangerSignalActive,
      details,
    };
  }

  // Perform clonal selection on a per-request clone (don't mutate global repertoire)
  const matchedIds = new Set(matchedAntibodies.map(m => m.antibodyId));
  const repertoireClone = ANTIBODY_REPERTOIRE.map(ab => ({ ...ab }));
  clonalSelection(repertoireClone, matchedIds);

  // Compute cluster-level activation
  const activatedClusters = computeClusterActivation(matchedAntibodies);
  for (const cluster of activatedClusters) {
    if (cluster.clusterActivation > 0.3) {
      details.push(`Cluster "${cluster.clusterId}" activation: ${(cluster.clusterActivation * 100).toFixed(1)}% (${cluster.dominantCategory})`);
    }
  }

  // Check for zero-day patterns
  const zeroDayResult = detectZeroDay(matchedAntibodies, allText);
  if (zeroDayResult.isZeroDay) {
    details.push(`ZERO-DAY ALERT: ${zeroDayResult.details}`);
  }

  // Compute score from matched antibodies
  // Use inclusion-exclusion for combining multiple detections:
  // P(scam) = 1 - product(1 - affinity_i)
  let combinedProbability = 1;
  for (const match of matchedAntibodies) {
    combinedProbability *= (1 - match.affinity);
    details.push(`Matched [${match.antibodyId}] "${match.name}" — affinity=${match.affinity.toFixed(3)}, matched: "${match.matchedText.substring(0, 80)}"`);
  }
  let rawScore = (1 - combinedProbability) * 100;

  // Cluster activation bonus: when >50% of a cluster fires, boost score
  for (const cluster of activatedClusters) {
    if (cluster.clusterActivation > 0.5) {
      rawScore = Math.min(100, rawScore * (1 + cluster.clusterActivation * 0.15));
      details.push(`Cluster "${cluster.clusterId}" bonus applied: activation=${(cluster.clusterActivation * 100).toFixed(1)}%`);
    }
  }

  // Zero-day bonus
  if (zeroDayResult.isZeroDay) {
    rawScore = Math.min(100, rawScore + zeroDayResult.confidence * 15);
  }

  // Apply danger signal gating
  const gatingFactor = dangerSignalActive ? 1.0 : 0.5;
  const finalScore = Math.min(100, rawScore * gatingFactor);

  details.push(`Raw combined score: ${rawScore.toFixed(2)}`);
  details.push(`Gating factor: ${gatingFactor} (danger signal ${dangerSignalActive ? 'ACTIVE' : 'inactive'})`);
  details.push(`Final immune score: ${finalScore.toFixed(2)}/100`);
  details.push(`Total antibodies matched: ${matchedAntibodies.length}/${ANTIBODY_REPERTOIRE.length}`);

  // Count by category
  const categoryCounts: Record<string, number> = {};
  for (const match of matchedAntibodies) {
    categoryCounts[match.category] = (categoryCounts[match.category] || 0) + 1;
  }
  for (const [cat, count] of Object.entries(categoryCounts)) {
    details.push(`  Category ${cat}: ${count} match(es)`);
  }

  return {
    score: Math.round(finalScore * 100) / 100,
    matchedAntibodies,
    activationGated: !dangerSignalActive,
    details,
  };
}

// Export the repertoire for testing/inspection
export { ANTIBODY_REPERTOIRE };
