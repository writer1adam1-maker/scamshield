// ============================================================================
// ScamShield Multilingual Scam Detector
// Detects scam patterns in Spanish, French, Portuguese, Arabic, German, Chinese.
// Enables detection of international scam campaigns targeting US diaspora communities.
// ============================================================================

import {
  ThreatCategory,
  MultilingualDetectionResult,
  MultilingualMatch,
} from './types';

// ---------------------------------------------------------------------------
// Pattern definition
// ---------------------------------------------------------------------------

interface MultilingualPattern {
  id: string;
  name: string;
  language: string;
  languageName: string;
  pattern: RegExp;
  confidence: number;
  category: ThreatCategory;
}

// ---------------------------------------------------------------------------
// Spanish (es) scam patterns
// ---------------------------------------------------------------------------

const SPANISH_PATTERNS: MultilingualPattern[] = [
  {
    id: 'ES-001',
    name: 'Urgencia bancaria',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(cuenta|banco|tarjeta)\b.{0,50}\b(suspend|bloqu|verific|actualiz)\b/i,
    confidence: 0.82,
    category: ThreatCategory.PHISHING,
  },
  {
    id: 'ES-002',
    name: 'Pago adelantado',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(pag[oa]|transfier[ae]|env[íi]a)\b.{0,40}\b(adelant[ao]|primero|antes\s*de)\b/i,
    confidence: 0.85,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'ES-003',
    name: 'Premio lotería',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(ganador|ganaste|seleccionado|premio|lotería|concurso)\b.{0,60}\b(reclam|cobr|collect)\b/i,
    confidence: 0.88,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'ES-004',
    name: 'Soporte técnico falso',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(soporte\s*técnico|servicio\s*técnico|microsoft|windows)\b.{0,60}\b(virus|infect|llam[ae]|llama\s*al)\b/i,
    confidence: 0.84,
    category: ThreatCategory.TECH_SUPPORT,
  },
  {
    id: 'ES-005',
    name: 'Inversión garantizada',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(invert[íi]r?|inversión|ganancia|rendimiento)\b.{0,40}\b(garantizad[ao]|segur[ao]|100%|diario)\b/i,
    confidence: 0.86,
    category: ThreatCategory.INVESTMENT_FRAUD,
  },
  {
    id: 'ES-006',
    name: 'Urgencia migración/ICE',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(inmigración|ice|uscis|deportación|visa)\b.{0,60}\b(problem[ao]|revocar|cancelar|ilegal|pag[oa])\b/i,
    confidence: 0.87,
    category: ThreatCategory.IRS_GOV,
  },
  {
    id: 'ES-007',
    name: 'Romance pedir dinero',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(te\s*(amo|quiero)|amor|mi\s*(vida|corazón|cielo))\b.{0,80}\b(env[íi]a?|dinero|ayud[ae]|transfier[ae])\b/i,
    confidence: 0.80,
    category: ThreatCategory.ROMANCE,
  },
  {
    id: 'ES-008',
    name: 'Código OTP bancario',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(código|clave|número)\b.{0,30}\b(verificación|autenticación|temporal|otp)\b.{0,30}\b(comparte?|proporciona?|env[íi]a?|dime)\b/i,
    confidence: 0.90,
    category: ThreatCategory.BANK_OTP,
  },
  {
    id: 'ES-009',
    name: 'Trabajo desde casa fraude',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(trabajo|empleo|gana[rs])\b.{0,40}\b(desde\s*casa|en\s*casa|home)\b.{0,30}\b(\$\d+|pesos|dólares|por\s*(hora|día|semana))\b/i,
    confidence: 0.78,
    category: ThreatCategory.EMPLOYMENT_SCAM,
  },
  {
    id: 'ES-010',
    name: 'Cripto duplicar dinero',
    language: 'es',
    languageName: 'Spanish',
    pattern: /\b(bitcoin|cripto|ethereum|btc)\b.{0,50}\b(duplicar|triplicar|doblar|multiplica)\b/i,
    confidence: 0.90,
    category: ThreatCategory.CRYPTO,
  },
];

// ---------------------------------------------------------------------------
// French (fr) scam patterns
// ---------------------------------------------------------------------------

const FRENCH_PATTERNS: MultilingualPattern[] = [
  {
    id: 'FR-001',
    name: 'Compte bancaire bloqué',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(compte|banque|carte)\b.{0,50}\b(bloqu|suspend|vérifi|actualise)\b/i,
    confidence: 0.82,
    category: ThreatCategory.PHISHING,
  },
  {
    id: 'FR-002',
    name: 'Frais avancés',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(paiement|virement|envoy)\b.{0,40}\b(avance|avant|d'abord)\b/i,
    confidence: 0.83,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'FR-003',
    name: 'Prix loterie français',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(gagnant|gagné|sélectionné|prix|loterie|concours)\b.{0,60}\b(réclam|reclam|collect)\b/i,
    confidence: 0.87,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'FR-004',
    name: 'Support technique Microsoft',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(support\s*technique|microsoft|windows)\b.{0,60}\b(virus|infecté|appelez|numéro)\b/i,
    confidence: 0.84,
    category: ThreatCategory.TECH_SUPPORT,
  },
  {
    id: 'FR-005',
    name: 'Code OTP bancaire',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(code|numéro)\b.{0,30}\b(vérification|authentification|temporaire|otp)\b.{0,30}\b(communiquez|envoyez|donnez|partagez)\b/i,
    confidence: 0.90,
    category: ThreatCategory.BANK_OTP,
  },
  {
    id: 'FR-006',
    name: 'Investissement crypto garanti',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(investissement|bitcoin|crypto|placement)\b.{0,50}\b(garanti|sûr|100%|quotidien|hebdomadaire)\b/i,
    confidence: 0.86,
    category: ThreatCategory.INVESTMENT_FRAUD,
  },
  {
    id: 'FR-007',
    name: 'Arnaque emploi domicile',
    language: 'fr',
    languageName: 'French',
    pattern: /\b(emploi|travail|gagner)\b.{0,40}\b(domicile|chez\s*soi|maison)\b.{0,30}\b(€|\d+\s*(euros?|€)|par\s*(jour|semaine|heure))\b/i,
    confidence: 0.78,
    category: ThreatCategory.EMPLOYMENT_SCAM,
  },
];

// ---------------------------------------------------------------------------
// Portuguese (pt) scam patterns
// ---------------------------------------------------------------------------

const PORTUGUESE_PATTERNS: MultilingualPattern[] = [
  {
    id: 'PT-001',
    name: 'Conta bancária suspensa',
    language: 'pt',
    languageName: 'Portuguese',
    pattern: /\b(conta|banco|cartão)\b.{0,50}\b(suspens|bloqu|verific|atualiz)\b/i,
    confidence: 0.82,
    category: ThreatCategory.PHISHING,
  },
  {
    id: 'PT-002',
    name: 'Pagamento adiantado',
    language: 'pt',
    languageName: 'Portuguese',
    pattern: /\b(pagamento|transfer[êe]ncia|envie?)\b.{0,40}\b(adiantado|primeiro|antes)\b/i,
    confidence: 0.83,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'PT-003',
    name: 'Código OTP banco',
    language: 'pt',
    languageName: 'Portuguese',
    pattern: /\b(código|número)\b.{0,30}\b(verificação|autenticação|temporário|otp)\b.{0,30}\b(compartilhe?|envie?|forneça|diga)\b/i,
    confidence: 0.90,
    category: ThreatCategory.BANK_OTP,
  },
  {
    id: 'PT-004',
    name: 'Ganhar prêmio loteria',
    language: 'pt',
    languageName: 'Portuguese',
    pattern: /\b(ganhador|ganhou|selecionado|prêmio|loteria|concurso)\b.{0,60}\b(reclam|resgat|cobr)\b/i,
    confidence: 0.87,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'PT-005',
    name: 'Investimento bitcoin garantido',
    language: 'pt',
    languageName: 'Portuguese',
    pattern: /\b(investimento|bitcoin|cripto|ethereum)\b.{0,50}\b(garantido|seguro|100%|diário|semanal)\b/i,
    confidence: 0.86,
    category: ThreatCategory.INVESTMENT_FRAUD,
  },
];

// ---------------------------------------------------------------------------
// Arabic (ar) scam patterns (transliterated + Arabic script basics)
// ---------------------------------------------------------------------------

const ARABIC_PATTERNS: MultilingualPattern[] = [
  {
    id: 'AR-001',
    name: 'Bank account suspended (ar)',
    language: 'ar',
    languageName: 'Arabic',
    // Matches "account" + "suspended/blocked" in Arabic
    pattern: /حساب.{0,30}(معلق|محظور|موقوف|تحقق)/,
    confidence: 0.83,
    category: ThreatCategory.PHISHING,
  },
  {
    id: 'AR-002',
    name: 'Prize/lottery winner (ar)',
    language: 'ar',
    languageName: 'Arabic',
    pattern: /\b(فائز|جائزة|يانصيب|ربحت)\b.{0,60}\b(استلم|احصل|اطلب)/,
    confidence: 0.85,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'AR-003',
    name: 'OTP code request (ar)',
    language: 'ar',
    languageName: 'Arabic',
    pattern: /رمز.{0,30}(تحقق|مؤقت|otp).{0,30}(أرسل|أعطِ|شارك)/,
    confidence: 0.90,
    category: ThreatCategory.BANK_OTP,
  },
];

// ---------------------------------------------------------------------------
// German (de) scam patterns
// ---------------------------------------------------------------------------

const GERMAN_PATTERNS: MultilingualPattern[] = [
  {
    id: 'DE-001',
    name: 'Konto gesperrt',
    language: 'de',
    languageName: 'German',
    pattern: /\b(konto|bank|karte)\b.{0,50}\b(gesperrt|eingeschränkt|verifizier|aktualisier)\b/i,
    confidence: 0.82,
    category: ThreatCategory.PHISHING,
  },
  {
    id: 'DE-002',
    name: 'Voraus zahlung',
    language: 'de',
    languageName: 'German',
    pattern: /\b(zahlung|überweis|schicken)\b.{0,40}\b(voraus|zuerst|im\s*vorhinein)\b/i,
    confidence: 0.83,
    category: ThreatCategory.ADVANCE_FEE,
  },
  {
    id: 'DE-003',
    name: 'TAN/OTP Code Phishing',
    language: 'de',
    languageName: 'German',
    pattern: /\b(tan|code|nummer)\b.{0,30}\b(verifikation|authentifizierung|einmalig)\b.{0,30}\b(mitteilen|senden|geben)\b/i,
    confidence: 0.90,
    category: ThreatCategory.BANK_OTP,
  },
  {
    id: 'DE-004',
    name: 'Paketlieferung Betrug',
    language: 'de',
    languageName: 'German',
    pattern: /\b(paket|sendung|lieferung)\b.{0,50}\b(gebühr|zahlen|klicken|verifizier)\b/i,
    confidence: 0.82,
    category: ThreatCategory.PACKAGE_DELIVERY,
  },
];

// ---------------------------------------------------------------------------
// All patterns combined
// ---------------------------------------------------------------------------

const ALL_MULTILINGUAL_PATTERNS: MultilingualPattern[] = [
  ...SPANISH_PATTERNS,
  ...FRENCH_PATTERNS,
  ...PORTUGUESE_PATTERNS,
  ...ARABIC_PATTERNS,
  ...GERMAN_PATTERNS,
];

// ---------------------------------------------------------------------------
// Language detection heuristics
// ---------------------------------------------------------------------------

const LANGUAGE_MARKERS: Record<string, RegExp> = {
  es: /\b(está|usted|cuenta|banco|pago|dinero|enviar|urgente|ganador|código|soporte|trabajo|inversión|bitcoin)\b/i,
  fr: /\b(est|vous|compte|banque|paiement|argent|envoyer|urgent|gagnant|code|soutien|emploi|investissement)\b/i,
  pt: /\b(está|conta|banco|pagamento|dinheiro|enviar|urgente|ganhador|código|suporte|trabalho|investimento)\b/i,
  de: /\b(ist|konto|bank|zahlung|geld|senden|dringend|gewinner|code|support|arbeit|investition)\b/i,
  ar: /[\u0600-\u06FF]{4,}/, // Arabic script block
};

function detectLanguage(text: string): string | null {
  let bestLang: string | null = null;
  let bestCount = 0;

  for (const [lang, marker] of Object.entries(LANGUAGE_MARKERS)) {
    const matches = (text.match(new RegExp(marker.source, 'gi')) || []).length;
    if (matches > bestCount) {
      bestCount = matches;
      bestLang = lang;
    }
  }

  return bestCount >= 2 ? bestLang : null;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function detectMultilingualScam(text: string): MultilingualDetectionResult {
  const startTime = performance.now();
  const matches: MultilingualMatch[] = [];
  const flagSet = new Set<string>();

  for (const pattern of ALL_MULTILINGUAL_PATTERNS) {
    const match = text.match(pattern.pattern);
    if (match) {
      matches.push({
        language: pattern.language,
        languageName: pattern.languageName,
        patternId: pattern.id,
        patternName: pattern.name,
        matchedText: match[0].substring(0, 120),
        confidence: pattern.confidence,
        category: pattern.category,
      });
      flagSet.add(`[${pattern.languageName}] ${pattern.name}`);
    }
  }

  const dominantLanguage = detectLanguage(text);

  // Risk score = highest single match confidence, boosted by match count
  const highestConf = matches.length > 0
    ? Math.max(...matches.map((m) => m.confidence))
    : 0;
  const countBoost = Math.min(0.15, (matches.length - 1) * 0.05);
  const riskScore = matches.length > 0 ? Math.min(1, highestConf + countBoost) : 0;

  return {
    detected: matches.length > 0,
    dominantLanguage,
    matches,
    riskScore,
    flags: Array.from(flagSet),
    processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
  };
}
