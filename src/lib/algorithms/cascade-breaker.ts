// ============================================================================
// VERIDICT Layer 3: Information Cascade Breaker
// Identifies manipulation triggers and measures how fragile trust is
// when those triggers are removed from the message.
// ============================================================================

import {
  AnalysisInput,
  CascadeBreakerResult,
  CascadeBreakdown,
  EmotionalExploitationResult,
} from './types';

// ---------------------------------------------------------------------------
// Trigger categories with their patterns
// ---------------------------------------------------------------------------
interface TriggerCategory {
  name: string;
  patterns: Array<{ regex: RegExp; label: string; weight: number }>;
}

const TRIGGER_CATEGORIES: TriggerCategory[] = [
  {
    name: 'urgency',
    patterns: [
      { regex: /\b(act now|right now|immediately|urgent(ly)?|asap)\b/gi, label: 'time pressure', weight: 0.8 },
      { regex: /\b(expires?\s+(today|soon|in\s+\d+)|limited\s+time|only\s+\d+\s+(left|remaining|available))\b/gi, label: 'expiration pressure', weight: 0.85 },
      { regex: /\b(last\s+chance|final\s+(notice|warning|attempt|reminder))\b/gi, label: 'last chance', weight: 0.85 },
      { regex: /\b(within\s+(24|48|72)\s*hours?|before\s+(midnight|end\s+of\s+(day|business)))\b/gi, label: 'deadline', weight: 0.75 },
      { regex: /\b(don'?t\s+(wait|delay|miss\s+(out|this))|hurry|rush)\b/gi, label: 'haste demand', weight: 0.7 },
      { regex: /\b(time\s+is\s+running\s+out|clock\s+is\s+ticking)\b/gi, label: 'countdown metaphor', weight: 0.75 },
      { regex: /\b(respond\s+(before|by|within)|reply\s+(now|today|urgently|immediately))\b/gi, label: 'response deadline', weight: 0.75 },
      { regex: /\b(offer\s+(ends|expires|valid)\s+(today|tonight|soon|in\s+\d+))\b/gi, label: 'offer expiry', weight: 0.7 },
      { regex: /\b(do\s+(not|n[o']t)\s+(ignore|disregard|delete)\s+this)\b/gi, label: 'anti-ignore demand', weight: 0.7 },
      { regex: /\b(every\s+(minute|second|hour)\s+(counts|matters|is\s+critical))\b/gi, label: 'time urgency intensifier', weight: 0.75 },
      { regex: /\b(your\s+window\s+(of\s+opportunity|to\s+(act|respond))\s+(is\s+)?(closing|shrinking|limited))\b/gi, label: 'window closing', weight: 0.8 },
      { regex: /\b(we\s+(cannot|can'?t)\s+(hold|reserve|guarantee)\s+this\s+(much\s+)?longer)\b/gi, label: 'hold expiry', weight: 0.75 },
      // Cialdini + FTC real phrases
      { regex: /\b(immediate\s+action\s+required|action\s+required)\b/gi, label: 'action required', weight: 0.85 },
      { regex: /\b(expires?\s+today|expiring\s+today)\b/gi, label: 'expires today', weight: 0.85 },
      { regex: /\b(final\s+warning)\b/gi, label: 'final warning', weight: 0.9 },
      { regex: /\b(within\s+24\s+hours?|in\s+24\s+hours?)\b/gi, label: '24-hour deadline', weight: 0.8 },
      { regex: /\b(your\s+account\s+will\s+(be\s+)?(suspended?|locked|deleted|terminated|closed))\b/gi, label: 'account suspension threat', weight: 0.9 },
      { regex: /\b(time[- ]sensitive)\b/gi, label: 'time-sensitive claim', weight: 0.75 },
      { regex: /\b(don'?t\s+delay|respond\s+immediately)\b/gi, label: 'delay prohibition', weight: 0.75 },
      { regex: /\b(deadline\s+approaching|hours?\s+remaining)\b/gi, label: 'deadline proximity', weight: 0.8 },
      { regex: /\b(before\s+it'?s?\s+too\s+late)\b/gi, label: 'too late warning', weight: 0.8 },
    ],
  },
  {
    name: 'authority',
    patterns: [
      { regex: /\b(official\s+(notice|communication|letter|notification))\b/gi, label: 'official claim', weight: 0.7 },
      { regex: /\b(federal|government|irs|fbi|doj|ssa|ftc|sec|dhs)\b/gi, label: 'government entity', weight: 0.8 },
      { regex: /\b(department\s+of|bureau\s+of|office\s+of|administration)\b/gi, label: 'department name', weight: 0.6 },
      { regex: /\b(pursuant\s+to|in\s+accordance\s+with|under\s+(section|code|title|law))\b/gi, label: 'legal citation', weight: 0.65 },
      { regex: /\b(authorized|certified|licensed|registered|approved)\s+(by|agent|representative)/gi, label: 'authorization claim', weight: 0.65 },
      { regex: /\b(this\s+is\s+(a|an)\s+(mandatory|required|compulsory))\b/gi, label: 'mandatory claim', weight: 0.7 },
      { regex: /\b(by\s+order\s+of|on\s+behalf\s+of|representing\s+the)\b/gi, label: 'delegation claim', weight: 0.65 },
      { regex: /\b(compliance\s+(officer|team|department)|regulatory\s+(body|authority|agency))\b/gi, label: 'compliance authority', weight: 0.7 },
      { regex: /\b(executive\s+(order|directive)|presidential|congressional)\b/gi, label: 'executive authority', weight: 0.8 },
      { regex: /\b(non[- ]?compliance\s+(will|may)\s+(result|lead))\b/gi, label: 'compliance threat', weight: 0.75 },
      { regex: /\b(case\s+(number|#|file|reference)\s*:?\s*\w+)\b/gi, label: 'case number', weight: 0.6 },
      { regex: /\b(badge\s*(number|#)|officer\s+(id|number)|agent\s+(id|name))\b/gi, label: 'officer identification', weight: 0.7 },
      // Cialdini + FTC real authority phrases
      { regex: /\b(IT\s+department|security\s+team|compliance\s+team)\b/gi, label: 'internal authority claim', weight: 0.7 },
      { regex: /\b(police|court\s+order|subpoena)\b/gi, label: 'law enforcement claim', weight: 0.85 },
      { regex: /\b(official\s+notice|mandatory|required\s+by\s+law)\b/gi, label: 'mandatory official notice', weight: 0.8 },
      { regex: /\b(legal\s+department|department\s+of\s+justice|social\s+security\s+administration)\b/gi, label: 'legal/government department', weight: 0.85 },
      { regex: /\b(DEA|homeland\s+security|drug\s+enforcement)\b/gi, label: 'federal law enforcement', weight: 0.9 },
    ],
  },
  {
    name: 'scarcity',
    patterns: [
      { regex: /\b(only\s+\d+\s+(spots?|seats?|positions?|openings?|slots?)\s+(left|remaining|available))\b/gi, label: 'limited availability', weight: 0.8 },
      { regex: /\b(exclusive|one[- ]time|once\s+in\s+a\s+lifetime|rare\s+opportunity)\b/gi, label: 'exclusivity', weight: 0.75 },
      { regex: /\b(limited\s+(edition|supply|quantity|offer)|while\s+supplies?\s+last)\b/gi, label: 'limited supply', weight: 0.75 },
      { regex: /\b(first\s+(come|served|\d+\s+(people|users|customers)))\b/gi, label: 'first come first served', weight: 0.7 },
      { regex: /\b(selling\s+fast|almost\s+(gone|sold\s+out)|running\s+out)\b/gi, label: 'selling fast', weight: 0.7 },
      { regex: /\b(invite[- ]only|by\s+invitation\s+only|hand[- ]picked|personally\s+selected)\b/gi, label: 'invitation exclusivity', weight: 0.75 },
      { regex: /\b(this\s+(won'?t|will\s+not)\s+(last|be\s+available)\s+(long|forever))\b/gi, label: 'availability warning', weight: 0.7 },
      { regex: /\b(demand\s+(is|has\s+been)\s+(high|overwhelming|incredible))\b/gi, label: 'high demand claim', weight: 0.65 },
      { regex: /\b(we\s+(rarely|seldom|never)\s+(offer|do)\s+this)\b/gi, label: 'rare offer claim', weight: 0.7 },
      { regex: /\b(once\s+(this|it)\s+is\s+gone|never\s+again|unrepeatable)\b/gi, label: 'finality claim', weight: 0.75 },
      // FTC real scarcity phrases
      { regex: /\b(limited\s+spots?|exclusive\s+offer)\b/gi, label: 'limited spots claim', weight: 0.75 },
      { regex: /\b(only\s+\d+\s+remaining|only\s+\d+\s+left)\b/gi, label: 'low stock count', weight: 0.8 },
      { regex: /\b(special\s+access|invitation\s+only|selected\s+users?)\b/gi, label: 'exclusive access claim', weight: 0.75 },
      { regex: /\b(claim\s+your\s+spot|don'?t\s+miss\s+out)\b/gi, label: 'spot claim demand', weight: 0.75 },
      { regex: /\b(almost\s+gone|first\s+come\s+first\s+served|reserved\s+for\s+you)\b/gi, label: 'reserved scarcity', weight: 0.7 },
    ],
  },
  {
    name: 'social_proof',
    patterns: [
      { regex: /\b(\d+[,.]?\d*\s*(people|users|customers|members)\s+(have\s+already|already|joined|signed\s+up))\b/gi, label: 'user count', weight: 0.6 },
      { regex: /\b(everyone\s+(is|has)|thousands\s+of|millions\s+of)\b/gi, label: 'popularity claim', weight: 0.55 },
      { regex: /\b(trusted\s+by|recommended\s+by|as\s+seen\s+on|featured\s+(in|on))\b/gi, label: 'trust signal', weight: 0.5 },
      { regex: /\b(testimonial|review|success\s+stor(y|ies)|case\s+stud(y|ies))\b/gi, label: 'testimonial reference', weight: 0.4 },
      { regex: /\b(your\s+(friend|neighbor|colleague|coworker)\s+(also|already|just))\b/gi, label: 'peer reference', weight: 0.65 },
      { regex: /\b(people\s+(like\s+you|in\s+your\s+(area|city|state))\s+(are|have))\b/gi, label: 'local peer pressure', weight: 0.65 },
      { regex: /\b(rated\s+#?\d|top[- ]rated|best[- ]selling|award[- ]winning)\b/gi, label: 'rating claim', weight: 0.5 },
      { regex: /\b(verified\s+(by|reviews?)|customer\s+(satisfaction|rating)\s+\d)/gi, label: 'verification claim', weight: 0.55 },
      { regex: /\b(join(ing)?\s+(the\s+)?\d+[,.]?\d*\+?\s*(others?|people|members?))\b/gi, label: 'join others', weight: 0.6 },
      { regex: /\b(don'?t\s+(be\s+)?the\s+(last|only)\s+one|everyone\s+(else\s+)?(is|has)\s+already)\b/gi, label: 'FOMO social', weight: 0.7 },
      // Real social proof manipulation phrases
      { regex: /\b(join\s+millions|endorsed\s+by)\b/gi, label: 'mass endorsement claim', weight: 0.6 },
      { regex: /\b(other\s+employees?\s+have\s+already|your\s+colleagues?\s+(have|already))\b/gi, label: 'workplace peer pressure', weight: 0.75 },
      { regex: /\b(thousands\s+have\s+already\s+claimed)\b/gi, label: 'mass claim pressure', weight: 0.7 },
      { regex: /\b(rated\s+5\s+stars?|5[- ]star\s+rated)\b/gi, label: '5-star rating claim', weight: 0.5 },
    ],
  },
  {
    name: 'fear',
    patterns: [
      { regex: /\b(your\s+(account|computer|device|identity)\s+(has\s+been|is|was)\s+(hack|compromis|infect|breach|stolen))/gi, label: 'compromise claim', weight: 0.85 },
      { regex: /\b(arrest\s+warrant|legal\s+action|prosecution|lawsuit|criminal\s+charges?)\b/gi, label: 'legal threat', weight: 0.9 },
      { regex: /\b(suspended?|deactivat|terminat|clos|lock|restrict|block)\s*(ed|ion|ing)?\s*(your\s+)?(account|access|service)/gi, label: 'account threat', weight: 0.85 },
      { regex: /\b(penalty|fine|fee|charge)\s*(of\s+)?\$[\d,.]+/gi, label: 'financial penalty', weight: 0.8 },
      { regex: /\b(if\s+you\s+(fail|do\s+not|don'?t)\s+(to\s+)?(respond|comply|act|pay|verify))/gi, label: 'consequence threat', weight: 0.8 },
      { regex: /\b(we\s+(will|shall)\s+(be\s+forced\s+to|have\s+no\s+choice|proceed\s+with))\b/gi, label: 'escalation threat', weight: 0.75 },
      { regex: /\b(virus|malware|trojan|spyware|ransomware)\b/gi, label: 'malware claim', weight: 0.7 },
      { regex: /\b(your\s+(family|children|loved\s+ones)\s+(will|may|could)\s+(be\s+)?(affected|harmed|at\s+risk))\b/gi, label: 'family threat', weight: 0.9 },
      { regex: /\b(permanent(ly)?\s+(delet|remov|los|destroy|eras))\b/gi, label: 'permanent loss threat', weight: 0.8 },
      { regex: /\b(we\s+(will|shall)\s+(publish|release|expose|share)\s+(your|the))\b/gi, label: 'exposure threat', weight: 0.9 },
      { regex: /\b(your\s+(data|information|files?|photos?)\s+(will\s+be|are\s+being)\s+(sold|shared|leaked))\b/gi, label: 'data threat', weight: 0.85 },
      { regex: /\b(irreversible|cannot\s+be\s+(undone|reversed)|point\s+of\s+no\s+return)\b/gi, label: 'irreversibility claim', weight: 0.8 },
      // FTC real fear phrases
      { regex: /\b(unauthorized\s+access\s+detected|suspicious\s+activity\s+(detected|found|on\s+your\s+account))\b/gi, label: 'unauthorized access alert', weight: 0.85 },
      { regex: /\b(security\s+breach|account\s+(compromised|hacked|breached))\b/gi, label: 'security breach claim', weight: 0.85 },
      { regex: /\b(virus\s+detected|malware\s+(found|detected)|identity\s+theft)\b/gi, label: 'security threat detected', weight: 0.85 },
      { regex: /\b(account\s+terminated|permanently\s+banned|data\s+loss)\b/gi, label: 'account termination threat', weight: 0.9 },
      { regex: /\b(payment\s+declined|overdue\s+balance)\b/gi, label: 'payment failure threat', weight: 0.75 },
      { regex: /\b(warrant\s+for\s+your\s+arrest|your\s+SSN\s+has\s+been\s+compromised)\b/gi, label: 'arrest or identity threat', weight: 0.95 },
    ],
  },
  {
    name: 'reciprocity',
    patterns: [
      { regex: /\b(free\s+(gift|trial|sample|bonus|reward|access|membership))\b/gi, label: 'free offer', weight: 0.6 },
      { regex: /\b(congratulations|you('ve|\s+have)\s+(been\s+)?(selected|chosen|picked|won|awarded))\b/gi, label: 'prize award', weight: 0.85 },
      { regex: /\b(claim\s+(your|this)\s+(prize|reward|gift|bonus|winnings?))\b/gi, label: 'prize claim', weight: 0.85 },
      { regex: /\b(no\s+(cost|charge|obligation|strings?\s+attached))\b/gi, label: 'no cost claim', weight: 0.6 },
      { regex: /\b(as\s+a\s+(token|gesture|thank\s+you|appreciation)|complimentary)\b/gi, label: 'gift framing', weight: 0.55 },
      { regex: /\b(you\s+(deserve|earned|qualified\s+for))\b/gi, label: 'entitlement framing', weight: 0.5 },
      { regex: /\b(special\s+(discount|offer|deal|price)\s+(just\s+)?for\s+you)\b/gi, label: 'personalized offer', weight: 0.65 },
      { regex: /\b(we('re|\s+are)\s+(giving\s+away|offering\s+free|waiving\s+(the\s+)?fee))\b/gi, label: 'generosity framing', weight: 0.6 },
      { regex: /\b(loyalty\s+(bonus|reward|gift)|thank\s+you\s+(gift|bonus|reward))\b/gi, label: 'loyalty reward', weight: 0.6 },
      { regex: /\b(only\s+pay\s+(shipping|handling|tax)|just\s+cover\s+(the\s+)?(shipping|postage))\b/gi, label: 'hidden cost bait', weight: 0.7 },
      // Cialdini reciprocity + real lure phrases
      { regex: /\b(free\s+gift|complimentary)\b/gi, label: 'free gift lure', weight: 0.65 },
      { regex: /\b(you'?ve?\s+been\s+selected|you\s+won|you\s+have\s+won)\b/gi, label: 'winner selection claim', weight: 0.85 },
      { regex: /\b(claim\s+your\s+prize|cash\s*back|refund\s+available)\b/gi, label: 'prize/refund claim', weight: 0.8 },
      { regex: /\b(special\s+offer\s+just\s+for\s+you|gift\s+card|voucher)\b/gi, label: 'personalized gift offer', weight: 0.75 },
    ],
  },
  {
    name: 'curiosity',
    patterns: [
      // Cialdini curiosity gap — real phishing lure phrases
      { regex: /\b(you\s+won'?t\s+believe|shocking|breaking\s+news)\b/gi, label: 'curiosity gap headline', weight: 0.65 },
      { regex: /\b(see\s+who\s+viewed|someone\s+shared\s+a\s+document\s+with\s+you)\b/gi, label: 'social platform lure', weight: 0.8 },
      { regex: /\b(you\s+have\s+a\s+new\s+message|new\s+message\s+waiting|unread\s+message)\b/gi, label: 'message lure', weight: 0.7 },
      { regex: /\b(voice\s+message\s+waiting|voicemail\s+from)\b/gi, label: 'voicemail lure', weight: 0.75 },
      { regex: /\b(missed\s+delivery\s+notification|delivery\s+attempt\s+failed)\b/gi, label: 'delivery lure', weight: 0.75 },
      { regex: /\b(is\s+this\s+you\s+in\s+(this\s+)?video|is\s+this\s+your\s+photo)\b/gi, label: 'video/photo bait', weight: 0.85 },
      { regex: /\b(someone\s+is\s+looking\s+for\s+you|someone\s+sent\s+you\s+a\s+(gift|file|photo))\b/gi, label: 'mystery sender lure', weight: 0.8 },
      { regex: /\b(click\s+to\s+(see|find\s+out|reveal|unlock))\b/gi, label: 'click bait reveal', weight: 0.7 },
      { regex: /\b(what\s+happens?\s+next\s+will\s+(shock|surprise|amaze))\b/gi, label: 'listicle shock bait', weight: 0.65 },
    ],
  },
  {
    name: 'isolation',
    patterns: [
      { regex: /\b(don'?t\s+tell\s+(anyone|anybody|your\s+(family|friends?|spouse|partner|bank)))\b/gi, label: 'secrecy demand', weight: 0.9 },
      { regex: /\b(this\s+is\s+(strictly\s+)?confidential|top\s+secret|classified\s+(information|document))\b/gi, label: 'confidentiality claim', weight: 0.8 },
      { regex: /\b(time[- ]sensitive.{0,20}act\s+alone|handle\s+this\s+(yourself|personally|alone))\b/gi, label: 'act alone demand', weight: 0.9 },
      { regex: /\b(do\s+not\s+(consult|contact|call|tell)\s+(your\s+)?(lawyer|attorney|bank|police|family))\b/gi, label: 'anti-consultation demand', weight: 0.95 },
      { regex: /\b(between\s+(you\s+and\s+(me|us)|us\s+only)|just\s+between\s+us)\b/gi, label: 'exclusivity intimacy', weight: 0.8 },
      { regex: /\b(if\s+(you\s+)?(tell|share|discuss)\s+(this|with)\s+(anyone|anybody|others))\b/gi, label: 'sharing prohibition', weight: 0.85 },
      { regex: /\b(others?\s+(won'?t|wouldn'?t|don'?t|cannot)\s+understand)\b/gi, label: 'understanding exclusion', weight: 0.7 },
      { regex: /\b(only\s+(you|I|we)\s+(can|know|understand))\b/gi, label: 'exclusive knowledge claim', weight: 0.75 },
      { regex: /\b(do\s+not\s+(forward|share|screenshot|copy)\s+this\s+(email|message|text))\b/gi, label: 'anti-forwarding demand', weight: 0.8 },
      { regex: /\b(disclosure\s+(will|may)\s+(void|cancel|invalidate|jeopardize))\b/gi, label: 'disclosure penalty', weight: 0.85 },
      { regex: /\b(keep\s+this\s+(quiet|private|to\s+yourself|under\s+wraps))\b/gi, label: 'silence demand', weight: 0.8 },
      // Real isolation phrases used in scams (FTC + pig butchering + romance scam data)
      { regex: /\b(do\s+not\s+discuss|this\s+is\s+confidential)\b/gi, label: 'discussion prohibition', weight: 0.85 },
      { regex: /\b(between\s+us\s+only|act\s+alone)\b/gi, label: 'act alone demand', weight: 0.9 },
      { regex: /\b(don'?t\s+(contact|call)\s+(your\s+)?(bank|police))\b/gi, label: 'anti-authority contact', weight: 0.95 },
      { regex: /\b(time[- ]sensitive[^.]{0,30}(act|tell)\s+(others|anyone))\b/gi, label: 'urgency isolation combo', weight: 0.9 },
      { regex: /\b(secret\s+offer|exclusive\s+and\s+private)\b/gi, label: 'secret offer framing', weight: 0.8 },
    ],
  },
];

// ---------------------------------------------------------------------------
// Second-order (subtler) trigger patterns
// These are detected only after primary triggers are removed
// ---------------------------------------------------------------------------
const SECOND_ORDER_TRIGGERS: Array<{ regex: RegExp; label: string; weight: number }> = [
  { regex: /\b(please|kindly)\s+(do\s+not|don'?t)\s+(ignore|disregard|delete)/gi, label: 'soft persistence', weight: 0.5 },
  { regex: /\b(for\s+your\s+(own\s+)?(safety|security|protection|benefit))\b/gi, label: 'safety framing', weight: 0.5 },
  { regex: /\b(we\s+(care|value|appreciate)\s+(about\s+)?your?\b)/gi, label: 'false rapport', weight: 0.4 },
  { regex: /\b(this\s+is\s+not\s+(a\s+)?(scam|fraud|spam|joke))\b/gi, label: 'scam denial', weight: 0.8 },
  { regex: /\b(100%\s*(safe|secure|guaranteed|legitimate|legal|legit))\b/gi, label: 'over-reassurance', weight: 0.7 },
  { regex: /\b(do\s+not\s+(share|tell|forward|show)\s+(this|anyone))\b/gi, label: 'secrecy demand', weight: 0.75 },
  { regex: /\b(keep\s+this\s+(confidential|private|between\s+us|secret))\b/gi, label: 'confidentiality demand', weight: 0.75 },
  { regex: /\b(I\s+am\s+(a\s+)?(prince|minister|general|barrister|solicitor|diplomat))\b/gi, label: 'title claim', weight: 0.85 },
  { regex: /\b(god|bless(ing)?|pray|faith|church|pastor|reverend)\b/gi, label: 'religious appeal', weight: 0.35 },
  { regex: /\b(just\s+(between|for)\s+(us|you\s+and\s+me))\b/gi, label: 'intimacy push', weight: 0.6 },
  { regex: /\b(I\s+(promise|swear|assure\s+you)|trust\s+me|believe\s+me|I\s+would\s+never)\b/gi, label: 'trust assertion', weight: 0.6 },
  { regex: /\b(this\s+is\s+(your|a)\s+(last|final|only)\s+(opportunity|chance))\b/gi, label: 'opportunity framing', weight: 0.7 },
  { regex: /\b(I('m|\s+am)\s+(just\s+)?trying\s+to\s+help|I\s+want\s+(to\s+)?help\s+you)\b/gi, label: 'helper framing', weight: 0.5 },
  { regex: /\b(no\s+one\s+else\s+(can|will|is\s+going\s+to)\s+help)\b/gi, label: 'sole savior claim', weight: 0.75 },
  { regex: /\b(I\s+(chose|picked|selected)\s+you\s+(personally|specifically|specially))\b/gi, label: 'personal selection claim', weight: 0.7 },
  { regex: /\b(you('re|\s+are)\s+(special|unique|different|chosen|the\s+only\s+one))\b/gi, label: 'flattery manipulation', weight: 0.6 },
  { regex: /\b(I('ve|\s+have)\s+(never\s+)?(told|shared|revealed)\s+this\s+(to|with)\s+(anyone|anybody))\b/gi, label: 'exclusive revelation', weight: 0.65 },
  { regex: /\b(you\s+(can|should)\s+verify|check\s+(it\s+)?yourself|look\s+it\s+up)\b/gi, label: 'false verifiability', weight: 0.4 },
];

// ---------------------------------------------------------------------------
// Emotional exploitation scoring
// Measures the emotional manipulation intensity of the message
// ---------------------------------------------------------------------------
function computeEmotionalExploitation(text: string): EmotionalExploitationResult {
  const emotions: Record<string, Array<{ regex: RegExp; intensity: number }>> = {
    fear: [
      { regex: /\b(danger|dangerous|threat|risk|warning|alert|emergency)\b/gi, intensity: 0.7 },
      { regex: /\b(lose|lost|losing)\s+(everything|all|your)/gi, intensity: 0.9 },
      { regex: /\b(jail|prison|arrest|court|sued|prosecut)\b/gi, intensity: 0.95 },
      { regex: /\b(hack|breach|stolen|compromis|infect)\b/gi, intensity: 0.8 },
      { regex: /\b(destroy|ruin|devastat|catastroph|disaster)\b/gi, intensity: 0.85 },
    ],
    greed: [
      { regex: /\b(rich|wealth|fortune|millionaire|billionaire)\b/gi, intensity: 0.8 },
      { regex: /\b(profit|earn|income|money|cash|reward)\b/gi, intensity: 0.5 },
      { regex: /\b(free|bonus|prize|jackpot|winnings?)\b/gi, intensity: 0.7 },
      { regex: /\b(guaranteed\s+returns?|risk[- ]free|passive\s+income)\b/gi, intensity: 0.9 },
      { regex: /\$[\d,]+\s*(thousand|million|billion)/gi, intensity: 0.95 },
    ],
    trust: [
      { regex: /\b(official|authorized|certified|verified|legitimate)\b/gi, intensity: 0.6 },
      { regex: /\b(government|federal|bank|security|department)\b/gi, intensity: 0.7 },
      { regex: /\b(safe|secure|protected|encrypted|private)\b/gi, intensity: 0.5 },
      { regex: /\b(guarantee|warrant|assur|promis|certif)\b/gi, intensity: 0.6 },
    ],
    guilt: [
      { regex: /\b(disappointed|let\s+(me|us)\s+down|failing|neglect)\b/gi, intensity: 0.7 },
      { regex: /\b(you\s+owe|your\s+responsibility|your\s+duty|obligation)\b/gi, intensity: 0.8 },
      { regex: /\b(don'?t\s+you\s+care|how\s+could\s+you|shame)\b/gi, intensity: 0.85 },
    ],
    sympathy: [
      { regex: /\b(dying|terminal|cancer|sick|ill|hospital|orphan)\b/gi, intensity: 0.85 },
      { regex: /\b(help\s+(me|us|them)|desperate|begging|plea(se|ding))\b/gi, intensity: 0.7 },
      { regex: /\b(widow|orphan|refugee|homeless|starving|suffering)\b/gi, intensity: 0.8 },
      { regex: /\b(child(ren)?|baby|mother|father|family)\s+(need|sick|dying|hurt)/gi, intensity: 0.9 },
    ],
  };

  const breakdown: Record<string, number> = {};
  let totalIntensity = 0;
  let emotionCount = 0;
  let maxEmotion = '';
  let maxScore = 0;

  for (const [emotion, patterns] of Object.entries(emotions)) {
    let emotionScore = 0;
    for (const { regex, intensity } of patterns) {
      const re = new RegExp(regex.source, regex.flags);
      const matches = text.match(re);
      if (matches) {
        emotionScore += intensity * matches.length;
        emotionCount += matches.length;
      }
    }
    breakdown[emotion] = Math.min(1, emotionScore);
    totalIntensity += emotionScore;
    if (emotionScore > maxScore) {
      maxScore = emotionScore;
      maxEmotion = emotion;
    }
  }

  // Normalize by text length to get intensity per word
  const words = text.split(/\s+/).length;
  const normalizedIntensity = words > 0 ? Math.min(1, totalIntensity / (words * 0.1)) : 0;

  // Multi-emotion penalty: using multiple emotional vectors is more manipulative
  const activeEmotions = Object.values(breakdown).filter(v => v > 0.1).length;
  const multiEmotionBonus = activeEmotions > 2 ? 1 + (activeEmotions - 2) * 0.15 : 1;

  const score = Math.min(100, normalizedIntensity * multiEmotionBonus * 100);

  return {
    score: Math.round(score * 100) / 100,
    dominantEmotion: maxEmotion || 'none',
    emotionBreakdown: breakdown,
    manipulationIntensity: Math.round(normalizedIntensity * 10000) / 10000,
  };
}

// ---------------------------------------------------------------------------
// Compute a simple trust score based on benign vs malicious indicator ratio
// ---------------------------------------------------------------------------
function computeTrustScore(text: string): number {
  if (!text || text.length < 5) return 0.5;

  const words = text.split(/\s+/).length;

  // Benign indicators: informational, polite, standard business communication
  const benignPatterns = [
    /\b(thank\s+you|thanks|please|regards|sincerely)\b/gi,
    /\b(our\s+records?\s+show|according\s+to\s+our|as\s+you\s+(may\s+)?know)\b/gi,
    /\b(if\s+you\s+have\s+(any\s+)?(questions?|concerns?|issues?))\b/gi,
    /\b(feel\s+free\s+to|do\s+not\s+hesitate\s+to|you\s+may\s+(also|contact))\b/gi,
    /\b(business\s+hours?|monday|tuesday|wednesday|thursday|friday|9\s*am|5\s*pm)\b/gi,
    /\b(unsubscribe|opt[- ]out|manage\s+(your\s+)?preferences?|privacy\s+policy)\b/gi,
  ];

  // Malicious indicators: pressure, threats, demands, too-good-to-be-true
  const maliciousPatterns = [
    /\b(act\s+now|immediately|urgent(ly)?|hurry|rush|don'?t\s+delay)\b/gi,
    /\b(click\s+(here|below|this)|verify\s+now|confirm\s+now)\b/gi,
    /\b(suspend|deactivat|terminat|lock|block|arrest|prosecut)\b/gi,
    /\b(winner|prize|lottery|jackpot|selected|congratulations)\b/gi,
    /\b(wire|transfer|gift\s*card|bitcoin|western\s+union)\b/gi,
    /\b(password|ssn|social\s+security|credit\s+card|cvv|pin)\b/gi,
  ];

  let benignScore = 0;
  let maliciousScore = 0;

  for (const pat of benignPatterns) {
    const matches = text.match(pat);
    if (matches) benignScore += matches.length;
  }
  for (const pat of maliciousPatterns) {
    const matches = text.match(pat);
    if (matches) maliciousScore += matches.length;
  }

  // Normalize by word count
  const benignNorm = benignScore / Math.max(1, words) * 20;
  const maliciousNorm = maliciousScore / Math.max(1, words) * 20;

  // Trust = benign / (benign + malicious), with baseline of 0.5
  const total = benignNorm + maliciousNorm;
  if (total === 0) return 0.5;

  return benignNorm / total;
}

// ---------------------------------------------------------------------------
// Remove all matches of a pattern set from text
// ---------------------------------------------------------------------------
function removePatterns(text: string, patterns: Array<{ regex: RegExp }>): string {
  let cleaned = text;
  for (const { regex } of patterns) {
    // Reset regex lastIndex
    const re = new RegExp(regex.source, regex.flags);
    cleaned = cleaned.replace(re, '');
  }
  // Clean up extra whitespace
  return cleaned.replace(/\s{2,}/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Run the Cascade Breaker
// ---------------------------------------------------------------------------
export function runCascadeBreaker(input: AnalysisInput): CascadeBreakerResult {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText || allText.length < 10) {
    return {
      score: 0,
      breakdowns: [],
      overallFragility: 0,
      details: ['Insufficient text for cascade analysis'],
    };
  }

  const breakdowns: CascadeBreakdown[] = [];
  const details: string[] = [];

  // Compute baseline trust score with all triggers present
  const baselineTrust = computeTrustScore(allText);
  details.push(`Baseline trust score (all triggers present): ${baselineTrust.toFixed(4)}`);

  let totalFragility = 0;
  let categoriesWithTriggers = 0;

  // For each trigger category, remove it and recompute trust
  for (const category of TRIGGER_CATEGORIES) {
    const triggersFound: string[] = [];

    // Find all matches
    for (const { regex, label } of category.patterns) {
      const re = new RegExp(regex.source, regex.flags);
      const matches = allText.match(re);
      if (matches) {
        for (const m of matches) {
          triggersFound.push(`[${label}] "${m}"`);
        }
      }
    }

    if (triggersFound.length === 0) {
      details.push(`Category "${category.name}": no triggers found`);
      continue;
    }

    categoriesWithTriggers++;

    // Remove this category's triggers and recompute trust
    const cleanedText = removePatterns(allText, category.patterns);
    const postRemovalTrust = computeTrustScore(cleanedText);

    // Fragility = how much trust changes when triggers are removed
    // If trust goes UP when we remove triggers, the triggers were creating false urgency
    const trustDelta = postRemovalTrust - baselineTrust;
    const fragility = trustDelta > 0 ? 1 + trustDelta * 5 : 1;

    // Check for second-order triggers in cleaned text
    const secondOrderFound: string[] = [];
    for (const { regex, label } of SECOND_ORDER_TRIGGERS) {
      const re = new RegExp(regex.source, regex.flags);
      const matches = cleanedText.match(re);
      if (matches) {
        for (const m of matches) {
          secondOrderFound.push(`[${label}] "${m}"`);
        }
      }
    }

    totalFragility += fragility;

    const breakdown: CascadeBreakdown = {
      triggerCategory: category.name,
      triggersFound,
      preTrustScore: baselineTrust,
      postRemovalTrustScore: postRemovalTrust,
      fragility,
      secondOrderTriggers: secondOrderFound,
    };
    breakdowns.push(breakdown);

    details.push(
      `Category "${category.name}": ${triggersFound.length} trigger(s), ` +
      `trust ${baselineTrust.toFixed(3)} → ${postRemovalTrust.toFixed(3)}, ` +
      `fragility=${fragility.toFixed(3)}, ` +
      `${secondOrderFound.length} second-order trigger(s)`
    );
  }

  // Overall fragility: average fragility across categories that had triggers
  const overallFragility = categoriesWithTriggers > 0
    ? totalFragility / categoriesWithTriggers
    : 1.0;

  // Score: map fragility to 0-100
  // fragility = 1.0 means no change (neutral)
  // fragility > 1.0 means trust increases when triggers removed (suspicious)
  // We map [1.0, 2.0] → [0, 100]
  let score = 0;
  if (overallFragility > 1.0) {
    score = Math.min(100, (overallFragility - 1.0) * 100);
  }

  // Boost score based on number of trigger categories activated
  const categoryBoost = Math.min(1.5, 1 + categoriesWithTriggers * 0.1);
  score = Math.min(100, score * categoryBoost);

  // Additional boost for second-order triggers (recursive depth)
  const totalSecondOrder = breakdowns.reduce((sum, b) => sum + b.secondOrderTriggers.length, 0);
  if (totalSecondOrder > 0) {
    score = Math.min(100, score * (1 + totalSecondOrder * 0.05));
    details.push(`Second-order trigger boost: ${totalSecondOrder} subtler manipulation patterns found`);
  }

  // Weighted trigger importance: compute average weight of found triggers
  let totalTriggerWeight = 0;
  let triggerWeightCount = 0;
  for (const category of TRIGGER_CATEGORIES) {
    for (const { regex, weight } of category.patterns) {
      const re = new RegExp(regex.source, regex.flags);
      if (re.test(allText)) {
        totalTriggerWeight += weight;
        triggerWeightCount++;
      }
    }
  }
  if (triggerWeightCount > 0) {
    const avgWeight = totalTriggerWeight / triggerWeightCount;
    // High-weight triggers boost the score
    if (avgWeight > 0.75) {
      score = Math.min(100, score * (1 + (avgWeight - 0.75) * 0.5));
      details.push(`High average trigger weight: ${avgWeight.toFixed(3)} — score boosted`);
    }
  }

  // Isolation trigger penalty: isolation is one of the strongest scam indicators
  const isolationBreakdown = breakdowns.find(b => b.triggerCategory === 'isolation');
  if (isolationBreakdown && isolationBreakdown.triggersFound.length > 0) {
    const isolationBoost = 1 + isolationBreakdown.triggersFound.length * 0.1;
    score = Math.min(100, score * isolationBoost);
    details.push(`Isolation trigger detected: ${isolationBreakdown.triggersFound.length} pattern(s) — strong scam indicator`);
  }

  // Emotional exploitation analysis
  const emotionalResult = computeEmotionalExploitation(allText);
  if (emotionalResult.score > 20) {
    const emotionalBoost = 1 + (emotionalResult.score / 100) * 0.3;
    score = Math.min(100, score * emotionalBoost);
    details.push(`Emotional exploitation score: ${emotionalResult.score.toFixed(2)}/100 (dominant: ${emotionalResult.dominantEmotion}, intensity: ${emotionalResult.manipulationIntensity.toFixed(4)})`);
    for (const [emotion, value] of Object.entries(emotionalResult.emotionBreakdown)) {
      if (value > 0.1) {
        details.push(`  Emotion "${emotion}": ${(value * 100).toFixed(1)}%`);
      }
    }
  }

  details.push(`Overall fragility: ${overallFragility.toFixed(4)}`);
  details.push(`Categories with triggers: ${categoriesWithTriggers}/${TRIGGER_CATEGORIES.length}`);
  details.push(`Final cascade breaker score: ${score.toFixed(2)}/100`);

  return {
    score: Math.round(score * 100) / 100,
    breakdowns,
    overallFragility: Math.round(overallFragility * 10000) / 10000,
    details,
  };
}
