// ---------------------------------------------------------------------------
// Tour step definitions for every page in ScamShield
// ---------------------------------------------------------------------------

export interface TourStep {
  /** data-tour attribute value on the target element */
  target: string;
  /** Short title shown in the tooltip header */
  title: string;
  /** Plain-English explanation (no jargon) */
  description: string;
}

export type TourPage =
  | "home"
  | "vaccine"
  | "dashboard"
  | "conversation"
  | "settings";

export const TOUR_STEPS: Record<TourPage, TourStep[]> = {
  // -----------------------------------------------------------------------
  // HOMEPAGE
  // -----------------------------------------------------------------------
  home: [
    {
      target: "scan-input",
      title: "Paste anything suspicious here",
      description:
        "Got a sketchy text, email, or link? Paste it right here. Pick the tab that matches \u2014 URL for links, Text for messages, or Screenshot for images.",
    },
    {
      target: "scan-tabs",
      title: "Choose what you\u2019re checking",
      description:
        "URL tab is for suspicious links. Text tab is for weird messages or emails. Screenshot tab lets you upload a photo of a scam text.",
    },
    {
      target: "analyze-button",
      title: "Hit this to scan",
      description:
        "Once you\u2019ve pasted your suspicious content, click Analyze. Our AI checks it against thousands of known scam patterns in under a second.",
    },
    {
      target: "score-ring",
      title: "Your threat score",
      description:
        "This circle shows how dangerous the content is on a scale of 0\u2013100. Green (0\u201330) means safe. Orange (31\u201360) means suspicious. Red (61+) means it\u2019s very likely a scam.",
    },
    {
      target: "evidence-section",
      title: "Proof of what we found",
      description:
        "These cards show exactly WHY we think it\u2019s a scam (or not). Each card explains a specific red flag we detected, like fake urgency or financial demands.",
    },
    {
      target: "layer-breakdown",
      title: "How we analyzed it",
      description:
        "Our AI uses 4 different detection methods simultaneously. Think of it like 4 different detectives all investigating the same case \u2014 if they all agree it\u2019s suspicious, we\u2019re more confident.",
    },
    {
      target: "financial-risk",
      title: "Money at risk",
      description:
        "If we detect a financial scam, this section estimates how much money you could lose and what type of fraud it is.",
    },
    {
      target: "feedback-buttons",
      title: "Help us improve",
      description:
        "Tell us if we got it right! Your feedback makes our detection smarter over time.",
    },
  ],

  // -----------------------------------------------------------------------
  // VACCINE PAGE
  // -----------------------------------------------------------------------
  vaccine: [
    {
      target: "vaccine-modes",
      title: "5 ways to check",
      description:
        "Choose how you want to scan. Website checks a live site for scam tricks. Phone analyzes phone numbers. SMS and Email scan message text. QR checks suspicious QR codes.",
    },
    {
      target: "vaccine-input",
      title: "Enter what you want to check",
      description:
        "Type or paste the thing you want to scan here. For websites, paste the URL. For phone/SMS/email, paste the number or message.",
    },
    {
      target: "vaccine-scan-button",
      title: "Start the scan",
      description:
        "Click this to run a deep scan. For websites, we actually visit the page and check for hidden tricks like fake login forms or invisible data collectors.",
    },
    {
      target: "breach-cards",
      title: "What we found wrong",
      description:
        "Each card represents a specific problem we detected. Red cards are serious \u2014 like a fake login form trying to steal your password. Yellow cards are warnings.",
    },
    {
      target: "breach-severity",
      title: "How serious each problem is",
      description:
        "The color tells you the danger level. Green = minor issue. Yellow = be careful. Orange = probably dangerous. Red = definitely a threat.",
    },
    {
      target: "breach-rule-type",
      title: "What to do about it",
      description:
        "Each card tells you the recommended action: BLOCK means avoid entirely. WARN means proceed with caution. SANDBOX means the site is doing something sneaky.",
    },
    {
      target: "vaccine-button",
      title: "Apply protection",
      description:
        "This button applies protective rules to block the threats we found. Think of it like a vaccine shot \u2014 it protects you from the specific threats detected.",
    },
  ],

  // -----------------------------------------------------------------------
  // DASHBOARD
  // -----------------------------------------------------------------------
  dashboard: [
    {
      target: "dashboard-stats",
      title: "Your scanning overview",
      description:
        "These four boxes show your activity at a glance \u2014 how many scans you\u2019ve done, how many threats we caught, your average threat score, and the most common scam type you\u2019ve encountered.",
    },
    {
      target: "recent-scans",
      title: "Your latest scans",
      description:
        "A quick list of everything you\u2019ve checked recently. Click any row to see the full details. The color-coded score helps you spot dangerous ones fast.",
    },
    {
      target: "threat-distribution",
      title: "What types of scams you\u2019re seeing",
      description:
        "This shows what kinds of scams are showing up in your scans. If you\u2019re seeing a lot of phishing, you might be getting targeted.",
    },
    {
      target: "trending-categories",
      title: "What\u2019s trending globally",
      description:
        "These are the scam types that are spiking RIGHT NOW across all ScamShield users. If phishing is trending, scammers are running a campaign.",
    },
    {
      target: "active-outbreaks",
      title: "Active scam outbreaks",
      description:
        "Think of this like a weather warning. When we detect a sudden spike in a specific scam type, it shows up here as an \u2018outbreak\u2019. Stay extra cautious during outbreaks.",
    },
    {
      target: "predictions",
      title: "What\u2019s coming next",
      description:
        "Our AI predicts which scam types are likely to increase in the coming days based on patterns. This helps you stay one step ahead.",
    },
  ],

  // -----------------------------------------------------------------------
  // CONVERSATION ANALYZER
  // -----------------------------------------------------------------------
  conversation: [
    {
      target: "conversation-input",
      title: "Paste a chat conversation",
      description:
        "Copy-paste a conversation from WhatsApp, Telegram, dating apps, or any messenger. We analyze the entire flow of the conversation to detect manipulation.",
    },
    {
      target: "conversation-formats",
      title: "Supported formats",
      description:
        "We understand WhatsApp exports, Telegram exports, and plain text. Just paste it \u2014 we figure out the format automatically.",
    },
    {
      target: "arc-risk-gauge",
      title: "Overall manipulation score",
      description:
        "This shows how manipulative the conversation is overall. Higher scores mean more grooming tactics detected. 60+ is serious cause for concern.",
    },
    {
      target: "phase-timeline",
      title: "The manipulation timeline",
      description:
        "Scammers follow a pattern: first they build trust, then isolate you, then ask for money. This timeline shows which stages of manipulation appear in your conversation.",
    },
    {
      target: "phase-cards",
      title: "Detailed phase analysis",
      description:
        "Each card represents one stage of the scam playbook. Green phases (trust building) are normal in any conversation. Red phases (pressure, money requests) are the danger signs.",
    },
  ],

  // -----------------------------------------------------------------------
  // SETTINGS
  // -----------------------------------------------------------------------
  settings: [
    {
      target: "settings-account",
      title: "Your account",
      description:
        "View your email, current plan, and referral code. Share your referral code with friends \u2014 you both get 10 free scans!",
    },
    {
      target: "settings-api-keys",
      title: "API Keys",
      description:
        "If you use our browser extension, you need an API key. Create one here, copy it, and paste it into the extension settings. This connects the extension to your account.",
    },
    {
      target: "settings-theme",
      title: "Choose your look",
      description:
        "Pick a color theme you like. Dark is the default cybersecurity look. Light mode is available if you prefer a brighter screen.",
    },
    {
      target: "settings-danger",
      title: "Delete account",
      description:
        "If you ever want to leave, you can delete your account here. This is permanent and removes all your data.",
    },
  ],
};

/** Map pathname to TourPage key */
export function pathToTourPage(pathname: string): TourPage | null {
  if (pathname === "/") return "home";
  if (pathname === "/vaccine") return "vaccine";
  if (pathname === "/dashboard") return "dashboard";
  if (pathname === "/conversation") return "conversation";
  if (pathname === "/settings") return "settings";
  return null;
}
