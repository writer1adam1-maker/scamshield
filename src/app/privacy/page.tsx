import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Policy — ScamShieldy",
  description: "How ScamShieldy collects, uses, and protects your data, including Google user data accessed via Gmail Shield.",
};

export default function PrivacyPage() {
  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-text-primary mb-2">Privacy Policy</h1>
        <p className="text-text-muted font-mono text-sm">Last updated: April 6, 2026</p>
      </div>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">1. Who We Are</h2>
        <p className="text-text-secondary leading-relaxed">
          ScamShieldy (&ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;) is an AI-powered scam and fraud detection service available at{" "}
          <span className="text-shield font-mono">scamshieldy.com</span>. We help users identify phishing attempts, scam messages,
          malicious URLs, and social engineering attacks in real time.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">2. Information We Collect</h2>

        <div className="space-y-3">
          <h3 className="font-semibold text-text-primary">Account Information</h3>
          <p className="text-text-secondary leading-relaxed">
            When you create an account, we collect your email address and a hashed password (via Supabase Auth).
            We also store your subscription plan (free or pro) and scan usage counts.
          </p>

          <h3 className="font-semibold text-text-primary">Scan Data</h3>
          <p className="text-text-secondary leading-relaxed">
            Text, URLs, or messages you submit for scanning are processed in real time by our detection engine.
            We may store anonymized scan results (threat score, category) for aggregate statistics. We do not store
            the raw content you submit beyond the immediate analysis session.
          </p>

          <h3 className="font-semibold text-text-primary">Usage Data</h3>
          <p className="text-text-secondary leading-relaxed">
            We collect basic usage metrics (number of scans today, threat counts) to display aggregate statistics.
            We do not use third-party analytics services that track individual behavior.
          </p>
        </div>
      </section>

      <section className="glass-card p-6 space-y-4 border border-shield/20">
        <h2 className="text-xl font-semibold text-text-primary">3. Google User Data (Gmail Shield)</h2>
        <p className="text-text-secondary leading-relaxed">
          ScamShieldy offers an optional <strong className="text-text-primary">Gmail Shield</strong> feature that connects
          to your Gmail account via Google OAuth 2.0 to automatically scan incoming emails for scams.
        </p>

        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-text-primary mb-1">What we access</h3>
            <p className="text-text-secondary leading-relaxed">
              We request the <span className="font-mono text-shield text-sm">https://www.googleapis.com/auth/gmail.metadata</span> scope only.
              This scope allows us to read email <strong>metadata</strong>: sender address, subject line, date, and message ID.
              <strong className="text-text-primary"> We do not access, read, or store the body or attachments of your emails.</strong>
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">Why we access it</h3>
            <p className="text-text-secondary leading-relaxed">
              Email subjects and sender addresses are sufficient to detect the majority of phishing, scam, and social engineering
              attacks. We analyze this metadata through our scam detection engine to flag suspicious messages and alert you.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">How we store it</h3>
            <p className="text-text-secondary leading-relaxed">
              Your OAuth tokens (access token and refresh token) are encrypted at rest using AES-256-GCM and stored in our
              Supabase database. Tokens are associated with your user account and are never shared with third parties.
              Email metadata processed during scanning is not permanently stored — it is analyzed in memory and discarded.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">How we use it</h3>
            <p className="text-text-secondary leading-relaxed">
              Google user data (email metadata) is used solely for the purpose of scam detection within ScamShieldy.
              We do not use this data for advertising, profiling, training AI models, or any purpose other than providing
              the Gmail Shield service you explicitly enabled.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">Data sharing</h3>
            <p className="text-text-secondary leading-relaxed">
              We do not sell, share, transfer, or disclose Google user data to any third party. Your Gmail metadata
              is processed exclusively within ScamShieldy&apos;s infrastructure.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">Revoking access</h3>
            <p className="text-text-secondary leading-relaxed">
              You can disconnect Gmail Shield at any time from your{" "}
              <Link href="/dashboard/gmail" className="text-shield hover:underline">Gmail dashboard</Link>.
              This immediately revokes our access token and deletes your stored tokens from our database.
              You can also revoke access directly from your{" "}
              <a
                href="https://myaccount.google.com/permissions"
                target="_blank"
                rel="noopener noreferrer"
                className="text-shield hover:underline"
              >
                Google Account permissions page
              </a>.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-text-primary mb-1">Compliance with Google API Services User Data Policy</h3>
            <p className="text-text-secondary leading-relaxed">
              ScamShieldy&apos;s use and transfer to any other app of information received from Google APIs adheres to the{" "}
              <a
                href="https://developers.google.com/terms/api-services-user-data-policy"
                target="_blank"
                rel="noopener noreferrer"
                className="text-shield hover:underline"
              >
                Google API Services User Data Policy
              </a>
              , including the Limited Use requirements.
            </p>
          </div>
        </div>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">4. Cookies and Session Storage</h2>
        <p className="text-text-secondary leading-relaxed">
          We use essential cookies for authentication (Supabase session cookies) and short-lived CSRF state tokens
          during OAuth flows. We do not use advertising or tracking cookies.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">5. Data Retention</h2>
        <p className="text-text-secondary leading-relaxed">
          Account data is retained until you delete your account. OAuth tokens for Gmail Shield are deleted immediately
          when you disconnect the integration. Anonymized aggregate statistics (scan counts, threat counts) are retained
          indefinitely as they contain no personal information.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">6. Security</h2>
        <p className="text-text-secondary leading-relaxed">
          We use industry-standard security practices: HTTPS everywhere, AES-256-GCM encryption for sensitive tokens,
          row-level security in our Supabase database, and server-side admin verification for all admin operations.
          Webhook signatures are verified before processing any payment events.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">7. Your Rights</h2>
        <p className="text-text-secondary leading-relaxed">
          You have the right to access, correct, or delete your personal data. To request data deletion or export,
          contact us at the email below. We will respond within 30 days.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">8. Changes to This Policy</h2>
        <p className="text-text-secondary leading-relaxed">
          We may update this privacy policy from time to time. The &ldquo;Last updated&rdquo; date at the top reflects the most
          recent revision. Continued use of ScamShieldy after changes constitutes acceptance of the updated policy.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">9. Contact</h2>
        <p className="text-text-secondary leading-relaxed">
          For privacy-related questions, data deletion requests, or concerns about how we handle Google user data,
          please contact us at:{" "}
          <a href="mailto:privacy@scamshieldy.com" className="text-shield hover:underline font-mono">
            privacy@scamshieldy.com
          </a>
        </p>
      </section>

      <div className="text-center pt-4">
        <Link href="/" className="text-text-muted hover:text-text-primary text-sm transition-colors">
          ← Back to ScamShieldy
        </Link>
      </div>
    </div>
  );
}
