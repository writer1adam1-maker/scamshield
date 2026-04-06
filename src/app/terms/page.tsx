import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms of Service — ScamShieldy",
  description: "Terms and conditions for using ScamShieldy's AI-powered scam detection service.",
};

export default function TermsPage() {
  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-text-primary mb-2">Terms of Service</h1>
        <p className="text-text-muted font-mono text-sm">Last updated: April 6, 2026</p>
      </div>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">1. Acceptance of Terms</h2>
        <p className="text-text-secondary leading-relaxed">
          By accessing or using ScamShieldy (&ldquo;the Service&rdquo;), you agree to be bound by these Terms of Service.
          If you do not agree, do not use the Service. These terms apply to all visitors, users, and anyone who accesses
          or uses ScamShieldy.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">2. Description of Service</h2>
        <p className="text-text-secondary leading-relaxed">
          ScamShieldy is an AI-powered fraud and scam detection tool. It analyzes text, URLs, and email metadata
          to identify potential scams, phishing attempts, and social engineering attacks. Results are provided for
          informational purposes only.
        </p>
        <p className="text-text-secondary leading-relaxed">
          <strong className="text-text-primary">ScamShieldy does not guarantee that all scams will be detected</strong> or that
          all flagged content is fraudulent. Always use your own judgment and do not rely solely on our analysis for
          financial, legal, or security decisions.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">3. User Accounts</h2>
        <p className="text-text-secondary leading-relaxed">
          You must provide accurate information when creating an account. You are responsible for maintaining the
          security of your account credentials. You must notify us immediately of any unauthorized access to your account.
          We reserve the right to suspend or terminate accounts that violate these terms.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">4. Acceptable Use</h2>
        <p className="text-text-secondary leading-relaxed">You agree not to:</p>
        <ul className="list-disc list-inside space-y-2 text-text-secondary leading-relaxed">
          <li>Use the Service to harass, harm, or discriminate against any person</li>
          <li>Submit content that is illegal, abusive, or violates third-party rights</li>
          <li>Attempt to reverse-engineer, scrape, or extract the detection models or pattern database</li>
          <li>Use automated scripts or bots to abuse the scan limits</li>
          <li>Use the Service to test or improve your own scam/phishing campaigns</li>
          <li>Circumvent any rate limits, access controls, or security measures</li>
        </ul>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">5. Subscription Plans and Billing</h2>
        <p className="text-text-secondary leading-relaxed">
          ScamShieldy offers free and paid (Pro) plans. Paid subscriptions are billed through Paddle.
          Prices are displayed at checkout. By subscribing, you authorize Paddle to charge your payment method
          on a recurring basis according to your chosen billing cycle.
        </p>
        <p className="text-text-secondary leading-relaxed">
          You may cancel your subscription at any time from your account settings. Cancellations take effect at the
          end of the current billing period. We do not offer refunds for partial billing periods unless required by law.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">6. Intellectual Property</h2>
        <p className="text-text-secondary leading-relaxed">
          All content, designs, algorithms, and software within ScamShieldy are owned by us or our licensors.
          You may not copy, reproduce, distribute, or create derivative works without our written permission.
          The scam pattern database and detection models are proprietary.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">7. Disclaimer of Warranties</h2>
        <p className="text-text-secondary leading-relaxed">
          THE SERVICE IS PROVIDED &ldquo;AS IS&rdquo; AND &ldquo;AS AVAILABLE&rdquo; WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED,
          INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
          WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR THAT DETECTION RESULTS WILL BE ACCURATE.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">8. Limitation of Liability</h2>
        <p className="text-text-secondary leading-relaxed">
          TO THE MAXIMUM EXTENT PERMITTED BY LAW, SCAMSHIELDY SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
          CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING LOSS OF PROFITS, DATA, OR GOODWILL, ARISING FROM YOUR USE OF
          OR INABILITY TO USE THE SERVICE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">9. Third-Party Services</h2>
        <p className="text-text-secondary leading-relaxed">
          ScamShieldy integrates with third-party services including Supabase (database), Paddle (payments),
          Resend (email), and Google (Gmail OAuth). Your use of these services is subject to their respective terms
          and privacy policies. We are not responsible for the practices of third-party services.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">10. Modifications to the Service</h2>
        <p className="text-text-secondary leading-relaxed">
          We reserve the right to modify, suspend, or discontinue any part of the Service at any time without notice.
          We may also update these Terms at any time. Continued use of the Service after changes constitutes acceptance
          of the updated Terms.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">11. Governing Law</h2>
        <p className="text-text-secondary leading-relaxed">
          These Terms shall be governed by and construed in accordance with applicable law. Any disputes arising
          from these Terms or your use of the Service shall be resolved through good-faith negotiation. If unresolved,
          disputes shall be submitted to binding arbitration.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">12. Contact</h2>
        <p className="text-text-secondary leading-relaxed">
          Questions about these Terms?{" "}
          <Link href="/contact" className="text-shield hover:underline">Contact us</Link>.
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
