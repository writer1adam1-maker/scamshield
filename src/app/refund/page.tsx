import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Refund Policy — ScamShieldy",
  description: "ScamShieldy's refund policy. We offer a full 30-day refund, no questions asked.",
};

export default function RefundPage() {
  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-text-primary mb-2">Refund Policy</h1>
        <p className="text-text-muted font-mono text-sm">Last updated: April 6, 2026</p>
      </div>

      <section className="glass-card p-6 space-y-4 border border-shield/20">
        <h2 className="text-xl font-semibold text-text-primary">30-Day Money-Back Guarantee</h2>
        <p className="text-text-secondary leading-relaxed text-lg">
          We offer a full refund within <strong className="text-text-primary">30 days</strong> of purchase.
          If you are not satisfied for any reason, contact us within 30 days and you will receive a complete refund —
          no questions asked.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">How to Request a Refund</h2>
        <p className="text-text-secondary leading-relaxed">
          To request a refund, simply{" "}
          <Link href="/contact" className="text-shield hover:underline">contact us</Link>{" "}
          within 30 days of your purchase date. Include your email address and we will process your refund promptly.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">Subscription Cancellations</h2>
        <p className="text-text-secondary leading-relaxed">
          You can cancel your subscription at any time from your account settings. Cancellations take effect at the
          end of the current billing period and you will not be charged again. If you cancel within the first 30 days,
          you are entitled to a full refund of the amount paid.
        </p>
      </section>

      <section className="glass-card p-6 space-y-4">
        <h2 className="text-xl font-semibold text-text-primary">Processing Time</h2>
        <p className="text-text-secondary leading-relaxed">
          Refunds are processed within 5–10 business days and returned to your original payment method.
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
