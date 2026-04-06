"use client";

import { useState } from "react";
import Link from "next/link";
import { Send, CheckCircle, AlertCircle } from "lucide-react";

export default function ContactPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "success" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("sending");
    setErrorMsg("");

    try {
      const res = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, subject, message }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || "Failed to send message.");
      }

      setStatus("success");
      setName("");
      setEmail("");
      setSubject("");
      setMessage("");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Something went wrong.");
      setStatus("error");
    }
  }

  return (
    <div className="max-w-xl mx-auto py-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-text-primary mb-2">Contact Us</h1>
        <p className="text-text-secondary leading-relaxed">
          Have a question, found a bug, or want to report a scam pattern? Send us a message and we&apos;ll get back to you.
        </p>
      </div>

      {status === "success" ? (
        <div className="glass-card p-8 text-center space-y-4">
          <CheckCircle className="w-12 h-12 text-safe mx-auto" />
          <h2 className="text-xl font-semibold text-text-primary">Message Sent</h2>
          <p className="text-text-secondary">
            Thanks for reaching out. We&apos;ll get back to you as soon as possible.
          </p>
          <button
            onClick={() => setStatus("idle")}
            className="btn-secondary text-sm px-4 py-2 rounded-lg"
          >
            Send another message
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="glass-card p-6 space-y-5">
          <div>
            <label className="block text-sm font-mono text-text-muted mb-1">Your Name</label>
            <input
              type="text"
              required
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="John Smith"
              className="w-full bg-void border border-white/10 rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-mono text-text-muted mb-1">Your Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full bg-void border border-white/10 rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-mono text-text-muted mb-1">Subject</label>
            <input
              type="text"
              required
              value={subject}
              onChange={e => setSubject(e.target.value)}
              placeholder="Bug report, question, feedback…"
              className="w-full bg-void border border-white/10 rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-mono text-text-muted mb-1">Message</label>
            <textarea
              required
              rows={6}
              value={message}
              onChange={e => setMessage(e.target.value)}
              placeholder="Tell us what's on your mind…"
              className="w-full bg-void border border-white/10 rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors resize-none"
            />
          </div>

          {status === "error" && (
            <div className="flex items-center gap-2 text-danger text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {errorMsg}
            </div>
          )}

          <button
            type="submit"
            disabled={status === "sending"}
            className="w-full flex items-center justify-center gap-2 bg-shield hover:bg-shield/90 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-colors"
          >
            <Send className="w-4 h-4" />
            {status === "sending" ? "Sending…" : "Send Message"}
          </button>
        </form>
      )}

      <div className="text-center">
        <Link href="/" className="text-text-muted hover:text-text-primary text-sm transition-colors">
          ← Back to ScamShieldy
        </Link>
      </div>
    </div>
  );
}
