"use client";

import { useState, useEffect } from "react";
import { Shield, Mail, Lock, Eye, EyeOff, AlertTriangle, ArrowRight, Loader2, CheckCircle2, Gift } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createBrowserClient } from "@/lib/supabase/client";

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [referralCode, setReferralCode] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [pendingUserId, setPendingUserId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();

  // Pre-fill referral code from URL ?ref=CODE
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ref = params.get("ref");
    if (ref) setReferralCode(ref.toUpperCase());
  }, []);

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords don't match.");
      return;
    }

    setLoading(true);

    const supabase = createBrowserClient();
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback?next=/dashboard`,
      },
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      // If referral code provided, redeem it after account creation
      if (referralCode.trim() && data.user) {
        setPendingUserId(data.user.id);
        try {
          const res = await fetch("/api/referral/redeem", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: referralCode.trim().toUpperCase() }),
          });
          // Non-blocking — ignore errors (user can redeem later)
          const rData = await res.json().catch(() => ({}));
          if (rData.bonusScans) {
            // Show bonus in done screen
            setPendingUserId(String(rData.bonusScans));
          }
        } catch { /* ignore */ }
      }
      setDone(true);
      setLoading(false);
    }
  }

  // Password strength
  const strength = password.length === 0 ? 0 : password.length < 8 ? 1 : password.length < 12 ? 2 : 3;
  const strengthLabel = ["", "Weak", "Good", "Strong"][strength];
  const strengthColor = ["", "text-danger", "text-caution", "text-safe"][strength];
  const strengthBg = ["bg-border", "bg-danger", "bg-caution", "bg-safe"];

  return (
    <div className="min-h-[80vh] flex items-center justify-center py-12">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-shield/10 border border-shield/20 mb-4">
            <Shield className="w-7 h-7 text-shield" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">Create your account</h1>
          <p className="text-text-muted text-sm mt-1">Start detecting scams for free — no credit card needed</p>
        </div>

        {done ? (
          <div className="glass-card p-8 text-center space-y-3">
            <CheckCircle2 className="w-12 h-12 text-safe mx-auto mb-2" />
            <h2 className="text-lg font-semibold text-text-primary">Check your email</h2>
            <p className="text-sm text-text-secondary">
              We sent a confirmation link to <span className="text-shield font-mono">{email}</span>.
              Click it to activate your account.
            </p>
            {pendingUserId && parseInt(pendingUserId) > 0 && (
              <div className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-shield/10 border border-shield/20 text-shield text-sm">
                <Gift size={14} />
                Referral applied! +{pendingUserId} bonus scans added to your account.
              </div>
            )}
            <Link
              href="/login"
              className="inline-flex items-center gap-2 mt-4 text-sm text-shield hover:underline"
            >
              Back to login
              <ArrowRight size={14} />
            </Link>
          </div>
        ) : (
          <div className="glass-card p-6 md:p-8">
            <form onSubmit={handleSignup} className="space-y-4">
              {/* Email */}
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1.5">Email address</label>
                <div className="relative">
                  <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    required
                    autoComplete="email"
                    className="w-full pl-9 pr-4 py-2.5 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20 transition-colors"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1.5">Password</label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    required
                    autoComplete="new-password"
                    className="w-full pl-9 pr-10 py-2.5 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20 transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                {/* Strength bar */}
                {password.length > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <div className="flex gap-1 flex-1">
                      {[1, 2, 3].map((i) => (
                        <div
                          key={i}
                          className={`h-1 flex-1 rounded-full transition-colors ${
                            i <= strength ? strengthBg[strength] : "bg-border"
                          }`}
                        />
                      ))}
                    </div>
                    <span className={`text-xs font-mono ${strengthColor}`}>{strengthLabel}</span>
                  </div>
                )}
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1.5">Confirm password</label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    required
                    autoComplete="new-password"
                    className="w-full pl-9 pr-4 py-2.5 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20 transition-colors"
                  />
                  {confirmPassword.length > 0 && (
                    <div className={`absolute right-3 top-1/2 -translate-y-1/2 ${password === confirmPassword ? "text-safe" : "text-danger"}`}>
                      {password === confirmPassword ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                    </div>
                  )}
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="flex items-start gap-2 p-2.5 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs">
                  <AlertTriangle size={12} className="shrink-0 mt-0.5" />
                  {error}
                </div>
              )}

              {/* Referral code */}
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1.5">
                  Referral code <span className="text-text-muted font-normal">(optional — get +20 bonus scans)</span>
                </label>
                <div className="relative">
                  <Gift size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                  <input
                    type="text"
                    value={referralCode}
                    onChange={(e) => setReferralCode(e.target.value.toUpperCase())}
                    placeholder="e.g. AB3K9XWZ"
                    maxLength={12}
                    autoComplete="off"
                    className="w-full pl-9 pr-4 py-2.5 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20 transition-colors font-mono tracking-wider"
                  />
                </div>
              </div>

              {/* Terms note */}
              <p className="text-xs text-text-muted">
                By signing up you agree to our{" "}
                <span className="text-shield">Terms of Service</span> and{" "}
                <span className="text-shield">Privacy Policy</span>.
              </p>

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-shield text-void font-semibold text-sm hover:bg-shield/90 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : (
                  <>
                    Create account
                    <ArrowRight size={15} />
                  </>
                )}
              </button>
            </form>

            {/* Divider */}
            <div className="flex items-center gap-3 mt-5">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-text-muted">or</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            {/* Google Sign Up */}
            <button
              onClick={async () => {
                setLoading(true);
                setError(null);
                const supabase = createBrowserClient();
                const { error } = await supabase.auth.signInWithOAuth({
                  provider: "google",
                  options: {
                    redirectTo: `${window.location.origin}/auth/callback?next=/dashboard`,
                  },
                });
                if (error) {
                  setError(error.message);
                  setLoading(false);
                }
              }}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2.5 py-2.5 mt-3 rounded-lg border border-border text-sm text-text-secondary hover:text-text-primary hover:border-shield/30 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <svg width="16" height="16" viewBox="0 0 24 24">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
              </svg>
              Sign up with Google
            </button>

            <p className="mt-4 text-center text-xs text-text-muted">
              Already have an account?{" "}
              <Link href="/login" className="text-shield hover:underline">
                Sign in
              </Link>
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
