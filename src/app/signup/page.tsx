"use client";

import { useState } from "react";
import { Shield, Mail, Lock, Eye, EyeOff, AlertTriangle, ArrowRight, Loader2, CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createBrowserClient } from "@/lib/supabase/client";

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();

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
    const { error } = await supabase.auth.signUp({
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

            <p className="mt-5 text-center text-xs text-text-muted">
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
