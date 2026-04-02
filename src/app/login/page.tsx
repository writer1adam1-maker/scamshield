"use client";

import { useState, Suspense } from "react";
import { Shield, Mail, Lock, Eye, EyeOff, AlertTriangle, ArrowRight, Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { createBrowserClient } from "@/lib/supabase/client";

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [magicSent, setMagicSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();
  const searchParams = useSearchParams();
  const nextPath = searchParams.get("next") ?? "/dashboard";
  const urlError = searchParams.get("error");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const supabase = createBrowserClient();
    const { error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      router.push(nextPath);
      router.refresh();
    }
  }

  async function handleMagicLink() {
    if (!email.trim()) {
      setError("Enter your email address first.");
      return;
    }
    setLoading(true);
    setError(null);

    const supabase = createBrowserClient();
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextPath)}`,
      },
    });

    if (error) {
      setError(error.message);
    } else {
      setMagicSent(true);
    }
    setLoading(false);
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center py-12">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-shield/10 border border-shield/20 mb-4">
            <Shield className="w-7 h-7 text-shield" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">Welcome back</h1>
          <p className="text-text-muted text-sm mt-1">Sign in to your ScamShield account</p>
        </div>

        {/* Error from URL (e.g. OAuth failure) */}
        {urlError && (
          <div className="mb-4 flex items-start gap-2 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            Authentication failed. Please try again.
          </div>
        )}

        {magicSent ? (
          <div className="glass-card p-8 text-center space-y-3">
            <div className="text-4xl mb-2">📧</div>
            <h2 className="text-lg font-semibold text-text-primary">Check your email</h2>
            <p className="text-sm text-text-secondary">
              We sent a magic link to <span className="text-shield font-mono">{email}</span>.
              Click the link to sign in — no password needed.
            </p>
            <button
              onClick={() => setMagicSent(false)}
              className="text-xs text-text-muted hover:text-text-secondary transition-colors mt-2"
            >
              Try a different email
            </button>
          </div>
        ) : (
          <div className="glass-card p-6 md:p-8 space-y-5">
            <form onSubmit={handleLogin} className="space-y-4">
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
                    placeholder="••••••••"
                    autoComplete="current-password"
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
              </div>

              {/* Error */}
              {error && (
                <div className="flex items-start gap-2 p-2.5 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs">
                  <AlertTriangle size={12} className="shrink-0 mt-0.5" />
                  {error}
                </div>
              )}

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
                    Sign in
                    <ArrowRight size={15} />
                  </>
                )}
              </button>
            </form>

            {/* Divider */}
            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-text-muted">or</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            {/* Magic Link */}
            <button
              onClick={handleMagicLink}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg border border-border text-sm text-text-secondary hover:text-text-primary hover:border-shield/30 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <Mail size={15} />
              Send magic link (passwordless)
            </button>

            {/* Footer links */}
            <div className="flex items-center justify-between text-xs text-text-muted pt-1">
              <Link href="/signup" className="hover:text-shield transition-colors">
                No account? Sign up
              </Link>
              <button
                onClick={async () => {
                  if (!email.trim()) { setError("Enter your email to reset password."); return; }
                  const supabase = createBrowserClient();
                  await supabase.auth.resetPasswordForEmail(email, {
                    redirectTo: `${window.location.origin}/auth/callback?next=/settings`,
                  });
                  setError("Password reset email sent.");
                }}
                className="hover:text-shield transition-colors"
              >
                Forgot password?
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
