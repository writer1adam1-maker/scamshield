"use client";

import { useState, useEffect } from "react";
import { Settings, Bell, Moon, User, Trash2, LogOut, Loader2, CheckCircle2, AlertTriangle, Key } from "lucide-react";
import { createBrowserClient } from "@/lib/supabase/client";
import { useRouter } from "next/navigation";
import type { User as SupabaseUser } from "@supabase/supabase-js";

export default function SettingsPage() {
  const [notifications, setNotifications] = useState(true);
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);
  const [signingOut, setSigningOut] = useState(false);
  const [passwordResetSent, setPasswordResetSent] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const supabase = createBrowserClient();
    supabase.auth.getUser().then(({ data }) => {
      setUser(data.user);
      setLoadingUser(false);
    });
  }, []);

  async function handleSignOut() {
    setSigningOut(true);
    const supabase = createBrowserClient();
    await supabase.auth.signOut();
    router.push("/");
    router.refresh();
  }

  async function handlePasswordReset() {
    if (!user?.email) return;
    const supabase = createBrowserClient();
    await supabase.auth.resetPasswordForEmail(user.email, {
      redirectTo: `${window.location.origin}/auth/callback?next=/settings`,
    });
    setPasswordResetSent(true);
  }

  return (
    <div className="space-y-8 max-w-2xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Settings className="w-6 h-6 text-shield" />
          Settings
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Manage your preferences and account
        </p>
      </div>

      {/* Account */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <User className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Account</h2>
        </div>

        {loadingUser ? (
          <div className="flex items-center gap-2 text-text-muted text-sm">
            <Loader2 size={14} className="animate-spin" />
            Loading account…
          </div>
        ) : user ? (
          <div className="space-y-4">
            {/* Email */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div>
                <p className="text-xs text-text-muted mb-0.5">Email address</p>
                <p className="text-sm font-mono text-text-primary">{user.email}</p>
              </div>
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-safe/10 border border-safe/20">
                <CheckCircle2 size={11} className="text-safe" />
                <span className="text-[10px] font-mono text-safe">Verified</span>
              </div>
            </div>

            {/* Plan */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div>
                <p className="text-xs text-text-muted mb-0.5">Current plan</p>
                <p className="text-sm font-semibold text-text-primary">Free</p>
              </div>
              <a
                href="/pricing"
                className="px-3 py-1 rounded-lg bg-shield/10 border border-shield/20 text-shield text-xs font-semibold hover:bg-shield/15 transition-colors"
              >
                Upgrade
              </a>
            </div>

            {/* Password reset */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-primary">Password</p>
                <p className="text-xs text-text-muted">Send a reset link to your email</p>
              </div>
              {passwordResetSent ? (
                <div className="flex items-center gap-1.5 text-safe text-xs">
                  <CheckCircle2 size={12} />
                  Reset email sent
                </div>
              ) : (
                <button
                  onClick={handlePasswordReset}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs text-text-secondary hover:text-text-primary hover:border-shield/30 transition-colors"
                >
                  <Key size={12} />
                  Reset password
                </button>
              )}
            </div>

            {/* Sign out */}
            <button
              onClick={handleSignOut}
              disabled={signingOut}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg border border-border text-sm text-text-secondary hover:text-danger hover:border-danger/30 transition-colors disabled:opacity-60"
            >
              {signingOut ? <Loader2 size={14} className="animate-spin" /> : <LogOut size={14} />}
              Sign out
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-text-muted">
              Sign in to manage your account, view scan history, and access Pro features.
            </p>
            <a
              href="/login"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-shield/10 border border-shield/20 text-shield text-sm font-semibold hover:bg-shield/15 transition-colors"
            >
              Sign in
            </a>
            <span className="text-text-muted text-sm mx-2">or</span>
            <a
              href="/signup"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-text-secondary text-sm hover:border-shield/30 transition-colors"
            >
              Create account
            </a>
          </div>
        )}
      </section>

      {/* Notification Preferences */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Bell className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Notifications</h2>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-text-primary">Email threat alerts</p>
            <p className="text-xs text-text-muted">Get notified when new scam patterns are detected</p>
          </div>
          <button
            onClick={() => setNotifications(!notifications)}
            role="switch"
            aria-checked={notifications}
            aria-label="Toggle email threat alerts"
            className={`relative w-12 h-6 rounded-full transition-colors ${
              notifications ? "bg-shield" : "bg-slate-mid"
            }`}
          >
            <div
              className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                notifications ? "translate-x-6" : "translate-x-0.5"
              }`}
            />
          </button>
        </div>
      </section>

      {/* Theme */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Moon className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Theme</h2>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-text-primary">Dark mode</p>
            <p className="text-xs text-text-muted">Light mode coming soon</p>
          </div>
          <button
            role="switch"
            aria-checked={true}
            aria-label="Toggle dark mode"
            className="relative w-12 h-6 rounded-full bg-shield cursor-not-allowed opacity-60"
            disabled
          >
            <div className="absolute top-0.5 w-5 h-5 rounded-full bg-white translate-x-6" />
          </button>
        </div>
      </section>

      {/* Danger Zone */}
      {user && (
        <section className="glass-card p-6 space-y-4 border-danger/20">
          <div className="flex items-center gap-2 mb-2">
            <Trash2 className="w-5 h-5 text-danger" />
            <h2 className="text-lg font-semibold text-danger">Danger Zone</h2>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-text-primary">Delete account</p>
              <p className="text-xs text-text-muted">Permanently delete your account and all data</p>
            </div>
            {deleteConfirm ? (
              <div className="flex items-center gap-2">
                <span className="text-xs text-danger">Are you sure?</span>
                <button
                  onClick={async () => {
                    // TODO: call server action to delete user via admin API
                    alert("Account deletion requires server-side implementation. Contact support.");
                    setDeleteConfirm(false);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-danger/20 border border-danger/30 text-danger text-xs font-semibold"
                >
                  Yes, delete
                </button>
                <button
                  onClick={() => setDeleteConfirm(false)}
                  className="px-3 py-1.5 rounded-lg border border-border text-text-muted text-xs"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setDeleteConfirm(true)}
                className="px-4 py-2 rounded-lg border border-danger/30 text-danger text-sm font-medium hover:bg-danger/10 transition-colors"
              >
                Delete Account
              </button>
            )}
          </div>

          {deleteConfirm && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs">
              <AlertTriangle size={12} className="shrink-0 mt-0.5" />
              This action is permanent. All your scan history and account data will be deleted.
            </div>
          )}
        </section>
      )}
    </div>
  );
}
