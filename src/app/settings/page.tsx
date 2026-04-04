"use client";

import { useState, useEffect } from "react";
import {
  Settings, Bell, Palette, User, Trash2, LogOut, Loader2, CheckCircle2,
  AlertTriangle, Key, Gift, Copy, ShieldAlert, Puzzle, Plus, X as XIcon,
} from "lucide-react";
import { createBrowserClient } from "@/lib/supabase/client";
import { useRouter } from "next/navigation";
import Link from "next/link";
import type { User as SupabaseUser } from "@supabase/supabase-js";

const THEMES = [
  { id: "dark",       label: "Dark",       desc: "Cybersecurity black",      preview: ["#0a0a0f", "#00d4ff", "#00e5a0"] },
  { id: "midnight",   label: "Midnight",   desc: "Deep ocean blue",          preview: ["#030b1a", "#4fa3ff", "#00e5a0"] },
  { id: "forest",     label: "Forest",     desc: "Dark green terminal",      preview: ["#020d06", "#00ff88", "#fbbf24"] },
  { id: "light",      label: "Light",      desc: "Clean and bright",         preview: ["#f4f6fa", "#0078cc", "#00a86b"] },
] as const;

type ThemeId = typeof THEMES[number]["id"];

const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  starter: "Starter",
  pro: "Pro",
  team: "Team",
  organization: "Organization",
  enterprise: "Enterprise",
};

const ADMIN_EMAILS = (process.env.NEXT_PUBLIC_ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());

export default function SettingsPage() {
  const [notifications, setNotifications] = useState(true);
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [userPlan, setUserPlan] = useState<string>("free");
  const [scanCountTotal, setScanCountTotal] = useState(0);
  const [referralCode, setReferralCode] = useState<string | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);
  const [signingOut, setSigningOut] = useState(false);
  const [passwordResetSent, setPasswordResetSent] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [deletingAccount, setDeletingAccount] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const [theme, setTheme] = useState<ThemeId>("dark");
  // API keys state
  const [apiKeys, setApiKeys] = useState<{ key_prefix: string; plan: string; label: string; created_at: string; requests_total: number }[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [newKeyLabel, setNewKeyLabel] = useState("");
  const [creatingKey, setCreatingKey] = useState(false);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const router = useRouter();

  const isAdmin = user ? ADMIN_EMAILS.includes((user.email || "").toLowerCase()) : false;

  useEffect(() => {
    // Load saved theme
    try {
      const saved = (localStorage.getItem("theme") || "dark") as ThemeId;
      setTheme(saved);
    } catch { /* ignore */ }

    const supabase = createBrowserClient();
    async function load() {
      const { data: { user: authUser } } = await supabase.auth.getUser();
      setUser(authUser);

      if (authUser) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { data } = await (supabase as any)
          .from("users")
          .select("plan, scan_count_total, referral_code")
          .eq("id", authUser.id)
          .single();
        const dbUser = data as { plan?: string; scan_count_total?: number; referral_code?: string } | null;
        if (dbUser) {
          setUserPlan(dbUser.plan ?? "free");
          setScanCountTotal(dbUser.scan_count_total ?? 0);
          setReferralCode(dbUser.referral_code || null);
        }
      }
      setLoadingUser(false);
    }
    load();
    loadApiKeys();
  }, []);

  async function loadApiKeys() {
    setApiKeysLoading(true);
    try {
      const res = await fetch("/api/extension/keys");
      if (res.ok) {
        const data = await res.json();
        setApiKeys(data.keys ?? []);
      }
    } catch { /* ignore */ }
    setApiKeysLoading(false);
  }

  async function handleCreateKey() {
    setCreatingKey(true);
    setRevealedKey(null);
    try {
      const res = await fetch("/api/extension/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: newKeyLabel || "Browser Extension" }),
      });
      const data = await res.json();
      if (!res.ok) { alert(data.error || "Failed to create key"); return; }
      setRevealedKey(data.key);
      setNewKeyLabel("");
      await loadApiKeys();
    } catch { alert("Failed to create API key."); }
    setCreatingKey(false);
  }

  async function handleRevokeKey(prefix: string) {
    if (!confirm("Revoke this API key? Any device using it will lose access.")) return;
    try {
      await fetch("/api/extension/keys", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prefix }),
      });
      await loadApiKeys();
      if (revealedKey?.startsWith(prefix)) setRevealedKey(null);
    } catch { alert("Failed to revoke key."); }
  }

  function applyTheme(t: ThemeId) {
    setTheme(t);
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("theme", t); } catch { /* ignore */ }
  }

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

  function copyReferralCode() {
    if (!referralCode) return;
    navigator.clipboard.writeText(referralCode).then(() => {
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    });
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

      {/* Admin shortcut — only visible to admins */}
      {isAdmin && (
        <Link
          href="/admin"
          className="flex items-center gap-3 p-4 rounded-xl bg-yellow-400/5 border border-yellow-400/20 hover:bg-yellow-400/10 transition-colors"
        >
          <ShieldAlert className="w-5 h-5 text-yellow-400" />
          <div>
            <p className="text-sm font-semibold text-yellow-400">Admin Dashboard</p>
            <p className="text-xs text-text-muted">Manage users, scan limits, and platform config</p>
          </div>
        </Link>
      )}

      {/* Account */}
      <section className="glass-card p-6 space-y-4" data-tour="settings-account">
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
                <p className="text-sm font-semibold text-text-primary">
                  {isAdmin ? "Ultimate (Admin)" : (PLAN_LABELS[userPlan] ?? userPlan)}
                </p>
                <p className="text-[10px] text-text-muted mt-0.5">{scanCountTotal} total scans</p>
              </div>
              {userPlan === "free" && !isAdmin ? (
                <Link
                  href="/pricing"
                  className="px-3 py-1 rounded-lg bg-shield/10 border border-shield/20 text-shield text-xs font-semibold hover:bg-shield/15 transition-colors"
                >
                  Upgrade
                </Link>
              ) : (
                <span className="px-3 py-1 rounded-lg bg-safe/10 border border-safe/20 text-safe text-xs font-semibold">
                  Active
                </span>
              )}
            </div>

            {/* Referral code */}
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Gift size={14} className="text-shield" />
                  <p className="text-xs font-medium text-text-primary">Your referral code</p>
                </div>
                <span className="text-[10px] text-text-muted">+10 scans per referral</span>
              </div>
              {referralCode ? (
                <div className="flex items-center gap-2">
                  <span className="flex-1 px-3 py-2 rounded-lg bg-void/60 border border-border font-mono text-sm text-shield tracking-widest">
                    {referralCode}
                  </span>
                  <button
                    onClick={copyReferralCode}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-border text-xs text-text-secondary hover:text-shield hover:border-shield/30 transition-colors"
                  >
                    {copiedCode ? <CheckCircle2 size={12} className="text-safe" /> : <Copy size={12} />}
                    {copiedCode ? "Copied!" : "Copy"}
                  </button>
                </div>
              ) : (
                <p className="text-xs text-text-muted">Loading code…</p>
              )}
              <p className="text-[10px] text-text-muted mt-2">
                Share this code with friends. When they sign up you both get +10 bonus scans.
              </p>
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
            <Link
              href="/login"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-shield/10 border border-shield/20 text-shield text-sm font-semibold hover:bg-shield/15 transition-colors"
            >
              Sign in
            </Link>
            <span className="text-text-muted text-sm mx-2">or</span>
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-text-secondary text-sm hover:border-shield/30 transition-colors"
            >
              Create account
            </Link>
          </div>
        )}
      </section>

      {/* API Keys — for browser extension & integrations */}
      {user && (
        <section className="glass-card p-6 space-y-4" data-tour="settings-api-keys">
          <div className="flex items-center gap-2 mb-2">
            <Puzzle className="w-5 h-5 text-shield" />
            <h2 className="text-lg font-semibold text-text-primary">API Keys</h2>
            <span className="ml-auto text-xs text-text-muted">for Browser Extension &amp; integrations</span>
          </div>

          {/* Revealed key banner */}
          {revealedKey && (
            <div className="p-3 rounded-xl bg-safe/5 border border-safe/20 space-y-2">
              <div className="flex items-center gap-2">
                <CheckCircle2 size={13} className="text-safe shrink-0" />
                <span className="text-xs font-semibold text-safe">New API key created — copy it now, it won&apos;t be shown again</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="flex-1 px-3 py-2 rounded-lg bg-void/60 border border-border font-mono text-xs text-shield tracking-wider overflow-x-auto whitespace-nowrap">
                  {revealedKey}
                </span>
                <button
                  onClick={() => { navigator.clipboard.writeText(revealedKey); setCopiedKey(true); setTimeout(() => setCopiedKey(false), 2000); }}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-border text-xs text-text-secondary hover:text-shield hover:border-shield/30 transition-colors shrink-0"
                >
                  {copiedKey ? <CheckCircle2 size={12} className="text-safe" /> : <Copy size={12} />}
                  {copiedKey ? "Copied!" : "Copy"}
                </button>
              </div>
            </div>
          )}

          {/* Create new key */}
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newKeyLabel}
              onChange={(e) => setNewKeyLabel(e.target.value)}
              placeholder="Label (e.g. My Chrome Extension)"
              maxLength={60}
              className="flex-1 px-3 py-2 rounded-lg bg-abyss/60 border border-border text-sm text-text-primary placeholder:text-text-muted/50 outline-none focus:border-shield/40 transition-colors"
            />
            <button
              onClick={handleCreateKey}
              disabled={creatingKey}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-shield/10 border border-shield/20 text-shield text-xs font-semibold hover:bg-shield/15 transition-colors disabled:opacity-50"
            >
              {creatingKey ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
              Create Key
            </button>
          </div>

          {/* Keys list */}
          {apiKeysLoading ? (
            <div className="flex items-center gap-2 text-text-muted text-sm">
              <Loader2 size={13} className="animate-spin" /> Loading keys…
            </div>
          ) : apiKeys.length === 0 ? (
            <p className="text-xs text-text-muted">No API keys yet. Create one to use with the browser extension.</p>
          ) : (
            <div className="space-y-2">
              {apiKeys.map((k) => (
                <div key={k.key_prefix} className="flex items-center gap-3 p-3 rounded-lg bg-abyss/60 border border-border/40">
                  <Key size={13} className="text-shield shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-shield">{k.key_prefix}…</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-shield/10 text-shield border border-shield/20">{k.plan}</span>
                    </div>
                    <div className="text-[10px] text-text-muted mt-0.5">
                      {k.label} · {k.requests_total} requests · Created {new Date(k.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRevokeKey(k.key_prefix)}
                    className="p-1.5 text-text-muted hover:text-danger transition-colors rounded-lg hover:bg-danger/10"
                    title="Revoke key"
                  >
                    <XIcon size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}

          <p className="text-[10px] text-text-muted">
            Paste your API key into the ScamShield browser extension settings to enable authenticated scanning.
            Free keys: 100 req/day. Pro keys: 10,000 req/day.
          </p>
        </section>
      )}

      {/* Theme picker */}
      <section className="glass-card p-6 space-y-4" data-tour="settings-theme">
        <div className="flex items-center gap-2 mb-2">
          <Palette className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Theme</h2>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {THEMES.map((t) => (
            <button
              key={t.id}
              onClick={() => applyTheme(t.id)}
              className={`p-3 rounded-xl border text-left transition-all ${
                theme === t.id
                  ? "border-shield bg-shield/10 shadow-[0_0_12px_rgba(0,212,255,0.15)]"
                  : "border-border hover:border-shield/30 bg-abyss/40"
              }`}
            >
              {/* Color preview dots */}
              <div className="flex gap-1 mb-2">
                {t.preview.map((c, i) => (
                  <div key={i} className="w-4 h-4 rounded-full border border-white/10" style={{ backgroundColor: c }} />
                ))}
              </div>
              <p className="text-xs font-medium text-text-primary">{t.label}</p>
              <p className="text-[10px] text-text-muted mt-0.5">{t.desc}</p>
              {theme === t.id && (
                <div className="flex items-center gap-1 mt-1.5">
                  <CheckCircle2 size={10} className="text-shield" />
                  <span className="text-[10px] text-shield">Active</span>
                </div>
              )}
            </button>
          ))}
        </div>
      </section>

      {/* Notifications */}
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

      {/* Danger Zone */}
      {user && (
        <section className="glass-card p-6 space-y-4 border-danger/20" data-tour="settings-danger">
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
                    setDeletingAccount(true);
                    try {
                      const supabase = createBrowserClient();
                      // eslint-disable-next-line @typescript-eslint/no-explicit-any
                      await (supabase as any).from("users").delete().eq("id", user!.id);
                      await supabase.auth.signOut();
                      router.push("/");
                      router.refresh();
                    } catch {
                      alert("Failed to delete account. Please try again or contact support.");
                      setDeletingAccount(false);
                      setDeleteConfirm(false);
                    }
                  }}
                  disabled={deletingAccount}
                  className="px-3 py-1.5 rounded-lg bg-danger/20 border border-danger/30 text-danger text-xs font-semibold disabled:opacity-60"
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
