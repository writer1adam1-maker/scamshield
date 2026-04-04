"use client";

import { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  ScanLine,
  LayoutDashboard,
  History,
  Database,
  Settings,
  Menu,
  X,
  Zap,
  User,
  LogIn,
  LogOut,
  MessageSquare,
  Syringe,
  ShieldAlert,
  Puzzle,
  Mail,
} from "lucide-react";
import clsx from "clsx";
import { createBrowserClient } from "@/lib/supabase/client";
import type { User as SupabaseUser } from "@supabase/supabase-js";

const navItems = [
  { href: "/", label: "Scan", icon: ScanLine },
  { href: "/vaccine", label: "Vaccine", icon: Syringe },
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/history", label: "History", icon: History },
  { href: "/conversation", label: "Conv. Arc", icon: MessageSquare },
  { href: "/patterns", label: "Patterns", icon: Database },
  { href: "/dashboard/gmail", label: "Gmail Shield", icon: Mail },
  { href: "/extension", label: "Extension", icon: Puzzle },
  { href: "/settings", label: "Settings", icon: Settings },
];

const PLAN_LABELS: Record<string, string> = {
  free:         "Free plan",
  starter:      "Starter plan",
  pro:          "Pro plan",
  team:         "Team plan",
  organization: "Organization",
  enterprise:   "Enterprise",
};

const ADMIN_EMAILS = (process.env.NEXT_PUBLIC_ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());

export function Sidebar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [scanCountPeriod, setScanCountPeriod] = useState(0);
  const [userPlan, setUserPlan] = useState<string>("free");
  const [isAdmin, setIsAdmin] = useState(false);
  const [rollingLimit, setRollingLimit] = useState(50); // free default
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    const supabase = createBrowserClient();

    async function loadUser() {
      const { data: { user: authUser } } = await supabase.auth.getUser();
      setUser(authUser);

      if (authUser) {
        const adminCheck = ADMIN_EMAILS.includes((authUser.email || "").toLowerCase());
        setIsAdmin(adminCheck);

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { data } = await (supabase as any)
          .from("users")
          .select("scan_count_month, plan, last_month_reset")
          .eq("id", authUser.id)
          .single();

        const dbUser = data as {
          scan_count_month?: number;
          plan?: string;
          last_month_reset?: string;
        } | null;

        if (dbUser) {
          const plan = dbUser.plan || "free";
          setUserPlan(plan);

          // Check if we're in a new 30-day period
          const now = Date.now();
          const periodStart = dbUser.last_month_reset ? new Date(dbUser.last_month_reset).getTime() : 0;
          const isNewPeriod = now - periodStart >= 30 * 24 * 60 * 60 * 1000;
          setScanCountPeriod(isNewPeriod ? 0 : (dbUser.scan_count_month ?? 0));

          // Load rolling limit from config
          try {
            const cfgRes = await fetch("/api/scan/limits");
            if (cfgRes.ok) {
              const cfg = await cfgRes.json();
              const key = `${plan}_rolling_limit`;
              if (cfg[key]) setRollingLimit(cfg[key]);
            }
          } catch { /* use default */ }
        }
      }
    }

    loadUser();

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
      if (session?.user) loadUser();
    });
    return () => subscription.unsubscribe();
  }, []);

  async function handleSignOut() {
    const supabase = createBrowserClient();
    await supabase.auth.signOut();
    router.push("/");
    router.refresh();
  }

  return (
    <>
      {/* Mobile toggle button */}
      <button
        onClick={() => setMobileOpen(true)}
        aria-label="Open navigation menu"
        className="fixed top-4 left-4 z-50 md:hidden p-2 rounded-lg glass-card text-text-secondary hover:text-shield transition-colors"
      >
        <Menu size={20} />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-void/60 backdrop-blur-sm z-40 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          "fixed top-0 left-0 h-full w-64 z-50 flex flex-col",
          "bg-abyss/95 backdrop-blur-xl border-r border-border",
          "transition-transform duration-300 ease-in-out",
          "md:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {/* Logo */}
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative">
              <Shield
                size={28}
                className="text-shield group-hover:drop-shadow-[0_0_8px_var(--color-shield)] transition-all"
              />
              <div className="absolute inset-0 bg-shield/20 rounded-full blur-lg opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-text-primary">
                Scam<span className="text-shield">Shieldy</span>
              </span>
              <div className="text-[9px] font-mono text-text-muted tracking-[0.3em] uppercase -mt-0.5">
                Threat Intel
              </div>
            </div>
          </Link>

          {/* Mobile close button */}
          <button
            onClick={() => setMobileOpen(false)}
            className="md:hidden p-1 text-text-muted hover:text-text-secondary"
          >
            <X size={18} />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={clsx(
                  "flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200",
                  isActive
                    ? "bg-shield/10 text-shield border border-shield/15 shadow-[0_0_20px_rgba(0,212,255,0.06)]"
                    : "text-text-muted hover:text-text-secondary hover:bg-slate-deep/40"
                )}
              >
                <Icon size={18} className={isActive ? "text-shield" : ""} />
                {item.label}
                {isActive && (
                  <div className="ml-auto w-1.5 h-1.5 rounded-full bg-shield" />
                )}
              </Link>
            );
          })}

          {/* Admin-only nav item */}
          {isAdmin && (
            <Link
              href="/admin"
              onClick={() => setMobileOpen(false)}
              className={clsx(
                "flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 mt-2",
                pathname.startsWith("/admin")
                  ? "bg-yellow-400/10 text-yellow-400 border border-yellow-400/20"
                  : "text-yellow-500/70 hover:text-yellow-400 hover:bg-yellow-400/5 border border-yellow-400/10"
              )}
            >
              <ShieldAlert size={18} />
              Admin Panel
              {pathname.startsWith("/admin") && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-yellow-400" />
              )}
            </Link>
          )}
        </nav>

        {/* Bottom section */}
        <div className="p-4 space-y-3 border-t border-border/50">
          {/* Usage counter — only for free/starter plans (not admin, not high-tier) */}
          {user && !isAdmin && (userPlan === "free" || userPlan === "starter") && (
            <div className="p-3 rounded-xl bg-slate-deep/40 border border-border/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-text-muted">Scans this period</span>
                <span className={`text-xs font-mono ${scanCountPeriod >= rollingLimit ? "text-danger" : "text-shield"}`}>
                  {scanCountPeriod}/{rollingLimit}
                </span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-obsidian overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${scanCountPeriod >= rollingLimit ? "bg-danger" : "bg-shield"}`}
                  style={{ width: `${Math.min(100, (scanCountPeriod / rollingLimit) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {/* Plan badge or upgrade button */}
          {isAdmin ? (
            <div className="p-3 rounded-xl bg-yellow-400/5 border border-yellow-400/20 text-center">
              <span className="text-xs font-mono text-yellow-400">Ultimate Plan — Admin Access</span>
            </div>
          ) : userPlan === "free" ? (
            <Link
              href="/pricing"
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-shield/10 border border-shield/20 text-shield text-sm font-semibold hover:bg-shield/15 transition-all shield-glow"
            >
              <Zap size={14} />
              Upgrade Plan
            </Link>
          ) : (
            <div className="p-3 rounded-xl bg-safe/5 border border-safe/20 text-center">
              <span className="text-xs font-mono text-safe">{PLAN_LABELS[userPlan] ?? userPlan}</span>
            </div>
          )}

          {/* User section */}
          {user ? (
            <div className="flex items-center gap-3 px-2 py-1">
              <div className="w-8 h-8 rounded-full bg-shield/10 flex items-center justify-center border border-shield/20 shrink-0">
                <User size={14} className="text-shield" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs text-text-secondary truncate">{user.email}</div>
                <div className="text-[10px] font-mono text-text-muted">
                  {isAdmin ? "Ultimate" : (PLAN_LABELS[userPlan] ?? userPlan)}
                </div>
              </div>
              <button
                onClick={handleSignOut}
                title="Sign out"
                className="p-1.5 text-text-muted hover:text-danger transition-colors rounded-lg hover:bg-danger/10"
              >
                <LogOut size={13} />
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="flex items-center gap-2 px-3 py-2 rounded-xl border border-border text-sm text-text-muted hover:text-text-secondary hover:border-shield/30 transition-colors"
            >
              <LogIn size={14} />
              Sign in
            </Link>
          )}
        </div>
      </aside>
    </>
  );
}
