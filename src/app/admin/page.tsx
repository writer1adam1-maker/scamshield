"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Shield, Users, Trash2, RefreshCw, Settings, Crown, User,
  AlertTriangle, Loader2, CheckCircle, Brain,
} from "lucide-react";

interface AdminUser {
  id: string;
  email: string;
  plan: string;
  scan_count_today: number;
  scan_count_total: number;
  scans_today_actual: number;
  created_at: string;
}

interface ScanConfig {
  anonymous_scan_limit: number;
  free_rolling_limit: number;
  starter_rolling_limit: number;
  pro_rolling_limit: number;
  team_rolling_limit: number;
  organization_rolling_limit: number;
  enterprise_rolling_limit: number;
}

const PLAN_COLORS: Record<string, string> = {
  free:         "bg-border/50 text-text-muted border-border",
  starter:      "bg-shield/10 text-shield border-shield/20",
  pro:          "bg-yellow-400/10 text-yellow-400 border-yellow-400/20",
  team:         "bg-green-400/10 text-green-400 border-green-400/20",
  organization: "bg-purple-400/10 text-purple-400 border-purple-400/20",
  enterprise:   "bg-orange-400/10 text-orange-400 border-orange-400/20",
};

const DEFAULT_CONFIG: ScanConfig = {
  anonymous_scan_limit:        4,
  free_rolling_limit:          50,
  starter_rolling_limit:       200,
  pro_rolling_limit:           500,
  team_rolling_limit:          5000,
  organization_rolling_limit:  20000,
  enterprise_rolling_limit:    100000,
};

export default function AdminDashboard() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [config, setConfig] = useState<ScanConfig>(DEFAULT_CONFIG);
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [savingLimits, setSavingLimits] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limitsSaved, setLimitsSaved] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [usersRes, configRes] = await Promise.all([
        fetch("/api/admin/users"),
        fetch("/api/admin/config"),
      ]);

      if (usersRes.status === 403) {
        setError("Access denied. You must be an admin to view this page.");
        setLoading(false);
        return;
      }

      if (usersRes.ok) {
        const data = await usersRes.json();
        setUsers(data.users || []);
      }

      if (configRes.ok) {
        const raw = await configRes.json();
        const cfg: ScanConfig = { ...DEFAULT_CONFIG, ...raw };
        setConfig(cfg);
        const newInputs: Record<string, string> = {};
        for (const [k, v] of Object.entries(cfg)) newInputs[k] = String(v);
        setInputs(newInputs);
      }
    } catch {
      setError("Failed to load admin data.");
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function saveLimits() {
    const updates: Record<string, number> = {};
    for (const [k, v] of Object.entries(inputs)) {
      const n = parseInt(v, 10);
      if (isNaN(n) || n < 1) {
        setError(`Invalid value for ${k}: must be a positive number.`);
        return;
      }
      updates[k] = n;
    }
    setSavingLimits(true);
    setError(null);
    const res = await fetch("/api/admin/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    setSavingLimits(false);
    if (res.ok) {
      setConfig({ ...config, ...updates } as ScanConfig);
      setLimitsSaved(true);
      setTimeout(() => setLimitsSaved(false), 3000);
    } else {
      const data = await res.json().catch(() => ({}));
      setError(data.error || "Failed to save limits.");
    }
  }

  async function deleteUser(userId: string, email: string) {
    if (!confirm(`Delete user ${email}? This cannot be undone.`)) return;
    setDeletingId(userId);
    const res = await fetch(`/api/admin/users?id=${userId}`, { method: "DELETE" });
    setDeletingId(null);
    if (res.ok) {
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } else {
      setError("Failed to delete user.");
    }
  }

  const totalUsers = users.length;
  const paidUsers = users.filter((u) => u.plan !== "free").length;
  const freeUsers = users.filter((u) => u.plan === "free").length;
  const totalScansToday = users.reduce((sum, u) => sum + (u.scans_today_actual || 0), 0);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-shield" />
      </div>
    );
  }

  if (error && users.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex items-center gap-3 p-4 rounded-lg bg-danger/10 border border-danger/20 text-danger">
          <AlertTriangle size={20} />
          {error}
        </div>
      </div>
    );
  }

  const limitFields: Array<{ key: keyof ScanConfig; label: string }> = [
    { key: "anonymous_scan_limit",        label: "Anonymous (session)" },
    { key: "free_rolling_limit",          label: "Free (30-day)" },
    { key: "starter_rolling_limit",       label: "Starter (30-day)" },
    { key: "pro_rolling_limit",           label: "Pro (30-day)" },
    { key: "team_rolling_limit",          label: "Team (30-day)" },
    { key: "organization_rolling_limit",  label: "Organization (30-day)" },
    { key: "enterprise_rolling_limit",    label: "Enterprise (30-day)" },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-yellow-400/10 border border-yellow-400/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-yellow-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary">Admin Dashboard</h1>
            <p className="text-sm text-text-muted">ScamShieldy management console</p>
          </div>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Quick links */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Link
          href="/admin/patterns"
          className="glass-card p-4 flex items-center gap-3 hover:border-shield/40 transition-colors group"
        >
          <div className="w-10 h-10 rounded-xl bg-shield/10 border border-shield/20 flex items-center justify-center">
            <Brain className="w-5 h-5 text-shield" />
          </div>
          <div>
            <div className="font-semibold text-text-primary group-hover:text-shield transition-colors">Pattern Manager</div>
            <div className="text-xs text-text-muted">Upload fraud data, extract & approve patterns for the VERIDICT engine</div>
          </div>
          <span className="ml-auto text-text-muted text-lg">→</span>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Users",  value: totalUsers,      icon: Users,     color: "text-shield"     },
          { label: "Paid Users",   value: paidUsers,       icon: Crown,     color: "text-yellow-400" },
          { label: "Free Users",   value: freeUsers,       icon: User,      color: "text-text-muted" },
          { label: "Scans Today",  value: totalScansToday, icon: Shield,    color: "text-green-400"  },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="glass-card p-4">
            <div className="flex items-center gap-2 mb-2">
              <Icon size={16} className={color} />
              <span className="text-xs text-text-muted">{label}</span>
            </div>
            <div className="text-2xl font-bold text-text-primary">{value}</div>
          </div>
        ))}
      </div>

      {/* Scan Limit Controls */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Settings size={18} className="text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Scan Limits</h2>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 mb-4">
          {limitFields.map(({ key, label }) => (
            <div key={key}>
              <label className="block text-xs text-text-muted mb-1">{label}</label>
              <input
                type="number"
                min="1"
                max="10000000"
                value={inputs[key] ?? String(config[key])}
                onChange={(e) => setInputs((prev) => ({ ...prev, [key]: e.target.value }))}
                className="w-full px-3 py-2 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20"
              />
            </div>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={saveLimits}
            disabled={savingLimits}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-shield text-void font-semibold text-sm hover:bg-shield/90 transition-colors disabled:opacity-60"
          >
            {savingLimits ? <Loader2 size={14} className="animate-spin" /> : limitsSaved ? <CheckCircle size={14} /> : <Settings size={14} />}
            {limitsSaved ? "Saved!" : "Apply Limits"}
          </button>
          <p className="text-xs text-text-muted">Changes take effect within 60 seconds.</p>
        </div>
      </div>

      {/* Users Table */}
      <div className="glass-card overflow-hidden">
        <div className="flex items-center gap-2 p-4 border-b border-border">
          <Users size={16} className="text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Users ({totalUsers})</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Email</th>
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Plan</th>
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Scans Today</th>
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Total Scans</th>
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Joined</th>
                <th className="px-4 py-3 text-xs font-medium text-text-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-border/50 hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3 text-text-primary font-mono text-xs">{user.email}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${PLAN_COLORS[user.plan] || PLAN_COLORS.free}`}>
                      {user.plan}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-text-primary">{user.scans_today_actual}</td>
                  <td className="px-4 py-3 text-text-primary">{user.scan_count_total}</td>
                  <td className="px-4 py-3 text-text-muted text-xs">
                    {new Date(user.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => deleteUser(user.id, user.email)}
                      disabled={deletingId === user.id}
                      className="flex items-center gap-1 px-2 py-1 rounded text-xs text-danger hover:bg-danger/10 transition-colors disabled:opacity-50"
                    >
                      {deletingId === user.id ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-text-muted">No users found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

