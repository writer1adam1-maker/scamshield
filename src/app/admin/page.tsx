"use client";

import { useEffect, useState, useCallback } from "react";
import { Shield, Users, Trash2, RefreshCw, Settings, Crown, User, AlertTriangle, Loader2, CheckCircle } from "lucide-react";

interface AdminUser {
  id: string;
  email: string;
  plan: "free" | "pro";
  scan_count_today: number;
  scan_count_total: number;
  scans_today_actual: number;
  created_at: string;
}

interface ScanLimits {
  anonymous_scan_limit: number;
  registered_scan_limit: number;
}

export default function AdminDashboard() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [limits, setLimits] = useState<ScanLimits>({ anonymous_scan_limit: 4, registered_scan_limit: 10 });
  const [anonInput, setAnonInput] = useState("4");
  const [registeredInput, setRegisteredInput] = useState("10");
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
        const cfg = await configRes.json();
        setLimits(cfg);
        setAnonInput(String(cfg.anonymous_scan_limit));
        setRegisteredInput(String(cfg.registered_scan_limit));
      }
    } catch {
      setError("Failed to load admin data.");
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function saveLimits() {
    const anon = parseInt(anonInput, 10);
    const reg = parseInt(registeredInput, 10);
    if (isNaN(anon) || isNaN(reg) || anon < 1 || reg < 1) {
      setError("Limits must be positive numbers.");
      return;
    }
    setSavingLimits(true);
    setError(null);
    const res = await fetch("/api/admin/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ anonymous_scan_limit: anon, registered_scan_limit: reg }),
    });
    setSavingLimits(false);
    if (res.ok) {
      setLimits({ anonymous_scan_limit: anon, registered_scan_limit: reg });
      setLimitsSaved(true);
      setTimeout(() => setLimitsSaved(false), 3000);
    } else {
      setError("Failed to save limits.");
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
  const proUsers = users.filter((u) => u.plan === "pro").length;
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

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-shield/10 border border-shield/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-shield" />
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

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Users", value: totalUsers, icon: Users, color: "text-shield" },
          { label: "Pro Users", value: proUsers, icon: Crown, color: "text-yellow-400" },
          { label: "Free Users", value: freeUsers, icon: User, color: "text-text-muted" },
          { label: "Scans Today", value: totalScansToday, icon: Shield, color: "text-green-400" },
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
          <span className="text-xs text-text-muted ml-1">(current: anon={limits.anonymous_scan_limit}, registered={limits.registered_scan_limit})</span>
        </div>
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-xs text-text-muted mb-1">Anonymous users (per day)</label>
            <input
              type="number"
              min="1"
              max="1000"
              value={anonInput}
              onChange={(e) => setAnonInput(e.target.value)}
              className="w-28 px-3 py-2 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20"
            />
          </div>
          <div>
            <label className="block text-xs text-text-muted mb-1">Registered free users (per day)</label>
            <input
              type="number"
              min="1"
              max="10000"
              value={registeredInput}
              onChange={(e) => setRegisteredInput(e.target.value)}
              className="w-28 px-3 py-2 bg-abyss/80 border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-shield/50 focus:ring-1 focus:ring-shield/20"
            />
          </div>
          <button
            onClick={saveLimits}
            disabled={savingLimits}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-shield text-void font-semibold text-sm hover:bg-shield/90 transition-colors disabled:opacity-60"
          >
            {savingLimits ? <Loader2 size={14} className="animate-spin" /> : limitsSaved ? <CheckCircle size={14} /> : <Settings size={14} />}
            {limitsSaved ? "Saved!" : "Apply Limits"}
          </button>
        </div>
        <p className="text-xs text-text-muted mt-3">
          Pro users always have unlimited scans. Changes take effect within 60 seconds.
        </p>
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
                <tr key={user.id} className="border-b border-border/50 hover:bg-white/2 transition-colors">
                  <td className="px-4 py-3 text-text-primary font-mono text-xs">{user.email}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                      user.plan === "pro"
                        ? "bg-yellow-400/10 text-yellow-400 border border-yellow-400/20"
                        : "bg-border/50 text-text-muted border border-border"
                    }`}>
                      {user.plan === "pro" && <Crown size={10} />}
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
