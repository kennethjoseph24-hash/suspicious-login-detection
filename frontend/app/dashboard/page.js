"use client";

import { useEffect, useState, useCallback } from "react";
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Legend,
} from "recharts";
import { api, clearToken, saveToken } from "../../lib/api";
import DatasetPanel from "./DatasetPanel";

const RISK_BG = { LOW: "#d8fce8", MEDIUM: "#fef7d0", HIGH: "#fee2e2" };
const RISK_FG = { LOW: "#146130", MEDIUM: "#7c4a0c", HIGH: "#9b1c1c" };
const CHART_STYLE = {
  background: "#ffffff", border: "1px solid #dde1ea",
  borderRadius: 6, fontSize: 12, color: "#181c24",
  boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
};

const STAT_CONFIG = [
  { key: "total_logins",       label: "Total Logins",   variant: "" },
  { key: "successful_logins",  label: "Successful",     variant: "stat-success" },
  { key: "failed_logins",      label: "Failed",         variant: "stat-danger" },
  { key: "suspicious_logins",  label: "Suspicious",     variant: "stat-warn" },
  { key: "blocked_logins",   label: "Blocked",      variant: "stat-danger" },
  { key: "pending_logins", label: "OTP Pending",    variant: "stat-warn" },
  { key: "low_risk_logins",    label: "Low Risk",       variant: "stat-success" },
  { key: "open_alerts",        label: "Open Alerts",    variant: "" },
];

function MiniScore({ score, level }) {
  const pct = Math.min(100, score ?? 0);
  return (
    <div className="mini-score">
      <div className="mini-score-track">
        <div className={`mini-score-fill mini-score-fill-${level}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="mini-score-label" style={{ color: RISK_FG[level] }}>{score}</span>
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats]       = useState(null);
  const [riskDist, setRiskDist] = useState([]);
  const [activity, setActivity] = useState([]);
  const [attempts, setAttempts] = useState([]);
  const [alerts, setAlerts]     = useState([]);
  const [filters, setFilters]   = useState({ risk_level: "", authentication_result: "", username: "", network_context: "" });
  const [loading, setLoading]   = useState(true);
  const [notice, setNotice]     = useState("");
  const [denied, setDenied]     = useState("");
  const [adminUsername, setAdminUsername] = useState("admin");
  const [adminPassword, setAdminPassword] = useState("");
  const [adminOtp, setAdminOtp] = useState("");
  const [pendingLogin, setPendingLogin] = useState(null);
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [activeTab, setActiveTab] = useState("activity");
  const [dataset, setDataset] = useState(null);
  const [datasetLoading, setDatasetLoading] = useState(false);
  const [datasetError, setDatasetError] = useState("");

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
    const [s, rd, act, la, al] = await Promise.all([
      api.dashboardStats(),
      api.riskDistribution(),
      api.activity(14),
      api.loginAttempts({ ...filters, limit: 50 }),
      api.alerts({ limit: 20 }),
    ]);
    setStats(s); setRiskDist(rd); setActivity(act); setAttempts(la); setAlerts(al);
    setDenied("");
    setNotice("");
    return true;
    } catch (error) {
      if (error.status === 401 || error.status === 403) setDenied(error.message);
      else setNotice(error.message || "Unable to load security activity.");
      return error;
    }
    finally { setLoading(false); }
  }, [filters]);

  useEffect(() => { loadAll(); }, [loadAll]);

  async function handleResolve(id) {
    try { await api.resolveAlert(id); await loadAll(); }
    catch (error) { setNotice(error.message); }
  }
  async function handleReset() {
    await api.demoReset();
    setNotice("Demo data reset — run the login scenarios again to repopulate.");
    loadAll();
  }

  async function loadDataset() {
    setDatasetLoading(true); setDatasetError("");
    try {
      setDataset(await api.datasetOverview());
    } catch (error) {
      if (error.status === 401 || error.status === 403) setDenied(error.message);
      else setDatasetError(error.message || "Unable to load the dataset summary.");
    } finally {
      setDatasetLoading(false);
    }
  }

  function openDataset() {
    setActiveTab("dataset");
    if (!dataset) loadDataset();
  }

  async function handleAdminLogin(event) {
    event.preventDefault();
    setAuthBusy(true); setAuthError(""); setPendingLogin(null); setAdminOtp("");
    clearToken();
    try {
      const result = await api.login({ username: adminUsername.trim(), password: adminPassword });
      if (result.otp_required) {
        setPendingLogin(result);
      } else if (result.access_token) {
        saveToken(result.access_token);
        setAdminPassword("");
        const dashboardResult = await loadAll();
        if (dashboardResult !== true) setAuthError(dashboardResult.message);
      } else {
        setAuthError(result.message || "Administrator sign-in failed.");
      }
    } catch (error) {
      setAuthError(error.message || "Administrator sign-in failed.");
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleAdminOtp(event) {
    event.preventDefault();
    setAuthBusy(true); setAuthError("");
    try {
      const result = await api.verifyOtp({ login_attempt_id: pendingLogin.login_attempt_id, otp_code: adminOtp });
      if (!result.success || !result.access_token) {
        setAuthError(result.message || "Verification failed.");
        return;
      }
      saveToken(result.access_token);
      setPendingLogin(null); setAdminPassword(""); setAdminOtp("");
      const dashboardResult = await loadAll();
      if (dashboardResult !== true) setAuthError(dashboardResult.message);
    } catch (error) {
      setAuthError(error.message || "Verification failed.");
    } finally {
      setAuthBusy(false);
    }
  }

  if (denied) {
    return (
      <div className="card signin-card" style={{ maxWidth: 460, margin: "48px auto" }}>
        <div className="eyebrow">SECURITY OPERATIONS</div>
        <h2>Administrator sign in</h2>
        <p className="subtext">Sign in here to open the dashboard.</p>
        {!pendingLogin ? (
          <form onSubmit={handleAdminLogin}>
            <label htmlFor="admin-username">Administrator username</label>
            <input id="admin-username" value={adminUsername} onChange={(event) => setAdminUsername(event.target.value)} autoComplete="username" required disabled={authBusy} />
            <label htmlFor="admin-password">Password</label>
            <input id="admin-password" type="password" value={adminPassword} onChange={(event) => setAdminPassword(event.target.value)} autoComplete="current-password" required disabled={authBusy} />
            <button className="full-button" disabled={authBusy}>{authBusy ? "Signing in..." : "Sign in to dashboard"}</button>
          </form>
        ) : (
          <form onSubmit={handleAdminOtp}>
            <p className="subtext">{pendingLogin.message}</p>
            <label htmlFor="admin-otp">Six-digit verification code</label>
            <input id="admin-otp" value={adminOtp} onChange={(event) => setAdminOtp(event.target.value.replace(/\D/g, ""))} inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required disabled={authBusy} />
            <button className="full-button" disabled={authBusy}>{authBusy ? "Verifying..." : "Verify and open dashboard"}</button>
            <button type="button" className="secondary" onClick={() => { setPendingLogin(null); setAuthError(""); }} disabled={authBusy}>Start over</button>
          </form>
        )}
        {authError && <div className="error-box" role="alert">{authError}</div>}
      </div>
    );
  }

  if (loading && !stats) {
    return <div className="card" style={{ textAlign: "center", color: "var(--muted)", padding: 40 }}>Loading dashboard…</div>;
  }

  return (
    <div>
      <div className="page-header">
        <div><div className="eyebrow">SECURITY OPERATIONS</div><h2>{activeTab === "dataset" ? "Dataset & model" : "Access overview"}</h2><p className="subtext">{activeTab === "dataset" ? "Explore the simulated semester and held-out evaluation." : "Monitor login context, risk decisions, and verification outcomes."}</p></div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="secondary small" onClick={activeTab === "dataset" ? loadDataset : loadAll} style={{ margin: 0 }}>Refresh</button>
          {activeTab === "activity" && <button className="secondary small" onClick={handleReset} style={{ margin: 0 }}>Reset Demo Data</button>}
        </div>
      </div>

      <div className="dashboard-tabs" role="tablist" aria-label="Dashboard sections">
        <button type="button" className="secondary small" role="tab" aria-selected={activeTab === "activity"} onClick={() => setActiveTab("activity")}>Live activity</button>
        <button type="button" className="secondary small" role="tab" aria-selected={activeTab === "dataset"} onClick={openDataset}>Dataset & model</button>
      </div>

      {notice && <div className="notice-bar">{notice}</div>}

      {activeTab === "dataset" ? <DatasetPanel data={dataset} loading={datasetLoading} error={datasetError} onRetry={loadDataset} /> : <>

      {/* Stat Tiles */}
      <div className="grid grid-4" style={{ marginBottom: 20 }}>
        {STAT_CONFIG.map(({ key, label, variant }) => (
          <div key={key} className={`card stat ${variant}`} style={{ marginBottom: 0 }}>
            <div className="value">{stats?.[key] ?? "—"}</div>
            <div className="label">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-2">
        <div className="card">
          <h3>Login Activity — Last 14 Days</h3>
          <ResponsiveContainer width="100%" height={230}>
            <LineChart data={activity} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
              <CartesianGrid stroke="#e8eaf0" strokeDasharray="4 4" />
              <XAxis dataKey="date" stroke="#6b7590" fontSize={10} tickLine={false} />
              <YAxis stroke="#6b7590" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={CHART_STYLE} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="successful" stroke="#146130" strokeWidth={2.5} dot={false} />
              <Line type="monotone" dataKey="failed"     stroke="#9b1c1c" strokeWidth={2.5} dot={false} />
              <Line type="monotone" dataKey="suspicious" stroke="#7c4a0c" strokeWidth={2} strokeDasharray="5 3" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={230}>
            <PieChart>
              <Pie
                data={riskDist} dataKey="count" nameKey="risk_level"
                cx="50%" cy="50%" outerRadius={88} innerRadius={46} paddingAngle={3}
              >
                {riskDist.map((entry) => (
                  <Cell key={entry.risk_level} fill={RISK_BG[entry.risk_level]} stroke={RISK_FG[entry.risk_level]} strokeWidth={1.5} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_STYLE} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h3>Login Outcomes by Day</h3>
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={activity} margin={{ top: 4, right: 8, bottom: 0, left: -12 }} barSize={14}>
            <CartesianGrid stroke="#e8eaf0" strokeDasharray="4 4" vertical={false} />
            <XAxis dataKey="date" stroke="#6b7590" fontSize={10} tickLine={false} />
            <YAxis stroke="#6b7590" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip contentStyle={CHART_STYLE} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="successful" fill="#6ee7a0" radius={[3, 3, 0, 0]} />
            <Bar dataKey="failed"     fill="#fca5a5" radius={[3, 3, 0, 0]} />
            <Bar dataKey="blocked" fill="#df5866" radius={[3, 3, 0, 0]} />
            <Bar dataKey="pending" fill="#e7ae43" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Attempts Table */}
      <div className="card">
        <h3>Recent Login Attempts</h3>
        <div className="filters">
          <div>
            <label>Risk Level</label>
            <select value={filters.risk_level} onChange={(e) => setFilters({ ...filters, risk_level: e.target.value })}>
              <option value="">All levels</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
            </select>
          </div>
          <div>
            <label>Result</label>
            <select value={filters.authentication_result} onChange={(e) => setFilters({ ...filters, authentication_result: e.target.value })}>
              <option value="">All results</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="pending">OTP pending</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
          <div>
            <label>Username</label>
            <input value={filters.username} onChange={(e) => setFilters({ ...filters, username: e.target.value })} placeholder="Filter by username…" />
          </div>
          <div>
            <label>Login Context</label>
            <select value={filters.network_context} onChange={(e) => setFilters({ ...filters, network_context: e.target.value })}>
              <option value="">All environments</option>
              <option>Campus Network</option>
              <option>Laboratory Device</option>
              <option>External Connection</option>
            </select>
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Username</th>
                <th>Location</th>
                <th>Context / Action</th>
                <th>Outcome</th>
                <th>Risk</th>
                <th>Score</th>
                <th>ML Flag</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a) => (
                <tr
                  key={a.id}
                  className="clickable"
                  onClick={() => (window.location.href = `/dashboard/attempts/${a.id}`)}
                >
                  <td style={{ color: "var(--muted)", fontFamily: "monospace", fontSize: 12 }}>
                    {new Date(a.login_timestamp).toLocaleString()}
                  </td>
                  <td style={{ fontWeight: 600, color: "var(--text)" }}><a className="link" href={`/dashboard/attempts/${a.id}`}>{a.username_attempted}</a></td>
                  <td>{a.location || "—"}</td>
                  <td>{a.network_context || "Legacy event"}<div className="subtext">{a.security_action || a.authentication_result}</div></td>
                  <td>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 3,
                      background: a.authentication_result === "success" ? "var(--low-bg)" : "var(--high-bg)",
                      color: a.authentication_result === "success" ? "var(--low)" : "var(--high)",
                      border: `1px solid ${a.authentication_result === "success" ? "var(--low-bd)" : "var(--high-bd)"}`,
                    }}>
                      {a.authentication_result}
                    </span>
                  </td>
                  <td><span className={`badge badge-${a.risk_level}`}>{a.risk_level}</span></td>
                  <td style={{ minWidth: 110 }}>
                    <MiniScore score={a.risk_score} level={a.risk_level} />
                  </td>
                  <td>
                    {a.ml_is_anomaly == null ? (
                      <span style={{ fontSize: 11, color: "var(--muted)" }}>—</span>
                    ) : a.ml_is_anomaly ? (
                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--high)", background: "var(--high-bg)", border: "1px solid var(--high-bd)", padding: "1px 7px", borderRadius: 3 }}>Anomaly</span>
                    ) : (
                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--low)", background: "var(--low-bg)", border: "1px solid var(--low-bd)", padding: "1px 7px", borderRadius: 3 }}>Normal</span>
                    )}
                  </td>
                </tr>
              ))}
              {attempts.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: "center", padding: "32px 0", color: "var(--muted)" }}>
                    No login attempts recorded. Run a scenario from the Login Simulator.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alerts */}
      <div className="card">
        <h3>Security Alerts</h3>
        {alerts.length === 0 ? (
          <p style={{ color: "var(--muted)", fontSize: 13 }}>No alerts generated yet.</p>
        ) : (
          alerts.map((al) => (
            <div key={al.id} className={`alert-item alert-${al.severity}`}>
              <div className="alert-item-bar" />
              <span className={`badge badge-${al.severity}`}>{al.severity}</span>
              <div className="alert-msg">
                <div style={{ fontWeight: 600, color: "var(--text)", marginBottom: 2 }}>{al.alert_type}</div>
                <div style={{ fontSize: 12, color: "var(--text-2)" }}>{al.message}</div>
              </div>
              <div className="alert-meta">{new Date(al.created_at).toLocaleString()}</div>
              {al.status === "OPEN" ? (
                <button className="small secondary" style={{ margin: 0 }} onClick={() => handleResolve(al.id)}>Resolve</button>
              ) : (
                <span style={{ fontSize: 11, color: "var(--muted)", padding: "4px 8px" }}>Resolved</span>
              )}
            </div>
          ))
        )}
      </div>
      </>}
    </div>
  );
}
