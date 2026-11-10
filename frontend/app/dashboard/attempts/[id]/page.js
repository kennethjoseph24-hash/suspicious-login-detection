"use client";

import { useEffect, useState } from "react";
import { api } from "../../../../lib/api";

function InfoSection({ title, rows }) {
  return (
    <div>
      <div className="section-title" style={{ marginTop: 16 }}>{title}</div>
      {rows.map(([key, val]) => (
        <div key={key} className="detail-pair">
          <span className="detail-key">{key}</span>
          <span className="detail-val">{val ?? "—"}</span>
        </div>
      ))}
    </div>
  );
}

const FEATURE_META = [
  { key: "location_novelty",    label: "Location novelty",    binary: true,  higherIsBad: true },
  { key: "device_novelty",      label: "Device novelty",      binary: true,  higherIsBad: true },
  { key: "browser_novelty",     label: "Browser novelty",     binary: true,  higherIsBad: true },
  { key: "ip_novelty",          label: "IP novelty",          binary: true,  higherIsBad: true },
  { key: "hour_deviation",      label: "Hour deviation",      binary: false, higherIsBad: true },
  { key: "failed_attempts_norm",label: "Failed attempts",     binary: false, higherIsBad: true },
  { key: "login_frequency_norm",label: "Login frequency",     binary: false, higherIsBad: true },
  { key: "geo_distance_norm",   label: "Geo distance",        binary: false, higherIsBad: true },
];

function FeatureBreakdown({ features }) {
  if (!features) return null;
  return (
    <div className="feature-grid">
      {FEATURE_META.map(({ key, label, binary }) => {
        const raw = features[key] ?? 0;
        const pct = Math.round(raw * 100);
        const isHigh = binary ? raw === 1 : raw > 0.5;
        const isMed  = !binary && raw > 0.2 && raw <= 0.5;
        const colorClass = isHigh ? "feature-fill-high" : isMed ? "feature-fill-med" : "feature-fill-low";
        const flagClass  = isHigh ? "feature-flag-novel" : isMed ? "feature-flag-novel" : "feature-flag-ok";
        const flagText   = binary ? (raw === 1 ? "Novel" : "Known") : (isHigh ? "High" : isMed ? "Med" : "Low");

        return (
          <div key={key} className="feature-row">
            <span className="feature-name">{label}</span>
            <div className="feature-track">
              <div className={`feature-fill ${colorClass}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="feature-val">{raw.toFixed(2)}</span>
            <span className={`feature-flag ${flagClass}`}>{flagText}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function AttemptDetailPage({ params }) {
  const { id } = params;
  const [attempt, setAttempt] = useState(null);
  const [error, setError]     = useState("");

  useEffect(() => {
    api.loginAttempt(id).then(setAttempt).catch((e) => setError(e.message));
  }, [id]);

  if (error) return <div className="error-box" style={{ marginTop: 16 }}>{error}</div>;
  if (!attempt) return (
    <div className="card" style={{ textAlign: "center", color: "var(--muted)", padding: 40 }}>
      Loading attempt record…
    </div>
  );

  const hb  = attempt.historical_behavior;
  const pct = Math.min(100, attempt.risk_score);

  // Build feature dict from raw ML scores stored on the attempt (if available via detail API)
  const mlFeatures = attempt.ml_features || null;

  return (
    <div>
      <a className="link" href="/dashboard">← Back to Dashboard</a>

      {/* Summary Card */}
      <div className="card" style={{ marginTop: 16, padding: 0, overflow: "hidden" }}>
        <div className="card-header">
          <div>
            <div className="ch-title">Login Attempt — Record #{attempt.id}</div>
            <div className="ch-sub">Detailed security analysis record</div>
          </div>
        </div>

        <div style={{ padding: "0 24px 24px" }}>
          {/* Risk summary banner */}
          <div style={{
            marginTop: 20, padding: "14px 16px", borderRadius: 6,
            background: attempt.risk_level === "HIGH" ? "var(--high-bg)" : attempt.risk_level === "MEDIUM" ? "var(--med-bg)" : "var(--low-bg)",
            border: `1px solid ${attempt.risk_level === "HIGH" ? "var(--high-bd)" : attempt.risk_level === "MEDIUM" ? "var(--med-bd)" : "var(--low-bd)"}`,
            borderLeft: `4px solid ${attempt.risk_level === "HIGH" ? "var(--high)" : attempt.risk_level === "MEDIUM" ? "var(--med)" : "var(--low)"}`,
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", marginBottom: 4 }}>
                  User: <strong>{attempt.username_attempted}</strong>&ensp;|&ensp;
                  {new Date(attempt.login_timestamp).toLocaleString()}
                </div>
                <div style={{ fontSize: 12, color: "var(--muted)" }}>
                  Authentication: <strong style={{ color: "var(--text-2)" }}>{attempt.authentication_result}</strong>&ensp;·&ensp;
                  Suspicious: <strong style={{ color: "var(--text-2)" }}>{attempt.is_suspicious ? "Yes" : "No"}</strong>
                </div>
              </div>
              <span className={`badge badge-${attempt.risk_level}`} style={{ padding: "5px 14px", fontSize: 12 }}>
                {attempt.risk_level} RISK
              </span>
            </div>

            <div className="risk-bar-wrap" style={{ marginTop: 14 }}>
              <div className="risk-bar-label">
                <span>Risk Score</span>
                <span>{attempt.risk_score} / 100</span>
              </div>
              <div className="risk-bar-track">
                <div className={`risk-bar-fill risk-bar-fill-${attempt.risk_level}`} style={{ width: `${pct}%` }} />
              </div>
            </div>
          </div>

          {/* Details grid */}
          <div className="grid grid-2" style={{ marginTop: 4, gap: 28 }}>
            <InfoSection title="Authentication Details" rows={[
              ["Result",        attempt.authentication_result],
              ["Suspicious",    attempt.is_suspicious ? "Yes" : "No"],
              ["Login Context", attempt.network_context || "Legacy event"],
              ["Security Action", attempt.security_action || "Legacy event"],
              ["OTP Required",  attempt.otp_required  ? "Yes" : "No"],
              ["OTP Verified",  attempt.otp_verified  ? "Yes" : "No"],
            ]} />
            <InfoSection title="Connection Details" rows={[
              ["IP Address", attempt.ip_address],
              ["Location",   `${attempt.location || "—"}${attempt.is_simulated_location ? " (demo)" : ""}`],
              ["Device",     attempt.device],
              ["Browser",    attempt.browser],
              ["OS",         attempt.operating_system],
            ]} />
          </div>

          {/* ML Analysis */}
          {attempt.ml_anomaly_score != null && (
            <div style={{ marginTop: 4 }}>
              <InfoSection title="ML Anomaly Analysis" rows={[
                ["Anomaly Score", `${attempt.ml_anomaly_score.toFixed(1)} / 100`],
                ["ML Verdict",    attempt.ml_is_anomaly ? "Flagged as anomalous" : "Within normal range"],
              ]} />
            </div>
          )}

          {/* Detection reasons */}
          <div style={{ marginTop: 4 }}>
            <div className="section-title" style={{ marginTop: 16 }}>Risk Detection Factors</div>
            {attempt.detection_reasons?.length > 0 ? (
              <ul className="reason-list">
                {attempt.detection_reasons.map((r, i) => <li key={i} style={{ color: "var(--text-2)" }}>{r}</li>)}
              </ul>
            ) : (
              <p style={{ color: "var(--muted)", fontSize: 13 }}>No risk factors detected — login appears normal.</p>
            )}
          </div>
        </div>
      </div>

      {/* ML Feature Breakdown — only shown when the ML model ran */}
      {attempt.ml_anomaly_score != null && (
        <div className="card">
          <h3>ML Feature Breakdown</h3>
          <p style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14, marginTop: -8 }}>
            The 8 numeric features fed to the Isolation Forest model, compared against this user&apos;s behaviour baseline.
            Values near 1 are more anomalous; values near 0 are within normal range.
          </p>
          <FeatureBreakdown features={attempt.ml_features} />
          {!attempt.ml_features && (
            <p style={{ color: "var(--muted)", fontSize: 13 }}>
              Feature values are not stored on this attempt record (older format).
            </p>
          )}

          {/* ML score bar */}
          <div style={{ marginTop: 20 }}>
            <div className="section-title">Overall ML Anomaly Score</div>
            <div className="risk-bar-wrap" style={{ marginTop: 8 }}>
              <div className="risk-bar-label">
                <span>Anomaly Score</span>
                <span>{attempt.ml_anomaly_score.toFixed(1)} / 100</span>
              </div>
              <div className="risk-bar-track">
                <div
                  className={`risk-bar-fill risk-bar-fill-${attempt.ml_is_anomaly ? "HIGH" : "LOW"}`}
                  style={{ width: `${Math.min(100, attempt.ml_anomaly_score)}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Historical Behaviour */}
      {hb && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header">
            <div>
              <div className="ch-title">Historical Behaviour Baseline</div>
              <div className="ch-sub">User&apos;s recorded patterns at the time of this login attempt</div>
            </div>
          </div>
          <div style={{ padding: "0 24px 24px" }}>
            <div className="grid grid-2" style={{ marginTop: 4, gap: 28 }}>
              <InfoSection title="Known Environments" rows={[
                ["Locations",         hb.known_locations.join(", ") || "None on record"],
                ["Devices",           hb.known_devices.join(", ")   || "None on record"],
                ["Browsers",          hb.known_browsers.join(", ")  || "None on record"],
                ["Operating Systems", hb.known_os.join(", ")        || "None on record"],
              ]} />
              <InfoSection title="Usage Statistics" rows={[
                ["Usual Hours",          `${hb.usual_login_hour_start}:00 – ${hb.usual_login_hour_end}:00`],
                ["Avg Failed Attempts",  hb.average_failed_attempts.toFixed(2)],
                ["Total Logins",         hb.total_logins],
                ["Successful Logins",    hb.successful_logins],
              ]} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
