"use client";
import { useState } from "react";
import { api, clearToken, saveToken } from "../lib/api";

const SCENARIOS = {
  campus: { label: "Campus Wi-Fi", description: "A shared network, a personal device.", location: "Hyderabad", device: "Windows Laptop", browser: "Chrome", operating_system: "Windows 10", ip_address: "192.0.2.20", simulate_hour: 20, simulate_failed_attempts: 0 },
  lab: { label: "Laboratory", description: "A registered, shared campus computer.", location: "Hyderabad", device: "Lab Workstation", browser: "Edge", operating_system: "Windows 11", ip_address: "192.0.2.30", lab_device_id: "lab-pc-01", simulate_hour: 20, simulate_failed_attempts: 0 },
  external: { label: "External", description: "An off-campus connection.", location: "Hyderabad", device: "Windows Laptop", browser: "Chrome", operating_system: "Windows 10", ip_address: "198.51.100.20", simulate_hour: 20, simulate_failed_attempts: 0 },
};
export default function LoginPage() {
  const [username, setUsername] = useState("kenneth");
  const [password, setPassword] = useState("Passw0rd!23");
  const [scenario, setScenario] = useState("campus");
  const [demo, setDemo] = useState(SCENARIOS.campus);
  const [result, setResult] = useState(null);
  const [otp, setOtp] = useState("");
  const [verified, setVerified] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);  const [accountMode, setAccountMode] = useState("login");  const [account, setAccount] = useState({ username: "", email: "", password: "", confirmPassword: "" });  const [accountNotice, setAccountNotice] = useState("");  function switchAccountMode(mode) {    setAccountMode(mode);    setError(""); setAccountNotice(""); setResult(null); setVerified(null); setOtp("");    setAccount({ username: "", email: "", password: "", confirmPassword: "" });  }  async function createAccount(e) {    e.preventDefault(); setError(""); setAccountNotice("");    if (account.password !== account.confirmPassword) {      setError("Passwords do not match.");      return;    }    setBusy(true);    try {      const created = await api.register({ username: account.username.trim(), email: account.email.trim(), password: account.password });      setUsername(created.username); setPassword("");      setAccount({ username: "", email: "", password: "", confirmPassword: "" });      setAccountMode("login");      setDemo({ ...SCENARIOS.campus }); setScenario("campus");      setAccountNotice("Account created. Enter your password below to sign in.");    } catch (e) { setError(e.message); }    finally { setBusy(false); }  }
  function selectScenario(key) { setScenario(key); setDemo({...SCENARIOS[key]}); setResult(null); setVerified(null); setOtp(""); setError(""); }
  async function login(e) {
    e.preventDefault(); setBusy(true); setError(""); setResult(null); setVerified(null); setOtp("");
    clearToken();
    try { const body = await api.login({username, password, demo_context: demo}); saveToken(body.access_token); setResult(body); }
    catch(e) { setError(e.message); } finally { setBusy(false); }
  }
  async function verify(e) {
    e.preventDefault(); setBusy(true); setError("");
    try { const body = await api.verifyOtp({login_attempt_id: result.login_attempt_id, otp_code: otp}); saveToken(body.access_token); setVerified(body); }
    catch(e) { setError(e.message); } finally { setBusy(false); }
  }
  function field(name, value) { setDemo({...demo, [name]: value}); }
  return <>
    <div className="portal-heading"><div><div className="eyebrow">CONTEXT-AWARE ACCESS SECURITY</div><h1>Every login has a story.</h1><p>Recognize shared campus environments. Challenge unusual activity. Keep access simple.</p></div><span className="prototype-pill">Academic prototype</span></div>
    <div className="login-workspace">
      <section className="card signin-card">
        <div className="shield-mark" aria-hidden="true">&#10003;</div>        <h2>{accountMode === "register" ? "Create your account" : "Welcome to your ERP"}</h2>        <p className="subtext">{accountMode === "register" ? "Choose the credentials you will use to access the portal." : "Sign in with your university account."}</p>        <div className="account-switch" role="group" aria-label="Account access">          <button type="button" className={accountMode === "login" ? "active" : ""} aria-pressed={accountMode === "login"} disabled={busy} onClick={() => switchAccountMode("login")}>Sign in</button>          <button type="button" className={accountMode === "register" ? "active" : ""} aria-pressed={accountMode === "register"} disabled={busy} onClick={() => switchAccountMode("register")}>Create account</button>        </div>
        {accountMode === "register" ? <form onSubmit={createAccount}>          <label htmlFor="new-username">University username</label>          <input id="new-username" value={account.username} onChange={e => setAccount({ ...account, username: e.target.value })} autoComplete="username" minLength={3} maxLength={50} placeholder="Choose a username" disabled={busy} required />          <label htmlFor="new-email">Email address</label>          <input id="new-email" type="email" value={account.email} onChange={e => setAccount({ ...account, email: e.target.value })} autoComplete="email" placeholder="you@college.edu" disabled={busy} required />          <label htmlFor="new-password">Password</label>          <input id="new-password" type="password" value={account.password} onChange={e => setAccount({ ...account, password: e.target.value })} autoComplete="new-password" minLength={6} maxLength={72} aria-describedby="password-help" disabled={busy} required />          <p id="password-help" className="field-hint">Use at least 6 characters. A longer, unique password is better.</p>          <label htmlFor="confirm-password">Confirm password</label>          <input id="confirm-password" type="password" value={account.confirmPassword} onChange={e => setAccount({ ...account, confirmPassword: e.target.value })} autoComplete="new-password" minLength={6} maxLength={72} disabled={busy} required />          <button className="full-button" disabled={busy}>{busy ? "Creating account..." : "Create account"}</button>        </form> : <form onSubmit={login}>
          <label htmlFor="username">University username</label><input id="username" value={username} onChange={e=>setUsername(e.target.value)} autoComplete="username" required />
          <label htmlFor="password">Password</label><input id="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password" required />
          <button className="full-button" disabled={busy}>{busy ? "Evaluating login..." : "Sign in securely"} <span aria-hidden="true">&#8594;</span></button>
        </form>}
        <div aria-live="polite">          {accountNotice && <div className="success-box">{accountNotice}</div>}
          {error && <div className="error-box">{error}</div>}
          {result && <div className={result.security_action === "block" ? "error-box" : result.otp_required ? "warn-box" : "success-box"}>
            <div className="decision-header"><strong>{result.security_action === "block" ? "Access blocked" : result.otp_required ? "Verify your identity" : "Access allowed"}</strong><span className={`badge badge-${result.risk_level}`}>{result.risk_level}</span></div>
            <div className="context-tag">{result.network_context}</div><p>{result.message}</p>
            <div className="risk-bar-label"><span>Risk assessment</span><strong>{result.risk_score}/100</strong></div><div className="risk-bar-track"><div className={`risk-bar-fill risk-bar-fill-${result.risk_level}`} style={{width: `${result.risk_score}%`}} /></div>
            <details className="decision-details"><summary>Why this decision?</summary><ul className="reason-list">{result.detection_reasons.map((r,i)=><li key={i}>{r}</li>)}</ul></details>
          </div>}
          {result?.otp_required && !verified?.success && <form className="otp-form" onSubmit={verify}><label htmlFor="otp">Six-digit verification code</label><input id="otp" value={otp} onChange={e=>setOtp(e.target.value.replace(/\D/g,""))} inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required /><button disabled={busy} className="full-button">Verify and continue</button><p className="subtext">Demo code is shown in the decision above. Expires after five minutes.</p></form>}
          {verified && <div className={verified.success ? "success-box" : "error-box"}>{verified.message}</div>}
        </div>
        <div className="signin-footer">Protected by context rules + Isolation Forest</div>
      </section>
      <section className="card simulation-card"><div className="eyebrow">LOGIN CONTEXT LAB</div><h2>Test the three environments</h2><p className="subtext">Demo inputs simulate context. Real requests use the observed network and registered device credentials.</p>
        <div className="scenario-grid">{Object.entries(SCENARIOS).map(([key,value],i)=><button type="button" key={key} className={`scenario-card ${scenario === key ? "selected" : ""}`} onClick={()=>selectScenario(key)} aria-pressed={scenario === key}><span className="scenario-number">0{i+1}</span><strong>{value.label}</strong><span>{value.description}</span></button>)}</div>
        <div className="context-form">
          <div><label htmlFor="ip">IP address</label><input id="ip" value={demo.ip_address} onChange={e=>field("ip_address",e.target.value)} /></div>
          <div><label htmlFor="location">Location (simulated)</label><select id="location" value={demo.location} onChange={e=>field("location",e.target.value)}>{["Hyderabad","Bangalore","Mumbai","Delhi","New York"].map(l=><option key={l}>{l}</option>)}</select></div>
          <div><label htmlFor="device">Device</label><input id="device" value={demo.device} onChange={e=>field("device",e.target.value)} /></div>
          <div><label htmlFor="browser">Browser</label><input id="browser" value={demo.browser} onChange={e=>field("browser",e.target.value)} /></div>
          <div><label htmlFor="hour">Local login hour (0-23)</label><input id="hour" type="number" min="0" max="23" value={demo.simulate_hour} onChange={e=>field("simulate_hour",Number(e.target.value))} /></div>
          <div><label htmlFor="failures">Recent failed attempts</label><input id="failures" type="number" min="0" max="100" value={demo.simulate_failed_attempts} onChange={e=>field("simulate_failed_attempts",Number(e.target.value))} /></div>
        </div>
        <div className="test-actions"><button type="button" className="secondary small" onClick={()=>{setScenario("campus");setDemo({...SCENARIOS.campus, simulate_failed_attempts: 3});setResult(null);setVerified(null);}}>Test OTP challenge</button><button type="button" className="secondary small" onClick={()=>{setScenario("external");setDemo({...SCENARIOS.external, location: "New York", device: "Unknown Desktop", browser: "Firefox", simulate_hour: 3, simulate_failed_attempts: 8});setResult(null);setVerified(null);}}>Test blocked login</button></div>
        <div className="policy-strip"><div><span className="policy-dot low" />Low risk<strong>Allow access</strong></div><div><span className="policy-dot medium" />Medium risk<strong>Verify with OTP</strong></div><div><span className="policy-dot high" />High risk<strong>OTP; block if guessing</strong></div></div>
      </section>
    </div>
  </>;
}
