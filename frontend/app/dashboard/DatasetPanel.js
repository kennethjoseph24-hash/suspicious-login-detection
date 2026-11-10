"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const number = (value) => Number(value ?? 0).toLocaleString();
const percent = (value, digits = 1) => value == null ? "—" : `${(value * 100).toFixed(digits)}%`;
const scenarioName = (name) => name.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

function Stat({ label, value, detail }) {
  return <div className="card dataset-stat"><div className="value">{value}</div><div className="label">{label}</div>{detail && <div className="dataset-stat-detail">{detail}</div>}</div>;
}

export default function DatasetPanel({ data, loading, error, onRetry }) {
  if (loading) return <div className="card" role="status">Loading dataset and model results...</div>;
  if (error) return <div className="card"><p className="error-box" role="alert">{error}</p><button className="secondary" onClick={onRetry}>Retry</button></div>;
  if (!data) return null;

  const { summary, model, system, sample_rows: sampleRows } = data;
  const split = model.split;
  const policies = Object.entries(system.policies);
  const confusion = model.confusion_matrix;
  const deployed = system.policies["Rules + Isolation Forest"];
  const correctPasswordRanking = system.ranking_correct_password_decisions;
  const contexts = Object.entries(summary.events_by_context).map(([name, count]) => ({ name, count }));
  const scenarios = Object.entries(system.scenarios).map(([key, result]) => ({
    name: scenarioName(key), attempts: result.entry_attempts,
    allowed: result.allowed, access: result.access_rate == null ? 0 : result.access_rate * 100,
  }));
  const splitRows = [
    { name: "Train", count: split.train_events, color: "#2349ca" },
    { name: "Calibration", count: split.calibration_events, color: "#62a5f5" },
    { name: "Held-out test", count: split.test_events, color: "#9ac9ee" },
  ];

  return <div className="dataset-view">
    <div className="card dataset-intro">
      <div className="eyebrow">SIMULATED STUDENT DATA</div>
      <h3>One semester of login behavior</h3>
      <p>{summary.data_source} These counts describe the training dataset. The Access overview shows live application activity from the database.</p>
    </div>

    <div className="grid grid-4 dataset-stats">
      <Stat label="Students" value={number(summary.students)} />
      <Stat label="Login events" value={number(summary.events)} />
      <Stat label="Attack events" value={number(summary.attack_events)} detail={`${number(summary.attack_campaigns)} campaigns`} />
      <Stat label="Semester" value={`${number(summary.semester_days)} days`} />
    </div>

    <div className="grid grid-2">
      <div className="card">
        <h3>Student-level train / test split</h3>
        <p className="subtext">Students appear in only one split. The forest fits on {number(split.normal_events_used_for_fitting)} normal training events.</p>
        <div className="dataset-split-bar" aria-label="60 percent train, 20 percent calibration, 20 percent test">
          {splitRows.map((part) => <span key={part.name} style={{ width: `${part.count / summary.events * 100}%`, background: part.color }} />)}
        </div>
        <div className="dataset-split-legend">{splitRows.map((part) => <div key={part.name}><span style={{ background: part.color }} /> <strong>{part.name}</strong><small>{number(part.count)} events</small></div>)}</div>
      </div>
      <div className="card">
        <h3>Login contexts in the dataset</h3>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={contexts} layout="vertical" margin={{ top: 0, right: 22, bottom: 0, left: 20 }}>
            <CartesianGrid stroke="#e8eaf0" strokeDasharray="4 4" horizontal={false} />
            <XAxis type="number" tickFormatter={(value) => `${(value / 1e6).toFixed(1)}m`} fontSize={11} />
            <YAxis type="category" dataKey="name" width={118} fontSize={11} />
            <Tooltip formatter={(value) => number(value)} />
            <Bar dataKey="count" fill="#2349ca" radius={[0, 4, 4, 0]} barSize={21} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>

    <div className="card">
      <h3>Isolation Forest on held-out test events</h3>
      <p className="subtext">{number(model.rows)} events from {number(system.test_students)} students, including {number(model.attack_rows)} simulated attack events. The calibration threshold targets a 1% false-positive rate.</p>
      <div className="dataset-metrics">
        <div><strong>{percent(model.recall)}</strong><span>Attack recall</span></div>
        <div><strong>{percent(model.precision)}</strong><span>Precision</span></div>
        <div><strong>{percent(model.false_positive_rate, 2)}</strong><span>False-positive rate</span></div>
        <div><strong>{model.roc_auc.toFixed(3)}</strong><span>ROC-AUC</span></div>
        <div><strong>{model.pr_auc.toFixed(3)}</strong><span>PR-AUC</span></div>
      </div>
      <p className="dataset-note">Model: {number(model.chosen_hyperparameters.n_estimators)} trees, {number(model.chosen_hyperparameters.max_samples)} samples per tree. Metrics across all events include password-guessing bursts; correct-password attack decisions are harder.</p>
    </div>

    <div className="grid grid-2">
      <div className="card">
        <h3>Model confusion matrix: all test events</h3>
        <p className="subtext">An anomaly flag is a model signal, not a final login decision.</p>
        <div className="table-wrap"><table className="dataset-matrix"><thead><tr><th>Actual event</th><th>Flagged anomaly</th><th>Not flagged</th></tr></thead><tbody>
          <tr><td><strong>Attack</strong></td><td>{number(confusion.true_positive)}</td><td>{number(confusion.false_negative)}</td></tr>
          <tr><td><strong>Genuine</strong></td><td>{number(confusion.false_positive)}</td><td>{number(confusion.true_negative)}</td></tr>
        </tbody></table></div>
        <p className="dataset-note">For example, {number(confusion.false_positive)} genuine events were flagged. This is why flags need rules and verification before an access decision.</p>
      </div>
      <div className="card">
        <h3>Correct-password attacker entries</h3>
        <p className="subtext">The deployed rules + model policy evaluated {number(deployed.attacker_entry_attempts)} attacker entries where the password was correct.</p>
        <div className="dataset-outcomes">
          <div><strong>{number(Math.round(deployed.attacker_entry_attempts * deployed.attacker_access_rate))}</strong><span>Allowed</span></div>
          <div><strong>{number(Math.round(deployed.attacker_entry_attempts * deployed.attacker_stopped_by_otp))}</strong><span>Challenged with OTP</span></div>
          <div><strong>{number(Math.round(deployed.attacker_entry_attempts * deployed.attacker_blocked))}</strong><span>Blocked</span></div>
        </div>
        <p className="dataset-note">The Isolation Forest PR-AUC on {number(correctPasswordRanking.events)} correct-password decisions is {correctPasswordRanking.models["Isolation Forest (unsupervised)"].pr_auc.toFixed(3)}. The access calculation assumes attackers cannot complete OTP.</p>
      </div>
    </div>

    <div className="card">
      <h3>Login policy comparison</h3>
      <p className="subtext">Attacker access uses {number(system.policies["Rules + Isolation Forest"].attacker_entry_attempts)} correct-password entry attempts. Genuine-login friction uses {number(system.policies["Rules + Isolation Forest"].normal_logins_scored)} normal logins.</p>
      <div className="table-wrap"><table><thead><tr><th>Policy</th><th>Attacker access</th><th>Genuine OTP</th><th>Genuine blocked</th><th>Students blocked at least once</th></tr></thead><tbody>
        {policies.map(([name, result]) => <tr key={name} className={name === "Rules + Isolation Forest" ? "dataset-current-policy" : ""}>
          <td><strong>{name}</strong>{name === "Rules + Isolation Forest" && <span className="dataset-deployed">Deployed</span>}</td>
          <td>{percent(result.attacker_access_rate)}</td><td>{percent(result.normal_otp_rate, 2)}</td><td>{percent(result.normal_block_rate, 2)}</td><td>{percent(result.students_blocked_at_least_once)}</td>
        </tr>)}
      </tbody></table></div>
    </div>

    <div className="card">
      <h3>Attacker access by scenario</h3>
      <p className="subtext">Share of attacker entries allowed under the deployed policy. Lower is better. Attackers who resemble the student are hardest to identify from login context.</p>
      <div className="table-wrap"><table><thead><tr><th>Scenario</th><th>Entry attempts</th><th>Allowed</th><th>Allowed rate</th></tr></thead><tbody>
        {scenarios.map((row) => <tr key={row.name}><td>{row.name}</td><td>{number(row.attempts)}</td><td>{number(row.allowed)}</td><td><div className="dataset-rate"><span>{row.access.toFixed(1)}%</span><div><i style={{ width: `${row.access}%` }} /></div></div></td></tr>)}
      </tbody></table></div>
    </div>

    <div className="card">
      <h3>Sample student login records</h3>
      <p className="subtext">One row from each of {sampleRows.length} simulated students in the included sample CSV. These are examples, not live users in the application database.</p>
      {sampleRows.length ? <div className="table-wrap"><table><thead><tr><th>Student ID</th><th>Time</th><th>Context</th><th>Location</th><th>Device</th><th>Result</th><th>Scenario</th></tr></thead><tbody>
        {sampleRows.map((row) => <tr key={row.student_id}><td><code>{row.student_id}</code></td><td>{row.timestamp.replace("T", " ")}</td><td>{row.network_context}</td><td>{row.location}</td><td>{row.device}</td><td>{row.result}</td><td>{scenarioName(row.scenario)}</td></tr>)}
      </tbody></table></div> : <p className="subtext">The optional sample CSV is not included in this installation.</p>}
    </div>
  </div>;
}
