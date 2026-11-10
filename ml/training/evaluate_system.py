"""End-to-end evaluation on the held-out students, with report figures.

Asks the questions a deployment cares about, rather than only "what is the AUC?":
  * How often does an attacker holding the right password get in?
  * How much friction do real students face (OTP prompts, wrongful blocks)?
  * Does the Isolation Forest add anything over the rules alone?

Assumptions that matter, and are stated in the report:
  * All data is simulated, and attack scenarios are hand-designed.
  * Attackers cannot complete an OTP, so "access" means the system said ALLOW.
  * Behaviour baselines were built during a rules-only replay. ML-assisted decisions
    are evaluated per attempt and are not fed back into those baselines.

    python ml/training/evaluate_system.py
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

import joblib
import matplotlib
import matplotlib.dates
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score  # noqa: E402

ML_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ML_ROOT.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.config import settings  # noqa: E402
from app.services.risk_engine import compute_risk, decide_action  # noqa: E402
from generate_student_dataset import OTP_PASS_RATE_LEGIT  # noqa: E402
from train_model import FEATURE_COLUMNS, load_events, split_students  # noqa: E402

BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7"
plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 10, "axes.edgecolor": AXIS,
    "axes.labelcolor": MUTED, "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": .6, "axes.axisbelow": True, "figure.dpi": 200, "savefig.bbox": "tight",
    "axes.titlesize": 11, "axes.titleweight": "bold", "axes.titlelocation": "left", "legend.frameon": False,
})
SCENARIO_LABELS = {
    "foreign_takeover": "Foreign takeover", "credential_stuffing": "Credential stuffing",
    "brute_force": "Brute force", "impossible_travel": "Impossible travel",
    "domestic_phishing": "Domestic phishing", "insider_peer": "Insider peer",
    "stolen_device": "Stolen device", "lab_shoulder_surf": "Lab shoulder-surf",
}


def wilson(successes, total, z=1.96):
    if not total:
        return [None, None]
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, centre - margin), min(1.0, centre + margin)]


def rate(mask):
    return float(np.mean(mask)) if len(mask) else 0.0


def thresholds_for(model, calibration, target_fpr):
    normal = calibration[calibration.label == 0]
    return {context: float(np.quantile(model.score_samples(part[FEATURE_COLUMNS].to_numpy()), target_fpr))
            for context, part in normal.groupby("network_context", observed=True)}


def hybrid_decisions(frame, flagged):
    """Actions and scores with the real risk engine for rows the forest flagged.
    Unflagged rows keep the replay's rules-only outcome, which is identical."""
    actions = frame.rule_action.astype(str).to_numpy().copy()
    scores = frame.rule_score.to_numpy().astype(float).copy()
    columns = {name: frame[name].to_numpy() for name in FEATURE_COLUMNS + ["os_novelty"]}
    failures, first = frame.failed_attempt_count.to_numpy(), frame.is_first_login.to_numpy()
    contexts = frame.network_context.astype(str).to_numpy()
    correct = frame.password_correct.to_numpy() == 1
    for i in np.flatnonzero(flagged & correct & (first == 0)):
        features = {name: float(values[i]) for name, values in columns.items()}
        risk = compute_risk(features=features, failed_attempt_count=int(failures[i]), ml_anomaly_score=None,
                            ml_is_anomaly=True, is_first_ever_login=False, network_context=contexts[i])
        scores[i] = risk["score"]
        actions[i] = decide_action(risk["level"], int(failures[i]))
    return actions, scores


def outcome_summary(decisions, frame, students):
    """Attacker access per scenario plus friction for real students, for one action array."""
    correct = frame.password_correct.to_numpy() == 1
    entry = correct & (frame.stage == "entry").to_numpy()
    normal = correct & (frame.label == 0).to_numpy() & (frame.is_first_login == 0).to_numpy()
    entry_campaigns = int(entry.sum())
    allowed = int((decisions[entry] == "allow").sum())
    student_ids = frame.student_id.to_numpy(dtype=str)
    return {
        "attacker_entry_attempts": entry_campaigns,
        "attacker_access_rate": allowed / entry_campaigns if entry_campaigns else None,
        "attacker_access_ci95": wilson(allowed, entry_campaigns),
        "attacker_stopped_by_otp": rate(decisions[entry] == "otp"),
        "attacker_blocked": rate(decisions[entry] == "block"),
        "normal_logins_scored": int(normal.sum()),
        "normal_allow_rate": rate(decisions[normal] == "allow"),
        "normal_otp_rate": rate(decisions[normal] == "otp"),
        "normal_block_rate": rate(decisions[normal] == "block"),
        "students_blocked_at_least_once": len(set(student_ids[normal & (decisions == "block")])) / students,
        "otp_prompts_per_student_semester": int((decisions[normal] == "otp").sum()) / students,
    }


def per_scenario(decisions, frame):
    entry = (frame.password_correct == 1).to_numpy() & (frame.stage == "entry").to_numpy()
    scenarios = frame.scenario.astype(str).to_numpy()
    table = {}
    for name in SCENARIO_LABELS:
        mask = entry & (scenarios == name)
        allowed = int((decisions[mask] == "allow").sum())
        table[name] = {"entry_attempts": int(mask.sum()), "allowed": allowed,
                       "access_rate": allowed / int(mask.sum()) if mask.sum() else None,
                       "access_ci95": wilson(allowed, int(mask.sum())),
                       "otp_rate": rate(decisions[mask] == "otp"), "block_rate": rate(decisions[mask] == "block")}
    return table


def ranking(labels, scores):
    return {"roc_auc": float(roc_auc_score(labels, scores)), "pr_auc": float(average_precision_score(labels, scores))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ML_ROOT / "dataset" / "student_login_events.csv.gz"))
    parser.add_argument("--students", default=str(ML_ROOT / "dataset" / "students.csv.gz"))
    parser.add_argument("--legacy", default=str(ML_ROOT / "dataset" / "synthetic_login_data.csv"))
    parser.add_argument("--models", default=str(ML_ROOT / "models"))
    parser.add_argument("--out", default=str(ML_ROOT / "results"))
    parser.add_argument("--no-figures", action="store_true")
    args = parser.parse_args()
    out = Path(args.out)
    (out / "figures").mkdir(parents=True, exist_ok=True)

    bundle = joblib.load(Path(args.models) / "isolation_forest.joblib")
    model, context_thresholds = bundle["model"], bundle["context_thresholds"]
    model.n_jobs = -1
    print("Loading events")
    frame = load_events(args.data)
    frame["split"] = split_students(frame.student_id)
    train = frame[frame.split == "train"]
    calibration = frame[frame.split == "calibration"].copy()
    test = frame[frame.split == "test"].reset_index(drop=True)
    test_students = test.student_id.nunique()
    print(f"test events {len(test):,} from {test_students:,} students")

    x_test = test[FEATURE_COLUMNS].to_numpy()
    if_scores = model.score_samples(x_test)
    contexts = test.network_context.astype(str)
    flagged = if_scores < contexts.map(context_thresholds).to_numpy()
    results = {"source": "Simulated student logins; real-world accuracy is not established",
               "test_students": test_students, "test_events": int(len(test)),
               "test_attack_events": int(test.label.sum())}

    # ---- Three policies ----
    rule_actions = test.rule_action.astype(str).to_numpy()
    hybrid_actions, hybrid_scores = hybrid_decisions(test, flagged)
    wrong_password = test.password_correct.to_numpy() == 0
    if_only_actions = np.where(wrong_password, "block", np.where(flagged, "otp", "allow"))
    password_only = np.where(wrong_password, "block", "allow")
    policies = {"Password only": password_only, "Isolation Forest only": if_only_actions,
                "Rules only": rule_actions, "Rules + Isolation Forest": hybrid_actions}
    results["policies"] = {name: outcome_summary(actions, test, test_students) for name, actions in policies.items()}
    results["scenarios"] = {name: per_scenario(actions, test) for name, actions in policies.items()}

    # ---- Ranking quality for the decision that matters: correct password, allow or not ----
    decision = (test.password_correct == 1).to_numpy() & (test.stage.isin(["normal", "entry"])).to_numpy()
    y_decision = test.label.to_numpy()[decision]
    # Comparators learn from labels in training. Labels are rarely available in deployment,
    # so these show what a supervised approach could reach, not what could be deployed.
    attacks = train[train.label == 1]
    normals = train[train.label == 0].sample(min(300_000, int((train.label == 0).sum())), random_state=3)
    supervised = pd.concat([attacks, normals])
    x_supervised, y_supervised = supervised[FEATURE_COLUMNS].to_numpy(), supervised.label.to_numpy()
    forest = RandomForestClassifier(n_estimators=150, min_samples_leaf=5, class_weight="balanced",
                                    random_state=42, n_jobs=-1).fit(x_supervised, y_supervised)
    logistic = LogisticRegression(max_iter=500, class_weight="balanced").fit(x_supervised, y_supervised)
    ranked = {"Isolation Forest (unsupervised)": -if_scores[decision],
              "Rule score": test.rule_score.to_numpy()[decision],
              "Rules + Isolation Forest score": hybrid_scores[decision],
              "Logistic regression (supervised)": logistic.predict_proba(x_test[decision])[:, 1],
              "Random forest (supervised)": forest.predict_proba(x_test[decision])[:, 1]}
    results["ranking_correct_password_decisions"] = {
        "events": int(decision.sum()), "attack_events": int(y_decision.sum()),
        "baseline_pr_auc_random": float(y_decision.mean()),
        "models": {name: ranking(y_decision, scores) for name, scores in ranked.items()},
    }
    results["ranking_all_events_isolation_forest"] = ranking(test.label, -if_scores)

    # ---- Threshold trade-off ----
    results["threshold_sweep"] = []
    for target in (0.005, 0.01, 0.02, 0.05, 0.10):
        limits = thresholds_for(model, calibration, target)
        marked = if_scores < contexts.map(limits).to_numpy()
        actions, _ = hybrid_decisions(test, marked)
        summary = outcome_summary(actions, test, test_students)
        results["threshold_sweep"].append({"target_fpr": target, "achieved_fpr_all_normal": rate(marked[test.label == 0]),
            **{key: summary[key] for key in ("attacker_access_rate", "normal_otp_rate", "normal_block_rate",
                                             "otp_prompts_per_student_semester")}})

    # ---- Which signals does the forest rely on? ----
    rng = np.random.default_rng(5)
    keep = np.flatnonzero(decision)
    positive, negative = keep[y_decision == 1], keep[y_decision == 0]
    subset = np.concatenate([positive, rng.choice(negative, min(150_000, len(negative)), replace=False)])
    base_x, base_y = x_test[subset].copy(), test.label.to_numpy()[subset]
    base_score = average_precision_score(base_y, -model.score_samples(base_x))
    results["permutation_importance_pr_auc_drop"] = {}
    for position, name in enumerate(FEATURE_COLUMNS):
        shuffled = base_x.copy()
        shuffled[:, position] = rng.permutation(shuffled[:, position])
        results["permutation_importance_pr_auc_drop"][name] = float(
            base_score - average_precision_score(base_y, -model.score_samples(shuffled)))

    # ---- Friction by student group and context, under the deployed policy ----
    profile = pd.read_csv(args.students)
    archetypes = dict(zip(profile.student_id, profile.archetype))
    residences = dict(zip(profile.student_id, profile.residence))
    normal_ok = (test.password_correct == 1).to_numpy() & (test.label == 0).to_numpy() & (test.is_first_login == 0).to_numpy()
    groups = {"archetype": test.student_id.map(archetypes).to_numpy(dtype=str),
              "residence": test.student_id.map(residences).to_numpy(dtype=str),
              "network_context": contexts.to_numpy()}
    results["friction_by_group"] = {}
    for group, values in groups.items():
        results["friction_by_group"][group] = {}
        for value in sorted(set(values)):
            mask = normal_ok & (values == value)
            results["friction_by_group"][group][value] = {
                "logins": int(mask.sum()), "allow": rate(hybrid_actions[mask] == "allow"),
                "otp": rate(hybrid_actions[mask] == "otp"), "block": rate(hybrid_actions[mask] == "block")}

    # ---- Alert load an IT team would see, scaled from the test population ----
    # Raised: correct password but not allowed, or a guessing run reaching three failures.
    # Left open: an OTP the student verified closes itself, so analysts see the remainder.
    raised = ((test.password_correct == 1).to_numpy() & (hybrid_actions != "allow")) | (
        wrong_password & (test.failed_attempt_count.to_numpy() == 2))
    is_attack = test.label.to_numpy() == 1
    genuine_otp = raised & ~is_attack & (hybrid_actions == "otp") & (test.password_correct == 1).to_numpy()
    open_genuine = (raised & ~is_attack).sum() - genuine_otp.sum() * OTP_PASS_RATE_LEGIT
    open_attack = (raised & is_attack).sum()
    per_day = 120 * test_students / 10_000
    results["alerts"] = {"raised_per_day_per_10000_students": float(raised.sum() / per_day),
                         "open_per_day_per_10000_students": float((open_genuine + open_attack) / per_day),
                         "share_of_open_alerts_from_attacks": float(open_attack / (open_genuine + open_attack))}

    # ---- Why the earlier 0.9998 cannot be trusted ----
    legacy_path = Path(args.legacy)
    if legacy_path.exists():
        legacy = pd.read_csv(legacy_path)
        legacy_train = legacy.sample(frac=.6, random_state=42)
        legacy_test = legacy.drop(legacy_train.index)
        legacy_model = IsolationForest(n_estimators=150, max_samples=256, random_state=42, n_jobs=-1).fit(
            legacy_train.loc[legacy_train.label == 0, FEATURE_COLUMNS].to_numpy())
        results["legacy_comparison"] = {
            "legacy_model_on_legacy_data": ranking(legacy_test.label, -legacy_model.score_samples(
                legacy_test[FEATURE_COLUMNS].to_numpy())),
            "legacy_model_on_student_decisions": ranking(y_decision, -legacy_model.score_samples(x_test[decision])),
            "deployed_model_on_student_decisions": ranking(y_decision, -if_scores[decision]),
        }

    # ---- Per-login latency of the path added by this system ----
    model.n_jobs = 1
    row = dict(zip(FEATURE_COLUMNS, x_test[0].tolist()))
    samples = []
    for _ in range(300):
        started = time.perf_counter()
        score = model.score_samples(np.array([[row[c] for c in FEATURE_COLUMNS]]))[0]
        compute_risk(features={**row, "os_novelty": 0}, failed_attempt_count=0, ml_anomaly_score=None,
                     ml_is_anomaly=bool(score < -1), is_first_ever_login=False)
        samples.append((time.perf_counter() - started) * 1000)
    results["latency_ms_ml_plus_rules"] = {"p50": float(np.percentile(samples, 50)),
                                           "p95": float(np.percentile(samples, 95))}
    results["risk_thresholds"] = {"low_max": settings.risk_low_max, "medium_max": settings.risk_medium_max}

    (out / "system_evaluation.json").write_text(json.dumps(results, indent=2))
    print(json.dumps({k: results[k] for k in ("policies", "ranking_correct_password_decisions",
                                               "threshold_sweep", "alerts", "latency_ms_ml_plus_rules")}, indent=1))
    if args.no_figures:
        return

    figures = out / "figures"
    # Attacker access by scenario, easiest to hardest.
    rules = results["scenarios"]["Rules only"]
    hybrid = results["scenarios"]["Rules + Isolation Forest"]
    names = [n for n in sorted(SCENARIO_LABELS, key=lambda n: hybrid[n]["access_rate"] or 0) if hybrid[n]["entry_attempts"]]
    fig, axis = plt.subplots(figsize=(7.2, 3.6))
    y = np.arange(len(names))
    height = .36
    axis.barh(y - height / 2 - .01, [100 * rules[n]["access_rate"] for n in names], height, color=ORANGE, label="Rules only")
    axis.barh(y + height / 2 + .01, [100 * hybrid[n]["access_rate"] for n in names], height, color=BLUE, label="Rules + Isolation Forest")
    for i, n in enumerate(names):
        axis.text(100 * hybrid[n]["access_rate"] + 1, i + height / 2 + .01, f"{100 * hybrid[n]['access_rate']:.0f}%", va="center", fontsize=8.5, color=MUTED)
    axis.set_yticks(y, [f"{SCENARIO_LABELS[n]} (n={hybrid[n]['entry_attempts']})" for n in names])
    axis.invert_yaxis()
    axis.grid(axis="y", visible=False)
    axis.set_xlim(0, 112)
    axis.set_xlabel("Attacker logins allowed through (%)")
    axis.set_title("Remote attackers are stopped. Attackers who look like the student are not.")
    axis.legend(loc="upper right")
    fig.savefig(figures / "attacker_access_by_scenario.png")
    plt.close(fig)

    # Precision-recall for the three deployable scorers.
    fig, axis = plt.subplots(figsize=(6.2, 3.8))
    for name, color in [("Rules + Isolation Forest score", BLUE), ("Rule score", ORANGE), ("Isolation Forest (unsupervised)", AQUA)]:
        precision, recall, _ = precision_recall_curve(y_decision, ranked[name])
        value = results["ranking_correct_password_decisions"]["models"][name]["pr_auc"]
        axis.step(recall, precision, where="post", color=color, linewidth=2, label=f"{name}: PR-AUC {value:.3f}")
    axis.set_xlabel("Recall (share of attacker logins caught)")
    axis.set_ylabel("Precision")
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1.02)
    axis.set_title("Detection quality on correct-password logins")
    axis.legend(loc="upper right", fontsize=8.5)
    fig.savefig(figures / "precision_recall.png")
    plt.close(fig)

    # Security versus friction as the forest's threshold moves.
    fig, axis = plt.subplots(figsize=(6.2, 3.4))
    sweep = results["threshold_sweep"]
    axis.plot([100 * s["normal_otp_rate"] for s in sweep], [100 * s["attacker_access_rate"] for s in sweep],
              color=BLUE, linewidth=2, marker="o", markersize=8, markeredgecolor="white", markeredgewidth=2)
    for s in sweep:
        axis.annotate(f"{100 * s['target_fpr']:g}%", (100 * s["normal_otp_rate"], 100 * s["attacker_access_rate"]),
                      textcoords="offset points", xytext=(8, 7), ha="left", fontsize=8.5, color=MUTED)
    axis.margins(x=.1, y=.15)
    axis.set_xlabel("Real student logins that get an OTP prompt (%)")
    axis.set_ylabel("Attacker logins allowed (%)")
    axis.set_title("Tightening the forest threshold trades friction for security")
    axis.text(.98, .95, "Point labels: forest's target false-positive rate", transform=axis.transAxes,
              ha="right", va="top", fontsize=8.5, color=MUTED)
    fig.savefig(figures / "threshold_tradeoff.png")
    plt.close(fig)

    # Signals the forest relies on.
    importance = sorted(results["permutation_importance_pr_auc_drop"].items(), key=lambda item: item[1])
    fig, axis = plt.subplots(figsize=(6.2, 3.1))
    axis.barh([k.replace("_", " ") for k, _ in importance], [v for _, v in importance], .55, color=BLUE)
    axis.grid(axis="y", visible=False)
    axis.set_xlabel("Drop in PR-AUC when the feature is shuffled")
    axis.set_title("Which signals the Isolation Forest relies on")
    fig.savefig(figures / "feature_importance.png")
    plt.close(fig)

    # Semester shape of the simulated log.
    daily = None
    for chunk in pd.read_csv(args.data, usecols=["timestamp"], chunksize=1_000_000, dtype=str):
        counts = chunk.timestamp.str.slice(0, 10).value_counts()
        daily = counts if daily is None else daily.add(counts, fill_value=0)
    daily = daily.sort_index()
    daily.index = pd.to_datetime(daily.index)
    daily = daily[(daily.index >= "2025-07-14") & (daily.index < "2025-11-11")]
    results["peak_daily_events"] = int(daily.max())
    fig, axis = plt.subplots(figsize=(7.2, 2.8))
    axis.plot(daily.index, daily.values / 1000, color=BLUE, linewidth=2)
    for label, when, height in [("Mid-sem exams", "2025-09-10", 92), ("Holiday", "2025-10-01", 62),
                                ("Results", "2025-10-10", 136), ("Holiday", "2025-10-20", 62),
                                ("End-sem exams", "2025-11-05", 92)]:
        axis.text(pd.Timestamp(when), height, label, ha="center", fontsize=8.5, color=MUTED)
    axis.xaxis.set_major_locator(matplotlib.dates.MonthLocator())
    axis.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%b %Y"))
    axis.set_ylabel("Login attempts per day (thousands)")
    axis.set_ylim(0, daily.max() / 1000 * 1.2)
    axis.set_title(f"One simulated semester: {daily.sum() / 1e6:.1f} million login attempts")
    fig.savefig(figures / "semester_activity.png")
    plt.close(fig)
    (out / "system_evaluation.json").write_text(json.dumps(results, indent=2))
    print("Figures written to", figures)


if __name__ == "__main__":
    main()
