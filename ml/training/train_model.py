"""Trains the deployed Isolation Forest on the simulated student login log.

Students are split 60/20/20 into train, calibration and test sets, so nobody's
behaviour appears on both sides of the evaluation. The forest learns from normal
training events only. Calibration events set one threshold per network context
and choose hyperparameters; test events are used for nothing but reporting.

Results come from simulated data and do not establish real-world ERP accuracy.

    python ml/training/train_model.py
"""
import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
FEATURE_COLUMNS = ["location_novelty", "device_novelty", "browser_novelty", "ip_novelty",
                   "hour_deviation", "failed_attempts_norm", "login_frequency_norm", "geo_distance_norm"]
TARGET_FPR = 0.01
TUNING_ROWS = 400_000
GRID = [(n, m) for n in (100, 150, 300) for m in (256, 1024, 4096)]
LOAD_COLUMNS = ["student_id", "network_context", "password_correct", "failed_attempt_count", "is_first_login",
                "os_novelty", "rule_score", "rule_action", "result", "label", "scenario", "stage",
                "campaign_id", *FEATURE_COLUMNS]
DTYPES = {**{c: "float32" for c in FEATURE_COLUMNS}, "password_correct": "int8", "failed_attempt_count": "int16",
          "is_first_login": "int8", "os_novelty": "int8", "rule_score": "float32", "label": "int8",
          "network_context": "category", "rule_action": "category", "result": "category",
          "scenario": "category", "stage": "category", "student_id": "string", "campaign_id": "string"}


def load_events(path):
    return pd.read_csv(path, usecols=LOAD_COLUMNS, dtype=DTYPES)


def split_students(student_ids, seed=42):
    """Returns 'train', 'calibration' or 'test' per event, keeping each student whole."""
    unique = np.sort(student_ids.unique().to_numpy(dtype=str))
    np.random.default_rng(seed).shuffle(unique)
    first, second = int(len(unique) * .6), int(len(unique) * .8)
    mapping = {**{s: "train" for s in unique[:first]},
               **{s: "calibration" for s in unique[first:second]},
               **{s: "test" for s in unique[second:]}}
    return student_ids.map(mapping).astype("category")


def report(frame, scores, flagged):
    labels = frame.label.to_numpy()
    normal = labels == 0
    return {
        "rows": int(len(frame)), "attack_rows": int(labels.sum()),
        "precision": float(precision_score(labels, flagged, zero_division=0)),
        "recall": float(recall_score(labels, flagged, zero_division=0)),
        "f1": float(f1_score(labels, flagged, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, -scores)),
        "pr_auc": float(average_precision_score(labels, -scores)),
        "false_positive_rate": float(flagged[normal].mean()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "dataset" / "student_login_events.csv.gz"))
    parser.add_argument("--models", default=str(ROOT / "models"))
    args = parser.parse_args()

    print(f"Loading {args.data}")
    frame = load_events(args.data)
    frame["split"] = split_students(frame.student_id)
    train = frame[frame.split == "train"]
    calibration = frame[frame.split == "calibration"]
    test = frame[frame.split == "test"]
    print({name: len(part) for name, part in [("train", train), ("calibration", calibration), ("test", test)]})

    train_normal = train.loc[train.label == 0, FEATURE_COLUMNS].to_numpy()
    tuning = calibration.sample(min(TUNING_ROWS, len(calibration)), random_state=1)
    # Keep every calibration attack so the small attack class is not lost to sampling.
    tuning = pd.concat([tuning[tuning.label == 0], calibration[calibration.label == 1]])
    tuning_x = tuning[FEATURE_COLUMNS].to_numpy()
    grid = []
    for n_estimators, max_samples in GRID:
        candidate = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                                    random_state=42, n_jobs=-1).fit(train_normal)
        grid.append({"n_estimators": n_estimators, "max_samples": max_samples,
                     "calibration_pr_auc": float(average_precision_score(
                         tuning.label, -candidate.score_samples(tuning_x)))})
        print(grid[-1])
    # Prefer the smallest forest within 0.005 of the best score: it serves every login.
    best_score = max(row["calibration_pr_auc"] for row in grid)
    chosen = min((row for row in grid if row["calibration_pr_auc"] >= best_score - .005),
                 key=lambda row: (row["n_estimators"], row["max_samples"]))

    started = time.perf_counter()
    model = IsolationForest(n_estimators=chosen["n_estimators"], max_samples=chosen["max_samples"],
                            contamination="auto", random_state=42, n_jobs=-1).fit(train_normal)
    training_seconds = time.perf_counter() - started

    normal_calibration = calibration[calibration.label == 0]
    reference = np.sort(model.score_samples(normal_calibration[FEATURE_COLUMNS].to_numpy()))
    threshold = float(np.quantile(reference, TARGET_FPR))
    context_thresholds = {}
    for context in sorted(calibration.network_context.astype(str).unique()):
        part = normal_calibration[normal_calibration.network_context == context]
        context_thresholds[context] = float(np.quantile(
            model.score_samples(part[FEATURE_COLUMNS].to_numpy()), TARGET_FPR))

    scores = model.score_samples(test[FEATURE_COLUMNS].to_numpy())
    flagged = scores < test.network_context.astype(str).map(context_thresholds).to_numpy()
    evaluation = report(test, scores, flagged)
    evaluation["by_context"] = {}
    for context, limit in context_thresholds.items():
        mask = (test.network_context == context).to_numpy()
        evaluation["by_context"][context] = report(test[mask], scores[mask], flagged[mask])
    evaluation.update({
        "split": {"unit": "student", "train_events": int(len(train)), "calibration_events": int(len(calibration)),
                  "test_events": int(len(test)), "normal_events_used_for_fitting": int(len(train_normal))},
        "target_calibration_fpr": TARGET_FPR, "chosen_hyperparameters": chosen, "hyperparameter_grid": grid,
        "training_seconds": round(training_seconds, 3),
        "source": "Simulated student logins; real-world accuracy is not established",
    })

    # Scoring uses every core in batch; model_service switches to one for single logins.
    bundle = {"model": model, "feature_columns": FEATURE_COLUMNS, "version": 3, "threshold": threshold,
              # A percentile lookup does not need every score, which keeps the model file small.
              "reference_scores": reference[np.linspace(0, len(reference) - 1, 20_000).astype(int)],
              "context_thresholds": context_thresholds, "training_rows": int(len(train_normal)),
              "evaluation": evaluation}
    models = Path(args.models)
    models.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, models / "isolation_forest.joblib", compress=3)
    (models / "evaluation.json").write_text(json.dumps(evaluation, indent=2))
    print(json.dumps({k: v for k, v in evaluation.items() if k != "hyperparameter_grid"}, indent=2))


if __name__ == "__main__":
    main()
