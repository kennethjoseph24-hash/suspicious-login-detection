# Machine learning and evaluation

All figures come from `ml/results/system_evaluation.json` and
`ml/models/evaluation.json`. The data is simulated, so they describe the system under
hand-designed scenarios and do not establish real-world accuracy.

## Model

An Isolation Forest (Liu, Ting and Zhou, 2008) isolates points with random splits;
unusual points separate in fewer splits. It suits this problem because it trains on
normal behaviour alone, and confirmed attack labels are rarely available to a college.

Hyperparameters were chosen on calibration students only: 100 trees and 4,096 samples
per tree, the smallest forest within 0.005 PR-AUC of the best in the grid. One
threshold per network context targets a 1% false-positive rate on normal calibration
logins. A flag adds 20 points to the risk score, so the model is one signal among
several, not a verdict.

## The eight features

Computed in `backend/app/ml/feature_engineering.py` against the student's profile.

| Feature | Meaning |
|---|---|
| `location_novelty` | Location not seen before |
| `device_novelty` | Device label not seen before (suppressed on registered lab PCs) |
| `browser_novelty` | Browser family not seen before (suppressed on registered lab PCs) |
| `ip_novelty` | IP not seen before (suppressed on campus networks) |
| `hour_deviation` | Circular distance from the usual login window, scaled to 0-1 |
| `failed_attempts_norm` | Recent failures in the last 15 minutes / 5, capped at 1 |
| `login_frequency_norm` | Near 1 when the previous attempt was seconds ago |
| `geo_distance_norm` | Distance from the average known location / 3,000 km, capped at 1 |

## Dataset

`ml/training/generate_student_dataset.py` simulates 50,000 students over a 120-day
semester: 5,507,347 login attempts, including 19,213 attack attempts in 4,920 campaigns.

**Why simulate?** No public dataset of real student logins could be used. The closest
candidate found, HIED-AuthLog, is under embargo until 23 December 2026. Real logs are
also personal data.

**Why not reuse the old dataset?** `generate_dataset.py` samples feature values directly,
so attacks are separable by construction: its model scores ROC-AUC 0.9998 on its own
data but 0.835 on realistic student decisions. The new simulator models behaviour only.
Each student's logins are replayed through the production `build_features`,
`contextualize_features`, `compute_risk` and `decide_action` code, and
`tests/test_simulator_parity.py` checks that profiles learn the same way as production.

**Normal behaviour:** five student archetypes, hostel and day scholars, weekends, exam
peaks, results day, holidays at home, trips, foreign exchange, changed phones, friends'
devices, typos and forgotten passwords.

**Attack scenarios:** credential stuffing, brute force, foreign takeover, domestic
phishing, impossible travel, insider peer, stolen device and lab shoulder-surfing.
Attackers who get in may return later, which can poison the baseline, as it would in
production. 10% of students being attacked is a stress-test assumption, not a prevalence
estimate.

## Method

Students, not events, are split 60/20/20 into train, calibration and test, so nobody
appears on both sides. The forest fits on normal training events only. Test students
(10,000 students, 1,098,676 attempts) are used only for reporting. Intervals are 95%
Wilson intervals; they reflect sampling only, not whether the scenarios are realistic.

## Results

The Isolation Forest's anomaly flag on all 1,098,676 held-out events has this
confusion matrix. This includes wrong-password attack bursts, which are easier
to identify than an attacker entering with the correct password.

| Actual event | Flagged anomaly | Not flagged |
|---|---:|---:|
| Attack | 3,107 | 885 |
| Normal | 10,860 | 1,083,824 |

That is 77.8% attack recall, 22.2% precision and a 0.99% false-positive
rate. A model flag contributes to the risk score; it is not itself a block.
The access-control comparison below evaluates 800 attacker entry attempts
with the correct password. Under the deployed policy, 306 were allowed,
490 required OTP, and 4 were blocked. These are distinct evaluation questions.

| Policy | Attacker access (95% CI) | OTP on real logins | Real logins blocked | Students blocked at least once |
|---|---|---|---|---|
| Password only | 100% | 0% | 0% | 0% |
| Isolation Forest only | 50.9% (47.4-54.3) | 0.54% | 0% | 0% |
| Rules only | 39.5% (36.2-42.9) | 2.16% | 0.10% | 8.8% |
| Rules + Isolation Forest | 38.2% (34.9-41.7) | 2.28% | 0.11% | 10.1% |

"Access" means the system said ALLOW to an attacker holding the correct password,
assuming attackers cannot complete an OTP.

| Scenario | Attempts | Rules + IF access | Rules-only access | IF-only access |
|---|---|---|---|---|
| Foreign takeover | 161 | 0% | 0% | 0% |
| Credential stuffing | 97 | 0% | 0% | 0% |
| Impossible travel | 46 | 0% | 0% | 0% |
| Brute force | 4 | 0% | 0% | 0% |
| Domestic phishing | 193 | 18.7% | 18.7% | 64.8% |
| Insider peer | 134 | 79.1% | 86.6% | 88.8% |
| Stolen device | 78 | 98.7% | 98.7% | 98.7% |
| Lab shoulder-surfing | 87 | 100% | 100% | 98.9% |

Ranking quality on correct-password decisions (attack rate 0.08%):

| Scorer | ROC-AUC | PR-AUC |
|---|---|---|
| Isolation Forest (unsupervised) | 0.839 | 0.185 |
| Rule score | 0.845 | 0.162 |
| Rules + Isolation Forest score | 0.847 | 0.141 |
| Logistic regression (supervised, for comparison) | 0.844 | 0.273 |
| Random forest (supervised, for comparison) | 0.861 | 0.426 |

Over all attempts, including password-guessing bursts, the forest reaches ROC-AUC 0.910:
0.967 on external connections, but only 0.597 on campus and 0.595 in labs, where
attackers look like students.

## What this means

1. **Rules and OTP do most of the work.** The forest's benefit over rules (39.5% to 38.2%)
   is within the margin of error, and in an independent run (seed 7, 10,000 students) it
   was zero (41.3% both ways).
2. **The forest alone is unstable.** It let through 0% of foreign takeovers in the main
   run and 39% in the independent run. It should not be the only control.
3. **Some attacks cannot be seen from login context.** A classmate on campus or a thief
   with the student's laptop looks like the student. These need a different control,
   such as passkeys or MFA on sensitive actions.
4. **Supervised models could do better if labels existed** (PR-AUC 0.426 against 0.185),
   but a college rarely has confirmed attack labels.

The forest relies mostly on `geo_distance_norm` (PR-AUC drop 0.27 when shuffled) and
`device_novelty` (0.05). Shuffling hour, failures or frequency slightly improves it on
correct-password decisions, so these features act as noise there.

## Design change made from these results

Originally every HIGH score was a hard block. Evaluation showed this blocked 28.3% of real
students at least once per semester, often for simply logging in from home. Since a block
and an OTP both keep an attacker out under our assumptions, behaviour alone now earns an
OTP, and a block needs 3+ recent password failures as well.

| Rules + IF | Before | After |
|---|---|---|
| Attacker access | 38.8% | 38.2% |
| Real logins blocked | 0.39% | 0.11% |
| Students blocked at least once | 28.3% | 10.1% |
| OTP on real logins | 2.16% | 2.28% |

The remaining 10.1% is mostly forgotten passwords, and clears after the 15-minute window.
The "before" results are in `ml/results/system_evaluation_before_policy_fix.json`.

## Operational cost

Per 10,000 students: about 248 alerts raised per day and 61 left open after students verify
their OTPs. Only 8.7% of open alerts relate to attacks, even at the assumed high attack
rate, so a real deployment would need alert tuning. In the latest local evaluation,
ML plus rule scoring took 5.8 ms median and 15.4 ms at the 95th percentile per login;
this timing depends on the machine.

## Threats to validity

- Behaviour rates and attack scenarios are our assumptions, not measurements.
- The percentage of attacks stopped depends on the scenario mix, so per-scenario figures
  are more meaningful than the overall figure.
- Baselines were built in a rules-only replay; ML decisions were not fed back into them.
- OTP is assumed secure. Real OTP phishing or SIM swapping would raise attacker access.
- Few brute-force attempts ever guess the password (4 in test), so that row is imprecise.
