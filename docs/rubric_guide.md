# CampusGuard: rubric-aligned presentation and report guide

This guide follows the six criteria in the supplied evaluation table. Use it with `presentation_script.md`. The project is a working **academic prototype evaluated on simulated data**. Present that fact clearly wherever results appear.

## 1. Introduction: problem statement, objectives, scope (5 marks)

### Put on the slide

**Problem:** A correct password does not prove that the person logging into a college ERP is the student. Generic location or device novelty checks also misread shared campus IPs, laboratory PCs, and students travelling home.

**Research question:** Can a context-aware login layer identify suspicious attempts while keeping verification requests manageable for genuine students, and where does that approach fail?

**Objectives:**

1. Classify a login as campus, registered laboratory, or external.
2. Maintain a personal behavior profile from trusted logins.
3. Combine explainable rules and an Isolation Forest anomaly signal.
4. Decide allow, OTP, or block, and record the reason.
5. Give admins a protected view of attempts, alerts, data, and evaluation.
6. Measure both attacker access and legitimate-student friction by scenario.

**Scope:** A Next.js/FastAPI prototype, SQLite demo database, simulated context controls, simulated student dataset, trained model, and held-out evaluation. No real college traffic, live geolocation, or delivered SMS/email OTP is claimed.

### Say

“The challenge is not just detecting an unusual login. A college has shared networks and lab computers, so normal behavior can look unusual. We built a login layer that adjusts for that context, then measured how often it stops attackers and how often it inconveniences students.”

### Evidence to show

Open the Access Portal. Point to the three network scenarios. State the research question before describing tools.

## 2. Literature review: depth and critical analysis (5 marks)

Use a comparison table. Explain what each study contributes, where its setting or method differs from this project, and which design decision you took from it. Do not claim that CampusGuard outperforms studies with real users; this prototype has only simulated data.

| Work | What it contributes | Limit for this project | CampusGuard's response |
|---|---|---|---|
| [Liu, Ting & Zhou, *Isolation Forest* (2008)](https://doi.org/10.1109/ICDM.2008.17) | An unsupervised anomaly method that isolates unusual points without requiring attack labels. | A generic anomaly score does not decide whether to allow, challenge, or block a college login; it does not model shared campus devices. | Use Isolation Forest as one 20-point signal within context-aware rules, then measure the actual access decision. |
| [Freeman et al., *Who Are You?* (NDSS 2016)](https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-are-you-statistical-approach-measuring-user-authenticity.pdf) | Evaluates login authenticity with real LinkedIn history and simulated attacks, showing how selective challenges can add security with limited user friction. | Its service and login patterns are not a college ERP; campus IP sharing and lab PCs need explicit treatment. | Maintain per-student history, ask for OTP only when warranted, and model college-specific shared contexts. |
| [Wiefling, Lo Iacono & Dürmuth (2019)](https://epb.bibl.th-koeln.de/frontdoor/index/index/year/2019/docId/1369) | Studies risk-based authentication on eight online services and shows variation in features and user experience. | It analyzes existing general services rather than delivering an explainable college prototype. | Expose reasons and risk decisions in the student portal and admin event details. |
| [Wiefling et al., *Pump Up Password Security!* (2022)](https://doi.org/10.1145/3546069) | Studies 3.3 million real users and 31.3 million logins, including the security–usability trade-off and configuration choices. | Its real-service evidence is stronger than ours, but its setting is not the shared campus/lab environment. Its public synthetic dataset is not a student-login benchmark. | Report attacker access and student friction by scenario; state that simulated results still require real validation. |

### Say

“The literature supports risk-based, selective verification, but it also shows that configuration and user friction matter. The original Isolation Forest paper supplies a method, not an ERP access policy. Freeman and Wiefling evaluate general online services, including large real deployments. Our narrower contribution is a working college-context prototype with explicit campus/lab handling and an honest per-scenario evaluation. Their real-world studies have stronger external validity than our simulation.”

### Critical point worth emphasizing

The result changed the design: hard-blocking every HIGH behavioral score caused too many genuine students to be blocked in simulation, so the deployed policy uses OTP for behavior-only risk and reserves hard blocking for repeated password failures. This shows that literature's security–usability trade-off was tested, not merely mentioned.

## 3. Methodology: tools and technologies (5 marks)

### Put on the slide

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | Next.js / React | Student access portal, OTP flow, admin dashboard, dataset view |
| Backend | FastAPI / Python | Authentication, context collection, feature calculation, rules, API |
| Database | SQLite with SQLAlchemy | Demo users, behavior profiles, login attempts, alerts |
| Model | scikit-learn Isolation Forest | Unsupervised anomaly signal on eight numeric features |
| Security | bcrypt, signed bearer token, hashed expiring OTP | Password storage, admin access, verification |
| Evaluation | pandas, NumPy, scikit-learn, Matplotlib | Student-level split, model metrics, policy and scenario comparison |

### Explain the method in order

1. Simulate 50,000 students across 120 days: 5,507,347 events, including 19,213 attack events. Distinguish generated data from the small live demo database.
2. Replay behavior through production feature and risk code. The eight model features are location, device, browser, and IP novelty; unusual hour; recent failed attempts; rapid frequency; and geographic distance.
3. Split **students**, not rows, 60/20/20. Training has 3,308,673 events, calibration 1,099,998, and test 1,098,676. Fit the forest on 3,297,824 normal training events.
4. Select 100 trees and 4,096 samples per tree using calibration data; set context-specific thresholds for a 1% normal calibration false-positive target.
5. Evaluate on 10,000 held-out students. Compare password-only, model-only, rules-only, and combined policies. Measure attacker access, OTP prompts, blocks, and per-scenario outcomes.

### Say

“We separated model fitting, threshold setting, and final reporting. No test student appears in training or calibration. Isolation Forest learns normal behavior without attack labels; the labels are used only to evaluate the result. The model flag is added to an explainable risk score rather than treated as an automatic block.”

### Method limits

The data generator and attacks are hand-designed. An independent real dataset could produce different results. The current split tests unseen students within the same simulated semester; a future time-separated real-world test would be stronger.

## 4. Final implementation: working prototype (20 marks)

This is the highest-weight row. Spend the most live-demo time here. Show the working chain from login input to stored decision and admin review.

### Live demo sequence

1. **Health and setup:** Show `http://localhost:8000/api/health` with `ml_model_loaded: true`. Run `python tools\smoke_check.py` from `Code` before the presentation; it checks backend, model, admin access, dataset summaries, and frontend.
2. **Normal student login:** On Access Portal, use the seeded Kenneth account and Campus Wi-Fi context. Show LOW risk, allowed access, and **Why this decision?**
3. **OTP case:** Use **Test OTP challenge**. Explain the changed context, enter the displayed demo code, and show that verification completes the login. Say clearly that real OTP delivery is not connected.
4. **Blocked case:** Use **Test blocked login**. Show the HIGH score, repeated-failure reason, and blocked result.
5. **Admin access:** Open Admin Dashboard and sign in there as the seeded admin. Show Live activity charts, alerts, a filtered login attempt, and its feature/reason breakdown. Student accounts receive 403 on protected routes.
6. **Dataset & model:** Select the tab. Show 50,000 students, 5.5 million events, train/test split, confusion matrix, correct-password outcomes, policy comparison, and attack-scenario table.

### Architecture sentence

“The frontend calls protected FastAPI endpoints. The backend validates credentials, classifies observed network context, compares the login with the stored profile, scores it with rules and the loaded model, records the result in SQLite, and updates the profile only after an allowed or OTP-verified login.”

### Proof of implementation

- Source has frontend, backend, database seed, dataset simulator, training/evaluation scripts, model, and documented API.
- The frontend production build passed.
- The full backend suite passed 56 tests.
- The end-to-end smoke command passed against the new backend and frontend.
- The two submission ZIPs contain the updated dashboard, report, script, and dataset summary. The full ZIP also contains the complete event file.

### Demo contingency

If the live app is unavailable, use the report's architecture and result figures plus `ml/results/system_evaluation.json` as evidence. Describe the last successful smoke check and the exact failing component. Do not claim a live demonstration succeeded if it did not.

## 5. Results and analysis (10 marks)

### Put two clearly labelled result panels on the slide

**A. Model anomaly detection on all held-out events** (includes wrong-password attacks):

| Actual class | Flagged anomaly | Not flagged |
|---|---:|---:|
| Attack | 3,107 | 885 |
| Normal | 10,860 | 1,083,824 |

Recall 77.83%; precision 22.25%; false-positive rate 0.99%; ROC-AUC 0.910; PR-AUC 0.740. This answers whether the model flags unusual events. It does **not** mean 77.83% of stolen-password entries are stopped.

**B. Deployed policy on 800 attacker entries with the correct password:**

| Action | Entries |
|---|---:|
| Allowed | 306 |
| OTP required | 490 |
| Blocked | 4 |

Attacker access = 306/800 = 38.25%. Under the stated assumption that attackers cannot complete OTP, 494/800 = 61.75% were stopped. Rules-only access was 39.5%, so the model's incremental benefit is small and the difference is within sampling uncertainty. Among 1,006,486 genuine logins, 22,991 got OTP (2.28%) and 1,133 were blocked (0.11%).

### Interpret by scenario, not only overall average

- Foreign takeover: 0 of 161 allowed; credential stuffing: 0 of 97; impossible travel: 0 of 46.
- Domestic phishing: 36 of 193 allowed (18.7%).
- Insider peer: 106 of 134 allowed (79.1%); stolen device: 77 of 78 (98.7%); lab shoulder-surfing: 87 of 87 (100%).
- Brute-force correct-password entries: only 4 in the test; do not draw a strong conclusion from that row.

### Say

“The model finds many attack events, but final access decisions are harder when an attacker knows the correct password. The rules and OTP stop most entries in our assumed scenario mix. The model adds a small amount, not a proven major gain. Familiar attackers are a major remaining weakness. We report this failure clearly instead of presenting a near-perfect score from an easy dataset.”

### Validity statement

These intervals reflect sampling of simulated cases, not uncertainty about how real students behave. The overall attacker-access rate depends on the mix of scenarios. Real OTP phishing, real devices, and real traffic could change the result.

## 6. Final presentation and report

### Recommended slide order

1. Title, team, and one-sentence aim.
2. Problem statement, objectives, and scope.
3. Literature comparison and gap (one table, four works).
4. Architecture and login decision flow.
5. Dataset, features, and student-level train/calibration/test split.
6. Working prototype demonstration: normal, OTP, block, admin.
7. Results: confusion matrix plus correct-password policy outcomes.
8. Scenario limits, what changed in the policy, and future work.
9. Conclusion and references; leave time for questions.

Use a consistent label on every result slide: **“Simulated data; not real-world accuracy.”** Define the denominator next to each percentage. Put paper citations on the literature slide and the source of project figures (`ml/models/evaluation.json` or `ml/results/system_evaluation.json`) in slide notes or captions. The full report already has dedicated chapters for introduction, related work, design, implementation, dataset, evaluation, discussion, and conclusion.

### Two report corrections to make before submission

1. In the current `Final_Report.docx`, reference **[4]** gives `arXiv:2202.06459`, which belongs to a different paper. Replace it with the correct DOI **10.1145/3546069** for Wiefling et al., *Pump Up Password Security!* (2022), or with its arXiv identifier **2206.15139**. Check the submitted PDF after correcting the source document.
2. Replace broad statements such as “stopped every remote attacker” with the named scenarios that actually had zero allowed entries. Domestic phishing had 36 of 193 entries allowed, so “every remote attacker” is too broad.

## Final 30-second closing

“CampusGuard is a working, explainable login-security prototype for a college ERP. It handles shared campus and lab contexts, compares each login with the student's history, and chooses allow, OTP, or block. On a simulated held-out semester, the deployed policy allowed 306 of 800 correct-password attacker entries and prompted 2.28% of genuine logins for OTP. The model contributes a smaller benefit than the rules, and attackers who resemble students remain difficult to stop. The next step is validation on appropriately handled real institutional data and stronger authentication for sensitive actions.”

## Audit of the current 15-slide presentation

The existing `Final_Presentation.pptx` is a useful starting point, but it does not yet cover every rubric item. Make these specific edits before presenting:

1. **Slide 1:** Replace `[UNIQUE PROJECT ID]`, `[Team member names]`, and `[Supervisor name]`. These are still literal placeholders.
2. **After slide 2:** Add a literature-review slide with the four-work comparison in section 2. The current deck has no literature-review slide, which leaves the 5-mark criterion largely unsupported.
3. **Slide 3:** Change “53 automated tests pass” to **“56 automated tests pass”**. Add the research objective and scope verbally, or place them on slide 2.
4. **Slide 6:** Add the student-level 60/20/20 split, 3,297,824 normal fitting events, and 10,000 held-out test students in speaker notes or a small methods panel. Dataset size alone is not a complete methodology.
5. **Slide 8:** Show both denominators: the all-event confusion matrix and 800 correct-password attacker entries (306 allow, 490 OTP, 4 block). The current “100% to 38%” headline needs those details for the Results and Analysis marks.
6. **Slides 9 and 15:** Replace “remote attackers are stopped” and “every remote attacker stopped” with **“0/161 foreign takeover, 0/97 credential-stuffing, and 0/46 impossible-travel entries were allowed in this test.”** Domestic phishing had 36/193 allowed.
7. **Slide 12:** Add the new **Dataset & model** tab to the admin demo. Rehearse the exact demo controls and OTP code flow once before presenting.
8. **Slide 14:** Prefer “validate on appropriately handled real institutional logs” over a promise about a named embargoed dataset unless you have checked its availability again.
9. **References:** Put the four primary literature sources and the report's corrected [4] DOI on a final references slide or in slide notes.
