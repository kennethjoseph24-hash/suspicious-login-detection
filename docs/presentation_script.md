# CampusGuard presentation script

Use this as a spoken guide for an approximately 10–12 minute prototype presentation. The numbers below come from the saved evaluation files in this project. The dataset is **simulated**; none of the figures is a claim of performance on real college logins. For the examiner's six criteria and a literature comparison table, see `rubric_guide.md`.

## Before entering the room

1. Start the backend from `Code\backend` with `venv\Scripts\uvicorn.exe app.main:app --port 8000`.
2. Start the frontend from `Code\frontend` with `npm run dev`.
3. From `Code`, run `python tools\smoke_check.py`. It checks the model, the administrator route, the dataset results, and the frontend. It records one admin login attempt in the demo database.
4. Open `http://localhost:3000`. Keep the Access Portal and Admin Dashboard ready. The seeded demo accounts and passwords are in `ReadMe.txt`.
5. The full dataset is a compressed file in the full submission ZIP. The compact ZIP has a sample, summary, trained model, evaluation results, and a generator for recreating the full file.

## Opening: the problem (about 1 minute)

“Our project is CampusGuard, a suspicious-login detection prototype for a college ERP. An ERP account may hold academic and personal information. A password check alone cannot tell whether a login with the correct password comes from the real student or somebody who obtained that password.

“CampusGuard adds a behavioral security check after the password check. It compares a login with that student's earlier behavior and with the network context. The system then allows the login, asks for an OTP, or blocks it. It also records a reason and an alert so an administrator can investigate. Our objectives are to build that complete decision flow, give administrators an auditable view, and measure both attacker access and student inconvenience. The scope is a working prototype and simulated evaluation, not a live institutional deployment.”

**Point to:** Access Portal, then Admin Dashboard in the top navigation.

## Related work and the gap (about 1 minute)

“Liu and colleagues introduced Isolation Forest as an unsupervised anomaly detector. It gives us a way to learn from normal events without needing labelled attacks, but its anomaly flag is not itself a login decision. Freeman and colleagues evaluated selective login challenges using real LinkedIn history and simulated attacks. Wiefling and colleagues studied how risk-based authentication is used by online services and later evaluated security and user friction on a large real service.

“These studies support selective verification and measuring the security–usability trade-off. Their real-service evidence is stronger than ours, but they do not answer how a college prototype should handle shared campus IPs and lab machines. We address that narrower design problem and report where it still fails. Our dataset is simulated, so we cannot claim the external validity of the real-service studies.”

**Point to:** A four-paper comparison slide. Use the sources and limitations table in `rubric_guide.md` rather than listing citations without analysis.

## Architecture and login flow (about 1 minute)

“The frontend is built with Next.js. The backend is FastAPI. SQLite stores demo users, behavior profiles, login attempts, and alerts. A trained Isolation Forest model is saved as a joblib file and loaded by the backend at startup.

“For a login, the backend checks the password, identifies campus, laboratory, or external network context, retrieves the student's behavior profile, calculates eight numeric features, asks the model whether the pattern is unusual, and combines that signal with explainable rules. An anomaly adds 20 points to the risk score. The risk score and recent password failures determine the action.

“The dataset used for training is stored separately as compressed CSV files. The Admin Dashboard's Live activity tab reads the application database. Its Dataset & model tab reads saved dataset summaries and evaluation results. The 5.5 million training events are not imported into the live SQLite database.”

**If asked for the rule thresholds:** Scores 0–30 are LOW and allowed. Scores 31–60 are MEDIUM and require OTP. Scores 61–100 are HIGH and require OTP unless there are at least three recent password failures, when the login is blocked. A wrong password always fails. Failed attempts expire from the count after 15 minutes.

## Dataset and features (about 1½ minutes)

**Click:** Admin Dashboard. Sign in with the demo admin account on that page. Select **Dataset & model**.

“We simulated 50,000 students over a 120-day semester. The dataset has 5,507,347 login events: 5,488,134 normal events and 19,213 attack events across 4,920 attack campaigns. It includes campus, laboratory, and external connections, five student behavior types, ordinary password mistakes, travel, device changes, and eight attack scenarios.

“This is synthetic data. It contains no real student or attack records. We made that choice because usable institutional login logs were not available for this prototype. The results show behavior under our stated scenarios, not real-world accuracy.

“The eight model features are: novelty of location, device, browser, and IP address; deviation from the student's usual login hour; recent password failures; rapid login frequency; and geographic distance from the student's normal locations. We adjust the features for shared environments: a campus IP is expected to be shared, and a registered lab PC should not be treated as the student's personal device. The operating-system novelty is an additional rule signal, not one of the eight model inputs.”

**Point to:** Dataset totals, context chart, and the sample records. Explain that the sample rows are simulated examples and are not live user accounts.

## Training and testing (about 1 minute)

“We split by **student**, not by individual event: 60% for training, 20% for calibration, and 20% for the held-out test. That means a test student's login history never appears in model fitting. The event counts were 3,308,673 training, 1,099,998 calibration, and 1,098,676 test. The Isolation Forest fitted on 3,297,824 normal training events. It did not train on attack labels.

“We compared candidate forests on calibration data and selected 100 trees with 4,096 samples per tree. A threshold for each network context targets a 1% false-positive rate on normal calibration logins. We then reported performance on 10,000 held-out students. Those test students were not used to choose the threshold or model settings.”

**Point to:** The train/calibration/test bar and model card.

## Two different result questions (about 2 minutes)

“There are two result questions here, and we keep them separate.

“First, did the Isolation Forest flag unusual events across **all** 1,098,676 test events, including password-guessing attempts? It flagged 3,107 of 3,992 attack events and missed 885. It also flagged 10,860 normal events, while 1,083,824 normal events were not flagged. That is 77.83% attack recall, 22.25% precision, and a 0.99% false-positive rate. Its ROC-AUC is 0.910 and PR-AUC is 0.740 on this all-event task. A model flag is a signal; it is not automatically a block.

“Second, what happens when an attacker has the **correct password**? This is the important access-control question. In 800 held-out attacker entry attempts, our deployed rules-plus-model policy allowed 306, challenged 490 with OTP, and blocked 4. Under our evaluation assumption that attackers cannot complete OTP, 494 of 800 entries were stopped and 306 were let in. So attacker access was 38.25%. Rules alone allowed 39.5%. The difference is small and within statistical uncertainty, so we do not claim that the Isolation Forest adds a large proven improvement.

“For legitimate students, among 1,006,486 normal logins scored for policy friction, 22,991 received an OTP prompt, about 2.28%, and 1,133 were blocked, about 0.11%. Those blocks largely relate to recent password failures. The model's PR-AUC on the harder correct-password decisions is 0.185, much lower than the 0.740 figure for all events. The two values use different sets of events and answer different questions.”

**Point to:** Confusion matrix, correct-password outcome card, and policy comparison table. Pause after “different questions”; this prevents the most common misunderstanding of the metrics.

## Where it works and where it does not (about 1 minute)

“The scenario table shows the system's strengths and limits. It allowed none of 161 foreign takeover entries, none of 97 credential-stuffing entries, and none of 46 impossible-travel entries in this test set. The brute-force correct-password row also shows zero allowed, but it has only four entries, so that row is too small for a strong claim.

“The difficult cases look like normal student activity: 106 of 134 insider-peer entries, 77 of 78 stolen-device entries, and all 87 lab shoulder-surfing entries were allowed. A friend on campus or someone using the student's own device may look normal to a login-context system. That is a limit of the available signals. A stronger authenticator or an extra check before sensitive ERP actions would address a different part of the risk.”

**Point to:** The attacker-access-by-scenario table. If short on time, show just one clear success case and one clear failure case.

## Live demonstration (about 1½ minutes)

1. **Access Portal, baseline:** Enter the seeded `kenneth` account and select **Campus Wi-Fi**. Say: “This resembles Kenneth's stored history, so it should be LOW risk and allowed.” Sign in. Open **Why this decision?** to show reasons.
2. **OTP challenge:** Use the portal's **Test OTP challenge** control. Say: “Unusual context earns a verification step.” Sign in, read the demo OTP displayed in the response, and verify it. The OTP is shown on screen only because this is a prototype.
3. **Repeated-failure block:** Use **Test blocked login**. Say: “A high risk score combined with recent password failures leads to a block.” Open the reason list.
4. **Administrator view:** Open **Admin Dashboard**, sign in as the seeded admin there, show Live activity and a login detail, then select **Dataset & model**. Say: “The live records and the large training dataset are separate.”

If a demo attempt has changed the student's baseline or repeated failures affect the next attempt, explain that the system learns from successful logins and counts failures for 15 minutes. Use **Reset Demo Data** before rehearsing; re-run `database\seed.py` to restore seeded behavior history.

## Limitations and next steps (about 1 minute)

“This is an academic prototype, not a production security service. The dataset is simulated, the location picker is a demo input rather than live IP geolocation, and OTP is displayed in the API response instead of being delivered through a real channel. The seeded passwords and development defaults must be replaced before deployment.

“The evaluation assumes an attacker cannot complete OTP. If an attacker can phish the OTP, access rates would be higher. The result also depends on the attack mix we simulated. We would validate on appropriately handled institutional logs before claiming real-world performance. We would then tune alerts, improve device identity, and add a stronger authentication method for sensitive actions.”

**Closing sentence:** “Our contribution is a working, explainable login decision pipeline and an evaluation that reports both where it helps and where it fails.”

## If you have only 60 seconds

“CampusGuard is a college ERP login-security prototype. It checks each login against the student's earlier behavior and network context, then allows it, asks for OTP, or blocks it using explainable rules plus an Isolation Forest. We trained and tested on a simulated 120-day dataset of 50,000 students and 5.5 million events, splitting by student so the test students were held out. On 800 attacker entries with the correct password, the deployed policy allowed 306, challenged 490 with OTP, and blocked 4. About 2.28% of genuine logins received OTP. It catches distinctive remote attacks in our scenarios, but it struggles with classmates or stolen devices that look like the real student. The data is simulated, so these are prototype results, not claims of real-world accuracy.”

## Likely viva questions and short answers

**Is the 5.5 million-event dataset in SQLite?** No. It is a separate compressed training file. SQLite holds demo accounts, behavior profiles, live login attempts, and alerts. The Dataset & model tab reads summary and evaluation files.

**Is this real student data?** No. It is generated data with no real student identities or institutional logins. That protects privacy, but it limits external validity.

**Why use Isolation Forest?** It can learn the shape of normal behavior without attack labels. It is a supporting signal, while rules and OTP make most of the access decisions in this evaluation.

**Why not report “77.83% of stolen-password attacks stopped”?** The 77.83% figure is model recall across all attack events, including wrong-password bursts. Correct-password entry attempts are a different and harder subset. The full policy stopped 494 of 800 such entries under the OTP assumption.

**What does precision 22.25% mean?** Of the events the model flagged as anomalous in the all-event test, about 22.25% were labeled attacks by the simulator. It also flags normal events, which is why a flag is not automatically a hard block.

**Why is PR-AUC 0.740 in one place and 0.185 in another?** The first uses all events, including easier password-guessing bursts. The second uses correct-password decisions, where attacks are much rarer and often look normal. The denominators differ.

**Does the ML model really improve the policy?** The measured attacker-access rate moved from 39.5% with rules alone to 38.25% with rules plus the model. That small difference is within the uncertainty of this simulated test, so the claim is limited.

**Why not block every HIGH-risk login?** In an earlier simulated policy, that blocked 28.3% of genuine students at least once over the semester. The current policy uses OTP for behavior-only risk and blocks only when HIGH risk is paired with at least three recent password failures.

**What happens on a first login?** There is no personal history yet, so novelty penalties are skipped. Password and recent-failure checks still apply, and a baseline is built from allowed logins.

**Can the model learn from an attacker?** Only successful allowed logins and verified OTPs update the profile. An attacker allowed as LOW risk could still contaminate the baseline; the simulator includes that possibility.

**Why separate train, calibration, and test by student?** If the same student appeared in both training and test, the evaluation could benefit from prior exposure to that student's pattern. The held-out test uses unseen students.

**What is needed for a real deployment?** Real validation data with appropriate permissions, genuine OTP or passkey integration, stronger secret and session management, controlled CORS, trusted network/device signals, alert tuning, and operational monitoring.

## Source files for the numbers

- `ml/dataset/student_dataset_summary.json`: dataset size and composition.
- `ml/models/evaluation.json`: Isolation Forest metrics on held-out events.
- `ml/results/system_evaluation.json`: policy comparison, attacker entries, genuine-login friction, scenarios, and ranking metrics.
- `docs/ml.md`: method, assumptions, and interpretation.
