# Viva and presentation guide

## 60-second pitch

"A stolen password looks exactly like a real one. CampusGuard compares each login with
that student's own history and the network it came from, using explainable rules and an
Isolation Forest, then allows it, asks for an OTP, or blocks it. We tested it on a
simulated semester of 50,000 students. It stopped the foreign takeover, credential-stuffing,
and impossible-travel entries in our test set while prompting genuine logins about 2.3%
of the time. It does not stop attackers who look
like the student, such as a classmate on campus, and we measured and report that limit."

## Live demo order

1. Sign in as `kenneth` on **Campus Wi-Fi**: LOW, allowed.
2. **Test OTP challenge**: MEDIUM. Enter the code shown on screen.
3. **Test blocked login**: HIGH with repeated failures, blocked. Open "Why this decision?"
4. Open **Admin Dashboard** and sign in as `admin` there: stats, charts, alerts. Click an event.
5. Select **Dataset & model**: student counts, held-out results, confusion matrix, scenarios.
6. Sign in as `kenneth` and try the dashboard: refused. Access control works.

## Likely questions

**Why does the dashboard show 77.8% model recall but 38.2% attacker access?**
The 77.8% is the Isolation Forest flag rate over all attack events, including wrong-password
bursts. The 38.2% is the deployed policy's allow rate for 800 attacker entries with the
correct password. A model flag is not itself an access decision.

**Is this real student data?**
No. It is simulated, and we say so everywhere. No public real student login dataset could
be used; the closest, HIED-AuthLog, is embargoed until 23 December 2026. Real logs are also
personal data under India's DPDP Act 2023.

**Then what do your numbers prove?**
They show how the system behaves under stated scenarios, not real-world accuracy. Real
validation needs anonymised institutional logs.

**Why not use the earlier 99.98% result?**
That dataset sampled feature values directly, so attacks were separable by construction.
The same model scored 0.835 on realistic decisions. High scores on easy data prove little.

**Does the machine learning actually help?**
Barely, on these measures. Attacker access went from 39.5% to 38.2%, within the margin of
error, and showed no change in an independent run. Rules and OTP do most of the work. The
forest is cheap and may catch patterns rules miss, but it should not stand alone: its
results varied a lot between runs.

**Why Isolation Forest rather than a supervised model?**
It needs no attack labels, which a college rarely has. A supervised random forest did better
here (PR-AUC 0.426 against 0.185), but only because the simulator supplies perfect labels.

**Why can't it stop a classmate or a stolen laptop?**
Those logins have the same place, device and hours as the student, so the login signals
look normal. They need a different control, such as passkeys or MFA on sensitive actions.

**Why OTP rather than block for high risk?**
Blocking on behaviour alone locked out 28.3% of real students at least once a semester.
OTP keeps attackers out just as well under our assumptions, while letting a real student
continue. A block now needs repeated password failures too.

**What if the attacker also phishes the OTP?**
Our results assume they cannot, so real access rates would be higher. This is a stated
limitation. Phishing-resistant passkeys would address it.

**Why is PR-AUC so low if ROC-AUC is 0.84?**
Attacks are only 0.08% of the decisions, and PR-AUC depends heavily on that. Random guessing
scores about 0.0008, so 0.185 is over 200 times better than chance, but many flags are still
false alarms.

**How does a shared lab PC avoid false alarms?**
A registered lab token suppresses device, browser and OS novelty, and campus networks suppress
IP novelty. Failures, location and unusual hours still count.

**What stops an attacker claiming to be on campus?**
Context comes from the observed IP and a server-side device token. `X-Forwarded-For` is ignored,
and a token from outside campus earns no lab trust.

**How does the baseline avoid learning an attacker?**
Only allowed logins and verified OTPs update it. An attacker who passes as LOW can still poison
it, which the simulation models and we report.

**What happens on a first login?**
There is no history to compare, so novelty checks are skipped, but password failure checks still run.

**Is the OTP really sent?**
No, it is shown on screen in demo mode. Real delivery is deployment work.

**How much does this slow a login?**
In the latest local evaluation, ML plus rule scoring took 5.8 ms median and 15.4 ms
at the 95th percentile. Timing depends on the machine.

**What would you do next?**
Validate on real anonymised logs, add passkeys or MFA for sensitive actions, stronger device
identity, real geolocation, and a travel-time feature for impossible travel.
