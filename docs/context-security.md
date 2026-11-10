# Context-aware college ERP login detection

The backend classifies network context before feature engineering, Isolation
Forest scoring, and rule evaluation. The resulting decision, context, reasons,
and effective ML features are stored with each login event.

## Context classification

1. Parse the observed client IP and match configured `CAMPUS_IP_RANGES` CIDRs.
2. On a campus network, match `X-Lab-Device-Token` against the server's
   `LAB_DEVICE_TOKENS` registry. A matching token means Laboratory Device;
   otherwise the context is Campus Network.
3. All other connections are External Connection. Invalid IPs fail closed
   to this classification. A lab token outside campus does not establish lab trust.

Do not identify a trusted lab computer from its User-Agent or display name.
Device credentials should be provisioned through an institutional device
agent or trusted gateway over HTTPS, never bundled in frontend JavaScript.
In demo mode only, `lab-pc-01` simulates a registered device on a campus IP.
The supplied 192.0.2.0/24 campus range is a documentation/demo subnet;
replace it with the institution's actual observed egress ranges.

The application does not trust arbitrary X-Forwarded-For headers. If deployed
behind a reverse proxy, configure the ASGI server to trust only that proxy.

## Context-specific treatment

Campus IP novelty is suppressed in both model inputs and rules. For registered
lab computers, device, browser, and OS novelty are suppressed too. Location,
time, password failures, and bursts combined with failures still matter.
External logins retain all novelty checks. Shared context never bypasses the
password check or the repeated-failure block threshold.

## Decisions and learning

Scores 0–30 allow access and 31–60 require OTP. Scores 61–100 also require OTP,
or are blocked if there are three or more recent password failures. Behaviour
alone never causes a hard block, because that locked out 28.3% of genuine students
per simulated semester (see `docs/ml.md`).
Incorrect passwords always fail. Failures count for 15 minutes, so guessing cannot
lock a student out permanently. Three recent failures require at least OTP.
Eight or more recent failed passwords trigger
a high-risk block even for a new user. Users without history do not receive
personal novelty penalties, but failure checks stay active.

Allowed logins update the baseline once. OTP challenges are recorded as pending
and update it only after successful verification. Blocked and failed logins do
not update trusted history. OTPs expire after five minutes by default, allow
five guesses, and cannot be reused. Original challenge actions remain in the
audit record after OTP verification; the outcome becomes success.

## Model evaluation

Generate the simulated student dataset, then train the model using the commands
in README.md. Students are split 60/20/20 into training, calibration and test sets. A
100-tree Isolation Forest is trained on normal training events. Separate thresholds
for each context target a 1% normal calibration false-positive rate. Test data
never selects these thresholds. See `docs/ml.md` for the full evaluation.

The anomaly score is a percentile relative to normal calibration scores, not
an attack probability. Rule reasons explain decisions; they are not claimed
to be exact feature contributions of the forest. Labels reflect generated
scenarios, not independently verified real attacks. Validate on anonymized,
time-separated institutional data before claiming real-world accuracy.

## Prototype boundaries

Location is simulated when supplied by demo controls and otherwise unknown;
there is no live geolocation provider. OTP delivery is a local demo response,
not a real email or SMS integration. Disable `DEMO_CONTEXT_ENABLED` before
connecting real traffic. Also wire real OTP delivery, restrict CORS,
and replace development credentials before institutional deployment.
