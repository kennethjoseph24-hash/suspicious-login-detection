# Testing

Run from `backend` (tests use a temporary SQLite database):

```bash
venv\Scripts\python -m pytest tests -q
```

Run the suite after changing the code; the test count can grow as features are added.

With both servers running, `python tools\smoke_check.py` checks model loading,
admin sign-in, the protected dataset endpoint, evaluation counts, live stats,
and the frontend. It records one demo admin login attempt.

| File | Covers |
|---|---|
| `test_auth.py` | Registration, duplicates, wrong password, first login, unknown user |
| `test_risk_and_otp.py` | Risk escalation, blocks, new devices, correct and wrong OTP, alert creation |
| `test_dashboard.py` | Stats, risk distribution, attempt list and detail |
| `test_context.py` | Campus, lab and external classification, forged tokens and headers, overnight windows, OTP expiry, reuse and guess limits, baseline learning only after verification |
| `test_hardening.py` | Admin-only access on all 9 security routes, forged tokens, lockout expiry, alert noise, behaviour-only OTP policy, browser updates |
| `test_simulator_parity.py` | The dataset simulator learns baselines the same way as production |

## Issues found during final evaluation

These were found and fixed before submission; each has a regression test.

| Issue | Effect | Fix |
|---|---|---|
| Failed-password count had no time limit | Eight wrong guesses by anyone locked a student out permanently | Failures count for 15 minutes |
| Every HIGH score was a hard block | 28.3% of real students blocked at least once per simulated semester | Behaviour alone earns an OTP; a block also needs 3+ failures |
| Browser and OS labels included versions | Every automatic browser update looked like a new browser | Compare families only |
| Security routes had no authentication | Anyone could read logins, resolve alerts or wipe demo data | Admin bearer token required |
| Alert for every wrong password | One typo raised a HIGH alert | One alert when failures reach three; verified OTPs close their alert |

## Manual checks

See the suggested demonstration in `ReadMe.txt`. Reset between runs with **Reset Demo Data**
on the dashboard and re-run `database/seed.py`, because successful logins change the
student's baseline.
