# CampusGuard: Suspicious Login Detection for College ERP Systems

An academic prototype that adds a behavioural security layer on top of passwords.
Each login is compared with the student's own history and the network it came
from, then allowed, challenged with an OTP, or blocked, with a stated reason.

## Results at a glance

Evaluated on 10,000 held-out students from a **simulated** semester of 50,000
students and 5.5 million login attempts. These figures describe the system under
hand-designed scenarios. They do not establish real-world accuracy.

| Policy | Attackers with the right password let in | Real logins prompted for OTP | Students wrongly blocked per semester |
|---|---|---|---|
| Password only | 100% | 0% | 0% |
| Isolation Forest only | 50.9% | 0.54% | 0% |
| Rules only | 39.5% | 2.16% | 8.8% |
| **Rules + Isolation Forest (deployed)** | **38.2%** | **2.28%** | **10.1%** |

- Remote attackers were all stopped: 0 of 308 foreign takeover, credential stuffing,
  brute force and impossible travel logins got through.
- Attackers who resemble the student mostly get in: insider peer 79%, stolen device
  99%, lab shoulder-surfing 100%. Context signals alone cannot stop these.
- The Isolation Forest adds little over the rules (the difference is within the
  margin of error), and on its own it is unstable between runs. Rules and OTP do
  most of the work.

Details: [docs/ml.md](docs/ml.md) and `ml/results/system_evaluation.json`.

## How a login is decided

1. **Context:** campus network, registered lab device or external connection, from
   configured IP ranges and a device token.
2. **Features:** eight signals comparing the attempt with the student's profile.
3. **Score:** explainable rules, plus 20 points if the Isolation Forest flags it.
4. **Action:**

| Score | Level | Action |
|---|---|---|
| 0-30 | LOW | Allow |
| 31-60 | MEDIUM | OTP |
| 61-100 | HIGH | OTP, or block if there are also 3+ recent password failures |

A wrong password always fails. Failures older than 15 minutes stop counting, so
guessing cannot lock a student out permanently. Only allowed logins and verified
OTPs update the student's baseline.

## Run it

Needs Python 3.11 and Node.js 18+. SQLite is the default, so no database or `.env`
file is required. Full instructions: [ReadMe.txt](ReadMe.txt) or
[docs/setup.md](docs/setup.md).

```bash
cd backend
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python ..\database\seed.py
venv\Scripts\uvicorn app.main:app --port 8000

# second terminal
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. API docs: http://localhost:8000/docs

With both servers running, check the demo in one command from the project root:

```powershell
python tools\smoke_check.py
```

This signs in once with the seeded demo administrator and verifies the protected
dataset view, held-out counts, live dashboard, and frontend.

After signing in as admin on the dashboard, open **Dataset & model** to see the
simulated student dataset summary, held-out evaluation, policy comparison, and
sample records. **Live activity** shows logins stored in the application database.

| Username | Password | Role |
|---|---|---|
| kenneth | Passw0rd!23 | student with 18 days of Hyderabad history |
| priya | Passw0rd!23 | student with Bangalore history |
| admin | AdminPass!23 | administrator; sign in directly on the dashboard |

## Reproduce the results

```bash
cd backend
venv\Scripts\python ..\ml\training\generate_student_dataset.py   # about 90 seconds, 107 MB
venv\Scripts\python ..\ml\training\generate_dataset.py           # legacy baseline for comparison
venv\Scripts\python ..\ml\training\train_model.py                # about 5 minutes
venv\Scripts\python ..\ml\training\evaluate_system.py            # about 5 minutes, needs 4 GB+ free RAM
venv\Scripts\python -m pytest tests -q
```

## Repository layout

```
backend/    FastAPI app: api, services (risk engine, login flow), ml, security, tests
frontend/   Next.js app: access portal, admin dashboard, attempt detail
ml/
  training/ student simulator, training, evaluation, legacy generator
  dataset/  simulated data (the full log is generated, a sample is included)
  models/   trained Isolation Forest and its metrics
  results/  system evaluation JSON and figures
database/   schema.sql, seed.py
docs/       architecture, API, ML, setup, context/security, testing, viva guide
```

## Known limitations

- All evaluation data is simulated. Validate on anonymised institutional logs before
  claiming real-world performance.
- Location comes from the demo picker; no live IP geolocation is connected.
- OTP is shown on screen in demo mode. Real SMS or email delivery is not connected.
- Device labels are coarse, so similar devices cannot be told apart.
- Disable `DEMO_CONTEXT_ENABLED` and `OTP_DEMO_MODE`, set a strong `JWT_SECRET_KEY`
  and restrict CORS before any real deployment.
