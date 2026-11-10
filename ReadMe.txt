CAMPUSGUARD: SUSPICIOUS LOGIN DETECTION FOR COLLEGE ERP SYSTEMS
Setup and run instructions
================================================================

FOLDER CONTENTS
  Final_Report.pdf   Project report
  ReadMe.txt         This file
  Code/              Full implementation (backend, frontend, ML, database, docs)
  Dataset/           Sample of the dataset, its summary, and how to get the full data


REQUIREMENTS
  - Extract the ZIP to a short path, such as C:\CG\
  - Python 3.11 (other versions may fail to install the pinned packages)
  - Node.js 18 or newer
  - No database install is needed. SQLite is the default.
  - No configuration file is needed for the default setup.
  - Commands below are for Windows. On Linux or macOS, replace
    venv\Scripts\ with venv/bin/ and use forward slashes.


STEP 1: SET UP THE BACKEND (first time only)
  Open a terminal in the Code folder, then run:

    cd backend
    python -m venv venv
    venv\Scripts\pip install -r requirements.txt
    venv\Scripts\python ..\database\seed.py

  seed.py creates the demo accounts and their login history. The trained model
  is already included at Code\ml\models\isolation_forest.joblib, so no training
  is needed to run the application.


STEP 2: START THE BACKEND
  From Code\backend:

    venv\Scripts\uvicorn app.main:app --port 8000

  Leave this terminal running.
  Check it works: http://localhost:8000/api/health should show
  "ml_model_loaded": true. API documentation: http://localhost:8000/docs


STEP 3: START THE FRONTEND
  Open a second terminal in the Code folder, then run:

    cd frontend
    npm install
    npm run dev

  Open http://localhost:3000 in a browser.

  Optional one-command check (from the Code folder, with both servers running):
    python tools\smoke_check.py
  It verifies model loading, admin access, the dataset summary and the dashboard.


STEP 4: USE THE APPLICATION
  Accounts:
    kenneth / Passw0rd!23     student with login history
    priya   / Passw0rd!23     student with login history
    admin   / AdminPass!23    administrator

  Suggested demonstration, signed in as kenneth on the Access Portal:
    1. Select "Campus Wi-Fi" and sign in           -> LOW risk, access allowed
    2. Click "Test OTP challenge" and sign in      -> MEDIUM risk, enter the code
                                                      shown on screen to continue
    3. Click "Test blocked login" and sign in      -> HIGH risk, access blocked
    4. Open Admin Dashboard and sign in as admin there -> events, reasons and alerts
    5. Select "Dataset & model" -> simulated student counts, test results and sample rows
    5. Students cannot open the dashboard: sign in as kenneth and try it.

  Location, device, hour and failed-attempt values on the portal are clearly
  labelled demo inputs. Use "Reset Demo Data" on the dashboard, then re-run
  seed.py, to return to a clean state.


RUN THE AUTOMATED TESTS
  From Code\backend:

    venv\Scripts\python -m pytest tests -q

  Tests use their own temporary SQLite database.


REPRODUCE THE DATASET, MODEL AND RESULTS (optional)
  From Code\backend. Needs about 4 GB of free RAM and 15 minutes:

    venv\Scripts\python ..\ml\training\generate_student_dataset.py
    venv\Scripts\python ..\ml\training\generate_dataset.py
    venv\Scripts\python ..\ml\training\train_model.py
    venv\Scripts\python ..\ml\training\evaluate_system.py

  The first command regenerates the full dataset exactly (fixed seed): 50,000
  students, 5.5 million login attempts, 107 MB compressed. Results are written to
  Code\ml\results and Code\ml\models.


ABOUT THE DATASET
  The dataset is SIMULATED. It contains no real student, login or attack records.
  No public dataset of real student logins could be used, so behaviour was simulated
  and passed through the production feature and risk code. Results describe the
  system under these scenarios and do not establish real-world accuracy.
  See Dataset\README_DATASET.txt and chapter 6 of the report.


OPTIONAL CONFIGURATION
  All settings have working defaults. To change them, copy Code\.env.example to
  Code\backend\.env and edit it. Settings include DATABASE_URL (PostgreSQL via
  docker-compose.yml is also supported), CAMPUS_IP_RANGES, LAB_DEVICE_TOKENS,
  FAILED_ATTEMPT_WINDOW_MINUTES, DEMO_CONTEXT_ENABLED and OTP_DEMO_MODE.


TROUBLESHOOTING
  Admin Dashboard asks for sign-in
      Sign in as admin on the Admin Dashboard page. Student accounts cannot view it.
  "ml_model_loaded": false
      Check that Code\ml\models\isolation_forest.joblib exists. Without it the
      system runs on rules alone.
  Frontend cannot reach the backend
      Check the backend is running on port 8000. The address is set in
      Code\frontend\.env.local.
  pip install fails, or "No module named sqlalchemy" appears
      Check "python --version" shows 3.11. Extract the ZIP to a short path such as
      C:\CG\ and try again, because Windows can fail on very long file paths.
      Delete the backend\venv folder before retrying.
