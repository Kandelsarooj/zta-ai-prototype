================================================
ZTA + AI CLOUD SECURITY PROTOTYPE — VERSION 4
================================================
Author    : Saroj Kandel
Student ID: 34114665
Course    : MSc Software Engineering
Module    : Research Methods (CP70011E)
University: University of West London
================================================

HOW TO RUN
================================================
Step 1 — Install libraries (only once):
  pip install flask scikit-learn numpy pandas

Step 2 — Go to the project folder:
  cd Desktop\zta_project_v4

Step 3 — Run the app:
  python app.py

Step 4 — Open your browser:
  http://127.0.0.1:5000

================================================
PAGES
================================================
Home          /           Choose a scenario
ZTA Checks    /zta-check  4 Zero Trust checks
AI Analysis   /ai-analysis  Risk scoring
Step-Up Auth  /step-up    Extra verification
Decision      /decision   Final result
Results       /results    All data + export CSV
About         /about      System explanation

================================================
ATTACK SCENARIOS
================================================
Normal Login    — alice / alice123 / managed_laptop / London
Brute Force     — 15 rapid attempts from unknown device
Insider Threat  — bob logs in at 2am (answer: DEV42)
Lateral Movement — rapid repeated attempts
Zero-Day        — unknown user, unregistered device

================================================
STEP-UP AUTHENTICATION ANSWERS
================================================
alice  — EMP001
bob    — DEV42
carol  — Smith
dave   — Bristol

================================================
