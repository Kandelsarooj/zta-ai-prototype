# app.py
# Author: Saroj Kandel — MSc Software Engineering, UWL
# Purpose: Main Flask web application — connects ZTA, AI, database and dashboard

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from datetime import datetime
import csv, io

from database    import create_database, save_login, get_all_logs, get_statistics, clear_all_logs, get_all_logs_csv
from zta         import run_zta_checks
from ai_detector import analyse_login

app = Flask(__name__)
app.secret_key = 'zta_saroj_uwl_2025'
create_database()

SCENARIOS = {
    'normal': {
        'label': 'Normal User Login',
        'description': 'A legitimate employee logs in during working hours from a trusted device.',
        'icon': '✅', 'color': '#1877f2',
        'username': 'alice', 'password': 'alice123',
        'device': 'managed_laptop', 'location': 'London, UK',
        'attempts_today': 1, 'hour_of_day': 10, 'login_speed': 60,
    },
    'brute_force': {
        'label': 'Brute Force Attack',
        'description': 'An attacker tries to guess a password with 15 rapid login attempts.',
        'icon': '💥', 'color': '#fa383e',
        'username': 'attacker', 'password': 'wrongpassword',
        'device': 'unknown_vm', 'location': 'Unknown Region',
        'attempts_today': 15, 'hour_of_day': 3, 'login_speed': 1,
    },
    'insider': {
        'label': 'Insider Threat',
        'description': 'A real employee logs in at 2am — unusual behaviour detected by AI.',
        'icon': '😈', 'color': '#f0a500',
        'username': 'bob', 'password': 'bob123',
        'device': 'managed_laptop', 'location': 'London, UK',
        'attempts_today': 2, 'hour_of_day': 2, 'login_speed': 45,
    },
    'lateral': {
        'label': 'Lateral Movement',
        'description': 'An authenticated user rapidly tries to access restricted system areas.',
        'icon': '➡️', 'color': '#e09000',
        'username': 'dave', 'password': 'dave123',
        'device': 'managed_laptop', 'location': 'London, UK',
        'attempts_today': 8, 'hour_of_day': 14, 'login_speed': 5,
    },
    'zeroday': {
        'label': 'Zero-Day Attack',
        'description': 'An unknown attacker uses an unregistered device with a suspicious payload.',
        'icon': '⚠️', 'color': '#822727',
        'username': 'unknown_user', 'password': 'exploit_payload',
        'device': 'unregistered_device', 'location': 'Tor Exit Node',
        'attempts_today': 20, 'hour_of_day': 4, 'login_speed': 0,
    },
}

SECURITY_QUESTIONS = {
    'alice': {'question': "What is your employee ID?",       'answer': 'EMP001'},
    'bob':   {'question': "What is your department code?",   'answer': 'DEV42'},
    'carol': {'question': "What is your manager's surname?", 'answer': 'Smith'},
    'dave':  {'question': "What city did you join from?",    'answer': 'Bristol'},
}

TRUSTED_DEVICES   = ['managed_laptop','company_phone','office_desktop','managed_tablet']
TRUSTED_LOCATIONS = ['London, UK','Manchester, UK','Birmingham, UK','Edinburgh, UK','Bristol, UK']

def get_access_level(ai_score, zta_passed):
    if not zta_passed or ai_score >= 70:
        return 'DENIED', []
    elif ai_score >= 31:
        return 'LIMITED', ['view_dashboard','read_reports']
    else:
        return 'FULL', ['view_dashboard','read_reports','download_files','edit_data','manage_settings','manage_users']

def generate_alert(username, ai_score, hour):
    if ai_score >= 50 and ai_score < 70:
        return {'level':'WARNING','message':f"Unusual login — {username} at {hour}:00 with risk score {ai_score}",'action':'Step-up authentication triggered','time':datetime.now().strftime("%H:%M:%S")}
    if ai_score >= 70:
        return {'level':'CRITICAL','message':f"High risk login BLOCKED — {username} — AI score {ai_score}",'action':'Access denied — security team notified','time':datetime.now().strftime("%H:%M:%S")}
    return {'level':'INFO','message':f"Normal login — {username} — no suspicious activity detected",'action':'Access granted normally','time':datetime.now().strftime("%H:%M:%S")}

# ── PAGES ────────────────────────────────────────────────────

@app.route('/')
def home():
    stats  = get_statistics()
    logs   = get_all_logs(10)
    return render_template('home.html', scenarios=SCENARIOS, stats=stats, logs=logs)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/zta-check/<scenario_key>')
def zta_check(scenario_key):
    if scenario_key not in SCENARIOS:
        return redirect(url_for('home'))
    session['scenario_key'] = scenario_key
    session.pop('zta_result', None)
    session.pop('ai_result', None)
    session.pop('alerts', None)
    session.pop('stepup_passed', None)
    return render_template('zta_check.html', scenario=SCENARIOS[scenario_key], key=scenario_key)

@app.route('/api/run-zta', methods=['POST'])
def run_zta():
    data = request.get_json()
    sk   = data.get('scenario_key')
    sc   = SCENARIOS.get(sk)
    if not sc: return jsonify({'error': 'Invalid scenario'}), 400
    result = run_zta_checks(sc['username'], sc['password'], sc['device'], sc['location'])
    session['zta_result']   = result
    session['scenario_key'] = sk
    return jsonify({'passed': result['passed'], 'checks': result['checks'], 'message': result['message'], 'role': result.get('role')})

@app.route('/ai-analysis')
def ai_analysis():
    sk = session.get('scenario_key')
    if not sk: return redirect(url_for('home'))
    return render_template('ai_analysis.html', scenario=SCENARIOS[sk], key=sk)

@app.route('/api/run-ai', methods=['POST'])
def run_ai():
    data = request.get_json()
    sk   = data.get('scenario_key')
    sc   = SCENARIOS.get(sk)
    if not sc: return jsonify({'error': 'Invalid scenario'}), 400
    dt = 1 if sc['device']   in TRUSTED_DEVICES   else 0
    lt = 1 if sc['location'] in TRUSTED_LOCATIONS else 0
    result = analyse_login(sc['attempts_today'], sc['hour_of_day'], dt, lt, sc['login_speed'])
    session['ai_result'] = result
    return jsonify(result)

@app.route('/step-up')
def step_up():
    sk = session.get('scenario_key')
    ai = session.get('ai_result')
    if not sk or not ai: return redirect(url_for('home'))
    sc   = SCENARIOS[sk]
    sq   = SECURITY_QUESTIONS.get(sc['username'], {'question': 'What is your employee code?', 'answer': 'N/A'})
    return render_template('step_up.html', scenario=sc, key=sk, question=sq['question'], ai_score=ai['risk_score'])

@app.route('/api/verify-stepup', methods=['POST'])
def verify_stepup():
    data     = request.get_json()
    sk       = session.get('scenario_key')
    sc       = SCENARIOS.get(sk, {})
    username = sc.get('username', '')
    answer   = data.get('answer', '').strip()
    sq       = SECURITY_QUESTIONS.get(username, {'answer': ''})
    passed   = answer.lower() == sq['answer'].lower()
    session['stepup_passed'] = passed
    return jsonify({'passed': passed})

@app.route('/decision')
def decision():
    sk  = session.get('scenario_key')
    zta = session.get('zta_result')
    ai  = session.get('ai_result')
    stp = session.get('stepup_passed', None)
    if not sk or not zta or not ai: return redirect(url_for('home'))
    sc       = SCENARIOS[sk]
    ai_score = ai['risk_score']
    zta_ok   = zta['passed']
    access_level, permissions = get_access_level(ai_score, zta_ok)
    if access_level == 'LIMITED' and stp is False:
        access_level = 'DENIED'; permissions = []
    final = 'DENIED' if access_level == 'DENIED' else 'GRANTED'
    alert = generate_alert(sc['username'], ai_score, sc['hour_of_day'])
    dt = 1 if sc['device']   in TRUSTED_DEVICES   else 0
    lt = 1 if sc['location'] in TRUSTED_LOCATIONS else 0
    save_login(
        username=sc['username'], role=zta.get('role','none'),
        device=sc['device'], location=sc['location'],
        time_of_day=f"{sc['hour_of_day']:02d}:00",
        attempts_today=sc['attempts_today'],
        zta_result='PASS' if zta_ok else 'FAIL',
        ai_risk_score=ai_score, final_decision=final,
        access_level=access_level, attack_type=sk
    )
    stats = get_statistics()
    logs  = get_all_logs(30)
    return render_template('decision.html',
        scenario=sc, scenario_key=sk, zta_result=zta,
        ai_result=ai, final=final, access_level=access_level,
        permissions=permissions, alert=alert,
        stepup_passed=stp, stats=stats, logs=logs)

@app.route('/results')
def results():
    logs  = get_all_logs(100)
    stats = get_statistics()
    return render_template('results.html', logs=logs, stats=stats)

@app.route('/export-csv')
def export_csv():
    rows = get_all_logs_csv()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID','Username','Role','Device','Location','Time','Attempts','ZTA Result','AI Score','Final Decision','Access Level','Attack Type','Timestamp'])
    writer.writerows(rows)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=zta_ai_results.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/reset')
def reset():
    clear_all_logs()
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("=" * 55)
    print("  ZTA + AI Prototype v4 — Saroj Kandel — UWL")
    print("  Open browser:  http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True, port=5000)

# Production entry point
application = app
