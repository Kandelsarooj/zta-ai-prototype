# app.py — ZTA + AI Security System
# Saroj Kandel, MSc Software Engineering, UWL 2025
# Live: https://zta-ai-prototype.onrender.com

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from datetime import datetime
import csv, io, requests

from database import (create_database, register_user, get_user, verify_password,
                      get_all_users, save_login, save_alert, get_all_logs,
                      get_alerts, get_statistics, get_logs_csv, clear_all_logs)
from zta import run_zta_checks, TRUSTED_DEVICES, TRUSTED_LOCATIONS, ROLE_PERMISSIONS
from ai_detector import analyse_login

app = Flask(__name__)
app.secret_key = 'zta_saroj_uwl_2025_secure'
create_database()

# ── Scenarios ─────────────────────────────────────────────
SCENARIOS = {
    'normal':     {'label':'Normal User Login',   'desc':'A legitimate employee logs in during working hours from a trusted device.', 'username':'alice','password':'alice123','device':'managed_laptop','location':'London, UK','attempts':1,'hour':10,'speed':60,'type':'real_user'},
    'brute_force':{'label':'Brute Force Attack',  'desc':'An attacker tries 15 rapid login attempts with wrong credentials at 3am.','username':'attacker','password':'wrongpass','device':'unknown_vm','location':'Unknown Region','attempts':15,'hour':3,'speed':1,'type':'attack'},
    'insider':    {'label':'Insider Threat',       'desc':'A real employee logs in at 2am — suspicious behaviour detected by AI.','username':'bob','password':'bob123','device':'managed_laptop','location':'London, UK','attempts':2,'hour':2,'speed':45,'type':'real_user'},
    'lateral':    {'label':'Lateral Movement',    'desc':'An authenticated user rapidly attempts to access multiple restricted areas.','username':'dave','password':'dave123','device':'managed_laptop','location':'London, UK','attempts':8,'hour':14,'speed':5,'type':'real_user'},
    'zeroday':    {'label':'Zero-Day Attack',      'desc':'An unknown attacker uses an unregistered device sending suspicious payloads.','username':'unknown_user','password':'exploit_payload','device':'unregistered_device','location':'Tor Exit Node','attempts':20,'hour':4,'speed':0,'type':'attack'},
}

SECURITY_QA = {
    'alice': {'q': 'What is your employee ID?',        'a': 'EMP001'},
    'bob':   {'q': 'What is your department code?',    'a': 'DEV42'},
    'carol': {'q': "What is your manager's surname?",  'a': 'Smith'},
    'dave':  {'q': 'What city did you join from?',     'a': 'Bristol'},
}

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def get_location_from_ip(ip):
    try:
        if ip in ('127.0.0.1', 'localhost') or ip.startswith('192.168') or ip.startswith('10.'):
            return 'London, UK', ip
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=country,city,status', timeout=2)
        data = r.json()
        if data.get('status') == 'success':
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}", ip
    except:
        pass
    return 'London, UK', ip

def get_access_level(ai_score, zta_passed, role='analyst'):
    if not zta_passed or ai_score >= 70:
        return 'DENIED', []
    perms = ROLE_PERMISSIONS.get(role, [])
    if ai_score >= 50:
        limited = [p for p in perms if p in ['view_dashboard', 'view_alerts', 'read_reports']]
        return 'LIMITED', limited
    return 'FULL', perms

def create_alert(level, username, message, action, ip, score):
    save_alert(level, username, message, action, ip, score)

# ── PAGES ──────────────────────────────────────────────────

@app.route('/')
def home():
    stats = get_statistics()
    logs = get_all_logs(8)
    alerts = get_alerts(5)
    return render_template('home.html', scenarios=SCENARIOS, stats=stats, logs=logs, alerts=alerts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        ok, msg = register_user(
            data['username'], data['password'], data['full_name'],
            data['role'], data['email'], data['device'], data['location']
        )
        return jsonify({'success': ok, 'message': msg})
    return render_template('register.html',
        roles=list(ROLE_PERMISSIONS.keys()),
        devices=TRUSTED_DEVICES,
        locations=TRUSTED_LOCATIONS)

@app.route('/users')
def users():
    all_users = get_all_users()
    return render_template('users.html', users=all_users)

@app.route('/zta-check/<scenario_key>')
def zta_check(scenario_key):
    if scenario_key not in SCENARIOS and scenario_key != 'custom':
        return redirect(url_for('home'))
    session['scenario_key'] = scenario_key
    session.pop('zta_result', None)
    session.pop('ai_result', None)
    session.pop('stepup_passed', None)
    sc = SCENARIOS.get(scenario_key, {})
    ip = get_client_ip()
    real_location, _ = get_location_from_ip(ip)
    session['client_ip'] = ip
    session['real_location'] = real_location
    return render_template('zta_check.html', scenario=sc, key=scenario_key,
                           client_ip=ip, real_location=real_location)

@app.route('/api/run-zta', methods=['POST'])
def run_zta():
    data = request.get_json()
    sk = data.get('scenario_key')
    sc = SCENARIOS.get(sk)
    if not sc:
        return jsonify({'error': 'Invalid scenario'}), 400
    user_data = get_user(sc['username'])
    result = run_zta_checks(sc['username'], sc['password'], sc['device'], sc['location'], user_data)
    session['zta_result'] = result
    return jsonify({'passed': result['passed'], 'checks': result['checks'],
                    'message': result['message'], 'role': result.get('role')})

@app.route('/ai-analysis')
def ai_analysis():
    sk = session.get('scenario_key')
    if not sk:
        return redirect(url_for('home'))
    sc = SCENARIOS.get(sk)
    if not sc:
        return redirect(url_for('home'))
    return render_template('ai_analysis.html', scenario=sc, key=sk)

@app.route('/api/run-ai-direct/<scenario_key>', methods=['GET'])
def run_ai_direct(scenario_key):
    """Fallback direct route if session is lost"""
    sc = SCENARIOS.get(scenario_key)
    if not sc:
        return jsonify({'error': 'Invalid scenario'}), 400
    session['scenario_key'] = scenario_key
    dt = 1 if sc['device'] in TRUSTED_DEVICES else 0
    lt = 1 if sc['location'] in TRUSTED_LOCATIONS else 0
    result = analyse_login(sc['attempts'], sc['hour'], dt, lt, sc['speed'])
    session['ai_result'] = result
    return jsonify(result)

@app.route('/api/run-ai', methods=['POST'])
def run_ai():
    data = request.get_json()
    sk = data.get('scenario_key')
    sc = SCENARIOS.get(sk)
    if not sc:
        return jsonify({'error': 'Invalid scenario'}), 400
    dt = 1 if sc['device'] in TRUSTED_DEVICES else 0
    lt = 1 if sc['location'] in TRUSTED_LOCATIONS else 0
    result = analyse_login(sc['attempts'], sc['hour'], dt, lt, sc['speed'])
    session['ai_result'] = result
    return jsonify(result)

@app.route('/step-up')
def step_up():
    sk = session.get('scenario_key')
    ai = session.get('ai_result')
    if not sk or not ai:
        return redirect(url_for('home'))
    sc = SCENARIOS[sk]
    qa = SECURITY_QA.get(sc['username'], {'q': 'What is your employee code?', 'a': 'N/A'})
    return render_template('step_up.html', scenario=sc, key=sk,
                           question=qa['q'], ai_score=ai['risk_score'])

@app.route('/api/verify-stepup', methods=['POST'])
def verify_stepup():
    data = request.get_json()
    sk = session.get('scenario_key')
    sc = SCENARIOS.get(sk, {})
    answer = data.get('answer', '').strip()
    qa = SECURITY_QA.get(sc.get('username', ''), {'a': ''})
    passed = answer.lower() == qa['a'].lower()
    session['stepup_passed'] = passed
    return jsonify({'passed': passed})

@app.route('/decision')
def decision():
    sk = session.get('scenario_key')
    zta = session.get('zta_result')
    ai = session.get('ai_result')
    stp = session.get('stepup_passed', None)
    if not sk or not zta or not ai:
        return redirect(url_for('home'))
    sc = SCENARIOS[sk]
    ai_score = ai['risk_score']
    zta_ok = zta['passed']
    role = zta.get('role', 'analyst')
    access_level, permissions = get_access_level(ai_score, zta_ok, role)
    if access_level == 'LIMITED' and stp is False:
        access_level = 'DENIED'
        permissions = []
    final = 'DENIED' if access_level == 'DENIED' else 'GRANTED'

    # Alert level
    if not zta_ok or ai_score >= 70:
        alert_level = 'CRITICAL'
        alert_msg = f"High-risk login blocked — {sc['username']} — AI score {ai_score}"
        alert_action = "Access denied — security team notified"
        create_alert('CRITICAL', sc['username'], alert_msg, alert_action,
                     session.get('client_ip', ''), ai_score)
    elif ai_score >= 50:
        alert_level = 'WARNING'
        alert_msg = f"Suspicious login detected — {sc['username']} at {sc['hour']:02d}:00 — score {ai_score}"
        alert_action = "Step-up authentication triggered — limited access granted"
        create_alert('WARNING', sc['username'], alert_msg, alert_action,
                     session.get('client_ip', ''), ai_score)
    else:
        alert_level = 'INFO'
        alert_msg = f"Normal login — {sc['username']} — score {ai_score}"
        alert_action = "Full access granted"

    dt = 1 if sc['device'] in TRUSTED_DEVICES else 0
    lt = 1 if sc['location'] in TRUSTED_LOCATIONS else 0
    save_login(sc['username'], role, sc['device'], sc['location'],
               session.get('client_ip', ''), f"{sc['hour']:02d}:00",
               sc['attempts'], 'PASS' if zta_ok else 'FAIL',
               ai_score, final, access_level, sk, alert_level)

    stats = get_statistics()
    logs = get_all_logs(20)
    all_perms = [('view_dashboard','View Dashboard'), ('read_reports','Read Reports'),
                 ('view_alerts','View Alerts'), ('view_logs','View Logs'),
                 ('access_dev_tools','Dev Tools'), ('download_files','Downloads'),
                 ('edit_data','Edit Data'), ('manage_users','Manage Users'),
                 ('system_settings','Settings')]
    return render_template('decision.html',
        scenario=sc, key=sk, zta_result=zta, ai_result=ai,
        final=final, access_level=access_level, permissions=permissions,
        alert_level=alert_level, alert_msg=alert_msg, alert_action=alert_action,
        stepup_passed=stp, stats=stats, logs=logs, all_perms=all_perms)

@app.route('/alerts')
def alerts_page():
    alerts = get_alerts(50)
    stats = get_statistics()
    return render_template('alerts.html', alerts=alerts, stats=stats)

@app.route('/results')
def results():
    logs = get_all_logs(100)
    stats = get_statistics()
    return render_template('results.html', logs=logs, stats=stats)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/export-csv')
def export_csv():
    rows = get_logs_csv()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['ID','Username','Role','Device','Location','IP','Time','Attempts',
                'ZTA Result','AI Score','Decision','Access Level','Attack Type','Alert Level','Timestamp'])
    w.writerows(rows)
    resp = make_response(out.getvalue())
    resp.headers['Content-Disposition'] = 'attachment; filename=zta_ai_results.csv'
    resp.headers['Content-type'] = 'text/csv'
    return resp

@app.route('/reset')
def reset():
    clear_all_logs()
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("=" * 60)
    print("  ZTA + AI Security System — Saroj Kandel — UWL 2025")
    print("  Browser: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)
