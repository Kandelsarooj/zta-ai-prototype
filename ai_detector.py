# ai_detector.py — Isolation Forest Anomaly Detector
# Saroj Kandel, MSc Software Engineering, UWL
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Training data — 20 normal login patterns
# Features: [attempts_today, hour_of_day, device_trusted, location_trusted, login_speed]
NORMAL_LOGINS = np.array([
    [1,9,1,1,45],[1,10,1,1,60],[2,11,1,1,90],[1,8,1,1,55],[1,14,1,1,70],
    [2,15,1,1,80],[1,16,1,1,65],[1,9,1,1,50],[3,10,1,1,40],[1,13,1,1,75],
    [2,12,1,1,85],[1,17,1,1,60],[1,8,1,1,55],[2,9,1,1,70],[1,11,1,1,65],
    [1,14,1,1,80],[3,15,1,1,45],[1,10,1,1,90],[2,13,1,1,75],[1,16,1,1,60],
])

_scaler = StandardScaler()
_training = _scaler.fit_transform(NORMAL_LOGINS)
_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
_model.fit(_training)

FEATURE_LABELS = [
    'Login attempts today',
    'Time of login (hour)',
    'Device trust status',
    'Location trust status',
    'Login speed (seconds)'
]

def calculate_risk_score(attempts, hour, device_trusted, location_trusted, speed):
    features = np.array([[attempts, hour, device_trusted, location_trusted, speed]])
    scaled = _scaler.transform(features)
    raw = _model.score_samples(scaled)[0]
    risk = (raw + 0.8) / 0.6
    risk = 1.0 - risk
    risk = max(0.0, min(1.0, risk))
    score = round(risk * 100, 1)

    # Domain knowledge rule boosts
    if attempts >= 10:                          score = min(100, score + 40)
    if hour < 6 or hour > 22:
        if not device_trusted:                  score = min(100, score + 35)
    if not device_trusted and not location_trusted: score = min(100, score + 30)
    if speed < 3 and attempts > 3:              score = min(100, score + 45)

    return float(round(min(100.0, score), 1))

def get_risk_label(score):
    if score < 40:  return 'LOW',      'Normal behaviour pattern — no anomalies detected'
    if score < 60:  return 'MEDIUM',   'Slightly unusual behaviour detected'
    if score < 70:  return 'ELEVATED', 'Suspicious behaviour detected — step-up required'
    return 'CRITICAL', 'High-risk anomaly detected — access blocked'

def get_feature_analysis(attempts, hour, device_trusted, location_trusted, speed):
    items = []
    items.append({
        'name': 'Login attempts today',
        'value': str(attempts),
        'status': 'danger' if attempts > 5 else 'warning' if attempts > 2 else 'safe',
        'note': 'Excessive attempts detected' if attempts > 5 else 'Normal' if attempts <= 2 else 'Slightly elevated'
    })
    items.append({
        'name': 'Time of login',
        'value': f'{hour:02d}:00',
        'status': 'danger' if hour < 6 or hour > 22 else 'safe',
        'note': 'Outside working hours' if hour < 6 or hour > 22 else 'Within normal hours'
    })
    items.append({
        'name': 'Device trust',
        'value': 'Trusted' if device_trusted else 'Untrusted',
        'status': 'safe' if device_trusted else 'danger',
        'note': 'Registered managed device' if device_trusted else 'Unregistered device'
    })
    items.append({
        'name': 'Location',
        'value': 'Trusted' if location_trusted else 'Untrusted',
        'status': 'safe' if location_trusted else 'danger',
        'note': 'Approved region' if location_trusted else 'Outside approved regions'
    })
    items.append({
        'name': 'Login speed',
        'value': f'{speed}s',
        'status': 'danger' if speed < 3 else 'warning' if speed < 15 else 'safe',
        'note': 'Automated bot-like speed' if speed < 3 else 'Normal human speed' if speed >= 15 else 'Fast typing'
    })
    return items

def analyse_login(attempts, hour, device_trusted, location_trusted, speed=45):
    score = calculate_risk_score(attempts, hour, device_trusted, location_trusted, speed)
    label, description = get_risk_label(score)
    features = get_feature_analysis(attempts, hour, device_trusted, location_trusted, speed)
    return {
        'risk_score': float(score),
        'risk_label': str(label),
        'description': str(description),
        'flagged': bool(score >= 70),
        'features': features
    }
