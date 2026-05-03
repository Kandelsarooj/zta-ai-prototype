# ai_detector.py
# Author: Saroj Kandel — MSc Software Engineering, UWL
# Purpose: AI anomaly detection using Isolation Forest (scikit-learn)

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

def calculate_risk_score(attempts_today, hour_of_day, device_trusted, location_trusted, login_speed):
    features = np.array([[attempts_today, hour_of_day, device_trusted, location_trusted, login_speed]])
    features_scaled = _scaler.transform(features)
    raw = _model.score_samples(features_scaled)[0]
    risk = (raw + 0.8) / 0.6
    risk = 1.0 - risk
    risk = max(0.0, min(1.0, risk))
    score = round(risk * 100, 1)
    # Rule-based boosts
    if attempts_today >= 10:              score = min(100, score + 40)
    if (hour_of_day < 6 or hour_of_day > 22) and device_trusted == 0:
                                          score = min(100, score + 35)
    if device_trusted == 0 and location_trusted == 0:
                                          score = min(100, score + 30)
    if login_speed < 3 and attempts_today > 3:
                                          score = min(100, score + 45)
    return round(min(100.0, score), 1)

def get_risk_label(score):
    if score < 30:  return 'LOW'
    if score < 70:  return 'MEDIUM'
    return 'HIGH'

def analyse_login(attempts_today, hour_of_day, device_trusted, location_trusted, login_speed=45):
    score = calculate_risk_score(attempts_today, hour_of_day, device_trusted, location_trusted, login_speed)
    label = get_risk_label(score)
    return {
        'risk_score': score, 'risk_label': label, 'flagged': score >= 70,
        'features': {
            'attempts_today': attempts_today, 'hour_of_day': hour_of_day,
            'device_trusted': device_trusted, 'location_trusted': location_trusted,
            'login_speed': login_speed
        }
    }
