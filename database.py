# database.py
# ZTA + AI Security System — Saroj Kandel, MSc Software Engineering, UWL
import sqlite3
from datetime import datetime
import hashlib
import os

DB = 'zta_security.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'analyst',
        email TEXT,
        device TEXT DEFAULT 'managed_laptop',
        location TEXT DEFAULT 'London, UK',
        created_at TEXT,
        is_active INTEGER DEFAULT 1
    )''')

    # Login attempts table
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        role TEXT,
        device TEXT,
        location TEXT,
        ip_address TEXT,
        time_of_day TEXT,
        attempts_today INTEGER DEFAULT 0,
        zta_result TEXT,
        ai_risk_score REAL DEFAULT 0,
        final_decision TEXT,
        access_level TEXT DEFAULT 'DENIED',
        attack_type TEXT DEFAULT 'normal',
        alert_level TEXT DEFAULT 'INFO',
        timestamp TEXT
    )''')

    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        username TEXT,
        message TEXT,
        action_taken TEXT,
        ip_address TEXT,
        ai_score REAL,
        timestamp TEXT,
        acknowledged INTEGER DEFAULT 0
    )''')

    # Seed default users
    default_users = [
        ('alice', 'alice123', 'Alice Johnson', 'analyst', 'alice@company.com', 'managed_laptop', 'London, UK'),
        ('bob', 'bob123', 'Bob Smith', 'developer', 'bob@company.com', 'managed_laptop', 'London, UK'),
        ('carol', 'carol123', 'Carol White', 'admin', 'carol@company.com', 'office_desktop', 'Manchester, UK'),
        ('dave', 'dave123', 'Dave Brown', 'analyst', 'dave@company.com', 'managed_laptop', 'Bristol, UK'),
    ]
    for u in default_users:
        try:
            c.execute('''INSERT INTO users (username, password_hash, full_name, role, email, device, location, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (u[0], hash_password(u[1]), u[2], u[3], u[4], u[5], u[6], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except:
            pass

    conn.commit()
    conn.close()

def register_user(username, password, full_name, role, email, device, location):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users (username, password_hash, full_name, role, email, device, location, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (username, hash_password(password), full_name, role, email, device, location,
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return True, "User registered successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        conn.close()

def get_user(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'id': row[0], 'username': row[1], 'password_hash': row[2],
                'full_name': row[3], 'role': row[4], 'email': row[5],
                'device': row[6], 'location': row[7]}
    return None

def verify_password(username, password):
    user = get_user(username)
    if user and user['password_hash'] == hash_password(password):
        return True, user
    return False, None

def get_all_users():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT username, full_name, role, device, location, created_at FROM users WHERE is_active = 1')
    rows = c.fetchall()
    conn.close()
    return [{'username': r[0], 'full_name': r[1], 'role': r[2],
             'device': r[3], 'location': r[4], 'created_at': r[5]} for r in rows]

def save_login(username, role, device, location, ip_address, time_of_day,
               attempts_today, zta_result, ai_risk_score, final_decision,
               access_level='DENIED', attack_type='normal', alert_level='INFO'):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''INSERT INTO login_attempts
        (username, role, device, location, ip_address, time_of_day, attempts_today,
         zta_result, ai_risk_score, final_decision, access_level, attack_type, alert_level, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
             (username, role, device, location, ip_address, time_of_day, attempts_today,
              zta_result, round(ai_risk_score, 1), final_decision, access_level,
              attack_type, alert_level, timestamp))
    conn.commit()
    conn.close()

def save_alert(level, username, message, action_taken, ip_address, ai_score):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''INSERT INTO security_alerts (level, username, message, action_taken, ip_address, ai_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
             (level, username, message, action_taken, ip_address, ai_score,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_all_logs(limit=50):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''SELECT id, username, role, device, location, ip_address, zta_result,
                        ai_risk_score, final_decision, access_level, attack_type, alert_level, timestamp
                 FROM login_attempts ORDER BY id DESC LIMIT ?''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'username': r[1], 'role': r[2], 'device': r[3],
             'location': r[4], 'ip_address': r[5], 'zta_result': r[6],
             'ai_risk_score': r[7], 'final_decision': r[8], 'access_level': r[9],
             'attack_type': r[10], 'alert_level': r[11], 'timestamp': r[12]} for r in rows]

def get_alerts(limit=20):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''SELECT id, level, username, message, action_taken, ip_address, ai_score, timestamp, acknowledged
                 FROM security_alerts ORDER BY id DESC LIMIT ?''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'level': r[1], 'username': r[2], 'message': r[3],
             'action': r[4], 'ip': r[5], 'score': r[6], 'time': r[7], 'ack': r[8]} for r in rows]

def get_statistics():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM login_attempts')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM login_attempts WHERE final_decision='GRANTED'")
    allowed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM login_attempts WHERE final_decision='DENIED'")
    blocked = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM login_attempts WHERE ai_risk_score >= 70")
    threats = c.fetchone()[0]
    c.execute("SELECT AVG(ai_risk_score) FROM login_attempts")
    avg = c.fetchone()[0] or 0.0
    c.execute("SELECT COUNT(*) FROM security_alerts WHERE acknowledged = 0")
    unread = c.fetchone()[0]
    conn.close()
    return {'total': total, 'allowed': allowed, 'blocked': blocked,
            'threats': threats, 'avg_score': round(avg, 1), 'unread_alerts': unread}

def get_logs_csv():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT * FROM login_attempts ORDER BY id')
    rows = c.fetchall()
    conn.close()
    return rows

def clear_all_logs():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('DELETE FROM login_attempts')
    c.execute('DELETE FROM security_alerts')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_database()
    print("Database ready!")
