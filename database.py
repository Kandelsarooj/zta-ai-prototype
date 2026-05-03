# database.py
# Author: Saroj Kandel — MSc Software Engineering, UWL
# Purpose: Creates and manages SQLite database for all login logs

import sqlite3
from datetime import datetime

DB_NAME = 'security_logs.db'

def create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL,
            role            TEXT,
            device          TEXT,
            location        TEXT,
            time_of_day     TEXT,
            attempts_today  INTEGER DEFAULT 0,
            zta_result      TEXT,
            ai_risk_score   REAL    DEFAULT 0.0,
            final_decision  TEXT,
            access_level    TEXT    DEFAULT 'DENIED',
            attack_type     TEXT    DEFAULT 'normal',
            timestamp       TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_login(username, role, device, location, time_of_day,
               attempts_today, zta_result, ai_risk_score,
               final_decision, access_level='DENIED', attack_type='normal'):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO login_attempts
        (username, role, device, location, time_of_day, attempts_today,
         zta_result, ai_risk_score, final_decision, access_level, attack_type, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (username, role, device, location, time_of_day,
          attempts_today, zta_result, round(ai_risk_score, 2),
          final_decision, access_level, attack_type, timestamp))
    conn.commit()
    conn.close()

def get_all_logs(limit=50):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, role, device, location, zta_result,
               ai_risk_score, final_decision, access_level, attack_type, timestamp
        FROM login_attempts ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{'id':r[0],'username':r[1],'role':r[2],'device':r[3],
             'location':r[4],'zta_result':r[5],'ai_risk_score':r[6],
             'final_decision':r[7],'access_level':r[8],
             'attack_type':r[9],'timestamp':r[10]} for r in rows]

def get_statistics():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM login_attempts')
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE final_decision='GRANTED'")
    allowed = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE final_decision='DENIED'")
    blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE ai_risk_score >= 70")
    threats = cursor.fetchone()[0]
    cursor.execute("SELECT AVG(ai_risk_score) FROM login_attempts")
    avg = cursor.fetchone()[0] or 0.0
    conn.close()
    return {'total':total,'allowed':allowed,'blocked':blocked,'threats':threats,'avg_score':round(avg,1)}

def get_all_logs_csv():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM login_attempts ORDER BY id')
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_all_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM login_attempts')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_database()
    print("Database ready!")
