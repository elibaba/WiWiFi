import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "wiwifi.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_mac TEXT,
            dst_ip TEXT,
            payload TEXT,
            analysis_tags TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_packet(src_ip, src_mac, dst_ip, payload, analysis_tags):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, src_mac, dst_ip, payload, analysis_tags)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), src_ip, src_mac, dst_ip, payload, json.dumps(analysis_tags)))
    conn.commit()
    conn.close()

def search_packets(query=None, mac=None, ip=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    sql = "SELECT * FROM packets WHERE 1=1"
    params = []
    
    if query:
        sql += " AND payload LIKE ?"
        params.append(f"%{query}%")
    if mac:
        sql += " AND src_mac = ?"
        params.append(mac)
    if ip:
        sql += " AND src_ip = ?"
        params.append(ip)
        
    sql += " ORDER BY timestamp DESC LIMIT 500"
    
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "timestamp": row[1],
            "src_ip": row[2],
            "src_mac": row[3],
            "dst_ip": row[4],
            "payload": row[5],
            "analysis_tags": json.loads(row[6])
        })
    return results

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
