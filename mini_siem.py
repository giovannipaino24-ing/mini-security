#!/usr/bin/env python3
"""Mini-SIEM semplice:
- legge file di log (formato personalizzato o syslog-like)
- estrae timestamp, livello, source, message, ip
- salva eventi in SQLite
- esporta CSV riepilogativo
- genera grafico con matplotlib (eventi per livello)
"""
import re
import sqlite3
import csv
from datetime import datetime
import argparse
import os
import matplotlib.pyplot as plt  # usa matplotlib (non specificare colori)

LOG_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<level>[A-Z]+)\]\s+(?P<src>[\w\-\.]+):\s+(?P<msg>.*)$'
)
IP_RE = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?!$)|$)){4}')

DB_FILE = 'mini_siem.db'

def init_db(db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            level TEXT,
            src TEXT,
            ip TEXT,
            msg TEXT
        )
    ''')
    conn.commit()
    return conn

def parse_log_line(line):
    m = LOG_LINE_RE.match(line.strip())
    if not m:
        return None
    ts = m.group('ts')
    level = m.group('level')
    src = m.group('src')
    msg = m.group('msg')
    ip_match = IP_RE.search(msg)
    ip = ip_match.group(0) if ip_match else None
    return {
        'ts': ts,
        'level': level,
        'src': src,
        'ip': ip,
        'msg': msg
    }

def ingest_file(path, conn):
    cur = conn.cursor()
    inserted = 0
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                cur.execute('INSERT INTO events (ts, level, src, ip, msg) VALUES (?, ?, ?, ?, ?)',
                            (parsed['ts'], parsed['level'], parsed['src'], parsed['ip'], parsed['msg']))
                inserted += 1
    conn.commit()
    return inserted

def export_csv(conn, out_path='siem_export.csv'):
    cur = conn.cursor()
    cur.execute('SELECT ts, level, src, ip, msg FROM events ORDER BY ts')
    rows = cur.fetchall()
    with open(out_path, 'w', newline='', encoding='utf-8') as csvf:
        w = csv.writer(csvf)
        w.writerow(['timestamp', 'level', 'source', 'ip', 'message'])
        w.writerows(rows)
    return out_path

def plot_event_counts(conn, out_image='events_by_level.png'):
    cur = conn.cursor()
    cur.execute('SELECT level, COUNT(*) FROM events GROUP BY level ORDER BY COUNT(*) DESC')
    data = cur.fetchall()
    if not data:
        print('Nessun dato per grafico.')
        return None
    levels = [r[0] for r in data]
    counts = [r[1] for r in data]
    plt.figure(figsize=(8,4))
    plt.bar(levels, counts)
    plt.title('Eventi per livello')
    plt.xlabel('Livello')
    plt.ylabel('Conteggio')
    plt.tight_layout()
    plt.savefig(out_image)
    plt.close()
    return out_image

def simple_alerts(conn, threshold_per_ip=10):
    """Esempio di regola: se una IP ha più di threshold eventi, segnala."""
    cur = conn.cursor()
    cur.execute('SELECT ip, COUNT(*) AS c FROM events WHERE ip IS NOT NULL GROUP BY ip HAVING c > ?', (threshold_per_ip,))
    return cur.fetchall()

def main():
    ap = argparse.ArgumentParser(description='Mini-SIEM ingest')
    ap.add_argument('--log', required=True, help='File di log da processare')
    ap.add_argument('--db', default=DB_FILE, help='File sqlite')
    ap.add_argument('--export', default='siem_export.csv', help='CSV di output')
    ap.add_argument('--plot', default='events_by_level.png', help='Grafico PNG di output')
    args = ap.parse_args()

    conn = init_db(args.db)
    n = ingest_file(args.log, conn)
    print(f'Inseriti {n} eventi in {args.db}')
    csv_path = export_csv(conn, args.export)
    print(f'Esportato CSV: {csv_path}')
    img = plot_event_counts(conn, args.plot)
    if img:
        print(f'Grafico salvato in: {img}')
    alerts = simple_alerts(conn)
    if alerts:
        print('ALERT: IP con molti eventi (ip, count):')
        for a in alerts:
            print(a)
    else:
        print('Nessun alert dalla regola semplice.')

if __name__ == '__main__':
    main()
