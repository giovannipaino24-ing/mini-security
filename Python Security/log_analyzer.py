#!/usr/bin/env python3
"""Analizzatore di log con:
- parsing (usa il parser del mini-siem o regex personalizzate)
- rilevamento IOC (lista di IP/URL/hash)
- threat scoring semplice (conteggio indicatori, livello)
- output JSON/CSV delle segnalazioni
"""

import re
import json
import argparse
from datetime import datetime
from collections import Counter

IP_RE = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?!$)|$)){4}')
URL_RE = re.compile(r'https?://[^\s,;]+')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,128}\b')  # md5/sha1/sha256 ecc.

# esempio di IOC locali (puoi caricare da file)
IOC_IPS = {'10.0.2.99', '192.168.56.100'}
IOC_URLS = {'http://malicious.example'}
IOC_HASHES = set()

def analyze_line(line):
    findings = []
    for ip in IP_RE.findall(line):
        if ip in IOC_IPS:
            findings.append(('ioc_ip', ip))
    for url in URL_RE.findall(line):
        if url in IOC_URLS:
            findings.append(('ioc_url', url))
    for h in HASH_RE.findall(line):
        if h in IOC_HASHES:
            findings.append(('ioc_hash', h))
    return findings

def process_file(path):
    alerts = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for lineno, line in enumerate(f, start=1):
            fnds = analyze_line(line)
            if fnds:
                alerts.append({'line': lineno, 'msg': line.strip(), 'findings': fnds})
    return alerts

def threat_score_for_alert(alert):
    # semplice: 10 punti per ogni IOC trovato
    return 10 * len(alert['findings'])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True)
    ap.add_argument('--outjson', default='alerts.json')
    args = ap.parse_args()
    alerts = process_file(args.log)
    # arricchimento
    for a in alerts:
        a['score'] = threat_score_for_alert(a)
        a['time'] = datetime.utcnow().isoformat()
    with open(args.outjson, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)
    print(f'{len(alerts)} alert salvati in {args.outjson}')
    # stampa sintetica
    counts = Counter([tuple(x) for a in alerts for x in a['findings']])
    print('Riepilogo findings:', counts)

if __name__ == '__main__':
    main()
