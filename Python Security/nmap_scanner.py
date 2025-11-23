#!/usr/bin/env python3
"""Semplice wrapper per nmap:
- esegue una scansione TCP SYN (-sS) leggera su target list
- produce un CSV con IP, porta, stato, servizio
Nota: richiede nmap installato nel sistema.
Usalo solo su reti di test o con permesso.
"""

import subprocess
import csv
import argparse
import shlex
import xml.etree.ElementTree as ET
import tempfile
import os

def run_nmap(target, args='-sS -Pn -T4 -p 1-1024'):
    # scrive output XML temporaneo
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tf:
        xmlfile = tf.name
    cmd = f"nmap {args} -oX {shlex.quote(xmlfile)} {shlex.quote(target)}"
    print('Eseguo:', cmd)
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        print('Attenzione: nmap ha restituito codice', res.returncode)
        print(res.stderr)
    return xmlfile

def xml_to_csv(xmlfile, csvfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    with open(csvfile, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'port', 'protocol', 'state', 'service'])
        for host in root.findall('host'):
            addr_el = host.find('address')
            addr = addr_el.get('addr') if addr_el is not None else 'unknown'
            ports = host.find('ports')
            if ports is None:
                w.writerow([addr, '', '', '', ''])
                continue
            for p in ports.findall('port'):
                portid = p.get('portid')
                protocol = p.get('protocol')
                state_el = p.find('state')
                state = state_el.get('state') if state_el is not None else ''
                svc = p.find('service')
                svcname = svc.get('name') if svc is not None else ''
                w.writerow([addr, portid, protocol, state, svcname])

def main():
    ap = argparse.ArgumentParser(description='Nmap scanner -> CSV')
    ap.add_argument('--target', required=True, help='IP/hostname o target range (es. 10.0.2.0/24)')
    ap.add_argument('--args', default='-sS -Pn -T4 -p 1-1024', help='Argomenti nmap')
    ap.add_argument('--out', default='nmap_report.csv', help='CSV di output')
    args = ap.parse_args()
    xmlfile = run_nmap(args.target, args.args)
    try:
        xml_to_csv(xmlfile, args.out)
        print('CSV scritto in', args.out)
    finally:
        if os.path.exists(xmlfile):
            os.remove(xmlfile)

if __name__ == '__main__':
    main()
