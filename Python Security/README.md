# Mini Lab Bundle (Kali + Windows Server helpers)

Contenuto:
- mini_siem.py      : parser + sqlite + grafici
- nmap_scanner.py   : wrapper nmap -> CSV
- log_analyzer.py   : IOC detection + threat scoring
- sample.log        : file di log di esempio
- hosts.txt         : lista host di esempio per nmap
- playbook.md       : checklist/playbook di risposta
- README.md         : questo file

Istruzioni rapide:
1. Copia i file su una macchina Linux (Kali va bene).
2. Assicurati di avere Python3 e matplotlib: `pip3 install matplotlib`
3. Esempi:
   - `python3 mini_siem.py --log sample.log`
   - `python3 log_analyzer.py --log sample.log --outjson alerts.json`
   - `python3 nmap_scanner.py --target 192.168.56.0/24 --args "-sS -Pn -T4 -p 22,80,443"`

Nota di sicurezza: usa questi script solo su reti e macchine su cui hai permesso esplicito.
