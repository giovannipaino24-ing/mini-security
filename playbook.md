# Playbook di risposta — Mini laboratorio (sintesi)

## 1) Rilevamento
- Fonte: Mini-SIEM, Event Viewer, tcpdump
- Azioni immediate: salvare i log rilevanti (export CSV/JSON), catturare screenshot Event Viewer

## 2) Containment
- Isolare VM sospetta: rimuovere interfaccia host-only o disconnettere rete virtuale
- Aggiungere regole firewall per bloccare IP sospetti

## 3) Analisi
- Raccolta: esporta eventi correlati (time window ± 15 minuti)
- Correlazione: cerca IP/URL/hash in IOC list e calcola threat score
- Captura pacchetti: tcpdump per timeline

## 4) Eradicazione e Recovery
- Rimuovere root cause (patch, chiudere servizio)
- Ripristinare da snapshot o reinstallare immagine pulita

## 5) Lessons Learned
- Documentare cause, gap di logging, mitigazioni e miglioramenti delle regole SIEM
