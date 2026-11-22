# IDS/IPS réseau en Python (Scapy)

Outil d'analyse de trafic réseau qui lit une capture PCAP, produit des statistiques par protocole et détecte automatiquement plusieurs attaques, avec identification de l'attaquant.

Projet réalisé dans le cadre du Mastère Cybersécurité de l'ESGI (sept. – nov. 2026).

## Fonctionnalités

- Lecture et analyse de fichiers PCAP avec Scapy
- Statistiques par protocole : Ethernet, ARP, IP, IPv6, TCP, UDP, ICMP, DNS
- Détection d'attaques, avec l'IP ou la MAC de l'attaquant :
  - **ARP spoofing** : plusieurs MAC pour une même IP, réponses ARP non sollicitées
  - **Scan de ports** : nombreux SYN vers des ports différents depuis une même source
  - **Injection SQL** : motifs suspects dans les requêtes HTTP (`' OR 1=1`, `UNION SELECT`…)
- Rapport **JSON** (lisible par une machine) et rapport **PDF** (graphique et tableau des volumes)
- Journalisation des événements et des attaques détectées

## Stack

Python · Scapy · pygal · fpdf2 · Poetry · pytest · pre-commit

## Installation

```bash
git clone https://github.com/rohithramassamy2004/network-ids-scapy.git
cd network-ids-scapy
poetry install
```

## Utilisation

```bash
poetry run ids --pcap capture.pcap --out report.json
```

L'outil écrit `report.json` et `report.pdf` :

```json
{
  "protocols": { "TCP": 128, "ARP": 12, "DNS": 7 },
  "attacks": [
    { "type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff" },
    { "type": "port_scan", "attacker": "10.0.0.5" },
    { "type": "sql_injection", "attacker": "10.0.0.9" }
  ]
}
```

## Tests

```bash
poetry run pytest -v
```

## Structure

```text
src/
└── tp1/
    ├── main.py          # point d'entrée (CLI)
    └── utils/
        ├── capture.py   # lecture PCAP, statistiques, détection d'attaques
        ├── report.py    # génération du rapport PDF
        ├── lib.py
        └── config.py
tests/
└── tp1/utils/
```

> Les captures d'entraînement fournies par l'école ne sont pas incluses dans ce dépôt.
