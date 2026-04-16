# P2P Chat – Startanleitung

**Kurs:** Network Security 2026 | **Gruppe 2**
**Protokoll:** P2PChat v1.0 | **Port:** 6769 | **TLS 1.3 + mTLS**

---

## Voraussetzungen

- Python 3.11+ (auf Kali Linux 2025.4 vorinstalliert)
- Zwei Kali-Linux-VMs im selben VirtualBox Internal Network oder Host-Only Adapter
- `certs/zertifikat.pem`, `certs/schluessel.pem` und `certs/ca_zertifikat.pem` (Generierung siehe unten)
- Nur Python-Standardbibliothek – kein `pip install` erforderlich

---

## Zertifikate generieren (einmalig, auf jeder VM)

Das Skript erstellt eine lokale CA sowie ein davon signiertes Peer-Zertifikat.
Beide VMs müssen anschließend das `ca_zertifikat.pem` des jeweils anderen Peers besitzen.

```bash
# Aus dem Projektverzeichnis ausführen:
bash certs/zertifikate_erstellen.sh
```

Danach `certs/ca_zertifikat.pem` gegenseitig übertragen:

```bash
# Von VM1 → VM2:
scp certs/ca_zertifikat.pem user@192.168.100.2:~/projekt/certs/ca_zertifikat.pem

# Von VM2 → VM1:
scp certs/ca_zertifikat.pem user@192.168.100.1:~/projekt/certs/ca_zertifikat.pem
```

**Hinweis:** Wenn beide VMs dieselbe CA verwenden sollen (z. B. Laborumgebung),
reicht es, das Skript einmal auszuführen und `certs/ca_zertifikat.pem` + `certs/ca_schluessel.pem`
auf die andere VM zu kopieren. Dort dann nur Schritte 3–4 des Skripts ausführen
(Peer-Schlüssel + Peer-Zertifikat generieren).

Zertifikat pruefen:
```bash
openssl x509 -in certs/zertifikat.pem -noout -text | grep -E "Subject:|Issuer:|Validity"
```

CA-Signierung prüfen:
```bash
openssl verify -CAfile certs/ca_zertifikat.pem certs/zertifikat.pem
```

---

## Starten

### Auto-Modus – Race to Connect (empfohlen)

**VM1 (z. B. IP 192.168.100.1):**
```bash
python3 src/hauptprogramm.py --ziel 192.168.100.2 --port 6769
```

**VM2 (z. B. IP 192.168.100.2):**
```bash
python3 src/hauptprogramm.py --ziel 192.168.100.1 --port 6769
```

Beide Peers starten gleichzeitig. Die Rolle (Server/Client) wird
automatisch bestimmt und ausgegeben.

### Manueller Modus (rückwärtskompatibel)

**VM1 – Server:**
```bash
python3 src/hauptprogramm.py --modus server --port 6769
```

**VM2 – Client:**
```bash
python3 src/hauptprogramm.py --modus client --ziel <IP_VON_VM1> --port 6769
```

**Optionale Parameter:**
```
--name    <name>    Anzeigename im Chat (Standard: "Peer", "Server" oder "Client")
--debug             DEBUG-Log-Level aktivieren (ausfuehrliche Ausgabe)
```

---

## Netzwerk pruefen

```bash
# VMs koennen sich gegenseitig erreichen?
ping <IP_VON_VM1>

# Port offen?
nc -zv <IP_VON_VM1> 6769

# Netzwerkinterfaces pruefen
ip addr show
```

---

## TLS-Handshake mit Wireshark/tshark beobachten

```bash
# Auf VM1 oder VM2 parallel zum Chat starten:
tshark -i eth0 -f "tcp port 6769"

# Nur TLS-Handshake-Pakete anzeigen:
tshark -i eth0 -f "tcp port 6769" -Y "tls.handshake"

# Aufzeichnung in Datei speichern:
tshark -i eth0 -f "tcp port 6769" -w capture.pcapng

# In Wireshark: Analyze → Expert Information zeigt TLS Cipher Suite
# Erwartung: TLS 1.3-Handshake sichtbar (Record Version: TLS 1.3), Payload verschluesselt
# TLS-Version pruefen: tshark -i eth0 -Y "tls.record.version == 0x0304"
```

---

## Log-Datei

Die Anwendung schreibt alle Ereignisse in `p2pchat.log` (im Projektverzeichnis):

```bash
# Log in Echtzeit verfolgen:
tail -f p2pchat.log

# Log-Level erhoehen (DEBUG zeigt Nachrichtendetails):
python3 src/hauptprogramm.py --ziel <IP> --debug
```

Log-Phasen:
- **Verbindungsaufbau:** TCP-Verbindung, mTLS-Handshake, Peer-Zertifikat-Prüfung
- **Datenuebertragung:** Nachrichten
- **Fehler:** Timeout, Verbindungsabbruch, Zertifikat abgelehnt
- **Verbindungsabbau:** Socket-Schliessen

---

## Protokoll-Uebersicht

Jede Nachricht wird als JSON-Objekt mit den Feldern `nachricht`, `zeitstempel`
und `absender` als UTF-8-codierte Bytes direkt ueber den TLS-Kanal uebertragen.

```
| JSON-Payload (n B, UTF-8) |
```

**Sicherheit:**
- **Vertraulichkeit & Integritaet:** TLS 1.3 (AEAD-Verschluesselung) – gesamter Kanal verschlüsselt und integritätsgesichert
- **TLS-Mindestversion:** TLS 1.3 wird serverseitig und clientseitig erzwungen (`minimum_version = TLSv1_3`). Verbindungsversuche mit TLS 1.2 oder älter werden abgelehnt.
- **Gegenseitige Authentifizierung (mTLS):** Beide Peers präsentieren ein CA-signiertes Zertifikat. Server und Client prüfen das Gegenzertifikat mit `CERT_REQUIRED` gegen die gemeinsame CA. Ein Angreifer ohne gültiges CA-Zertifikat wird beim Handshake abgelehnt.

---

## Projektstruktur

```
projekt/
├── src/                        – Quellcode
│   ├── hauptprogramm.py        – Einstiegspunkt, argparse, Orchestrierung
│   ├── konfig.py               – Alle Konstanten (Port, Timeouts, Pfade)
│   ├── netzwerk.py             – TCP/mTLS-Verbindungsverwaltung
│   ├── sitzung.py              – Sitzungslebenszyklus, Nachrichten
│   ├── konsole.py              – Chat-Modi (peer, server, client)
│   └── cli_ui.py               – Terminal-UI (Banner, Prompt)
├── docs/                       – Dokumentation
│   ├── LIESMICH.md             – Diese Datei
│   ├── TECHNISCHE_UEBERSICHT.md
│   ├── LIMITIERUNGEN.md
│   ├── INTELLIGENZ.md
│   └── 2026_Aufgabenstellung_Programmentwurf_v1.1.pdf
├── certs/                      – Zertifikate (alle .pem in .gitignore)
│   ├── zertifikate_erstellen.sh – CA + Peer-Zertifikat generieren
│   ├── ca_zertifikat.pem        – CA-Zertifikat (an Partner übertragen)
│   ├── zertifikat.pem           – Peer-Zertifikat (lokal)
│   ├── schluessel.pem           – Peer-Schlüssel (NICHT verteilen)
│   └── ca_schluessel.pem        – CA-Schlüssel (NICHT verteilen)
└── .gitignore
```

---

## Fehlerbehebung

| Problem                          | Loesung                                                              |
|----------------------------------|----------------------------------------------------------------------|
| `Port already in use`            | `sudo lsof -i :6769` – alten Prozess beenden                         |
| `SSL: CERTIFICATE_VERIFY_FAILED` | `certs/ca_zertifikat.pem` fehlt oder Peer-Zertifikat nicht von dieser CA signiert |
| `SSL: NO_CERTIFICATE_RETURNED`   | Gegenseite hat kein Zertifikat gesendet – `bash certs/zertifikate_erstellen.sh` auf beiden VMs |
| Keine Verbindung nach 15 s       | IP falsch, Port blockiert oder beide im Client-Try                    |
