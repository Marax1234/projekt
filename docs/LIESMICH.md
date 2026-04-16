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

## Zertifikate generieren (einmalig pro Laboraufbau)

Beide Peers verwenden eine **gemeinsame CA**. Peer A generiert sie,
Peer B signiert sein eigenes Zertifikat damit.

### Schritt 1 – Peer A: CA + eigenes Zertifikat generieren

```bash
bash certs/zertifikate_erstellen.sh
```

Danach CA-Dateien für Peer B bereitstellen:

```bash
cd certs && python3 -m http.server 8080
# Läuft bis Schritt 3 abgeschlossen ist, dann Strg+C
```

Das Skript gibt am Ende automatisch die fertigen `wget`-Befehle mit der eigenen IP aus.

### Schritt 2 – Peer B: CA holen

```bash
wget http://<IP_PEER_A>:8080/ca_zertifikat.pem -O certs/ca_zertifikat.pem
wget http://<IP_PEER_A>:8080/ca_schluessel.pem -O certs/ca_schluessel.pem
```

### Schritt 3 – Peer B: eigenes Zertifikat signieren

```bash
bash certs/zertifikate_erstellen.sh --nur-peer-cert
```

### Schritt 4 – Peer A: HTTP-Server beenden

```bash
# Strg+C im Terminal von Schritt 1
```

---

### Zertifikate prüfen

```bash
# Inhalt anzeigen:
openssl x509 -in certs/zertifikat.pem -noout -text | grep -E "Subject:|Issuer:|Validity"

# CA-Signierung prüfen:
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

## Netzwerk prüfen

```bash
# VMs können sich gegenseitig erreichen?
ping <IP_VON_VM1>

# Port offen?
nc -zv <IP_VON_VM1> 6769

# Netzwerkinterfaces prüfen
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
# Erwartung: TLS 1.3-Handshake sichtbar (Record Version: TLS 1.3), Payload verschlüsselt
```

---

## Log-Datei

Die Anwendung schreibt alle Ereignisse in `p2pchat.log` (im Projektverzeichnis):

```bash
# Log in Echtzeit verfolgen:
tail -f p2pchat.log

# Log-Level erhöhen (DEBUG zeigt Nachrichtendetails):
python3 src/hauptprogramm.py --ziel <IP> --debug
```

Log-Phasen:
- **Verbindungsaufbau:** TCP-Verbindung, mTLS-Handshake, Peer-Zertifikat-Prüfung
- **Datenübertragung:** Nachrichten
- **Fehler:** Timeout, Verbindungsabbruch, Zertifikat abgelehnt
- **Verbindungsabbau:** Socket-Schließen

---

## Protokoll-Übersicht

Das Anwendungsprotokoll läuft über **TCP + TLS 1.3**. Nach dem mTLS-Handshake
folgt ein anwendungsspezifischer App-Handshake (`APP_HELLO`/`APP_HELLO_ACK`). Erst danach
dürfen CHAT-Nachrichten gesendet werden.

**Framing:** NDJSON (newline-delimited JSON) – jede Nachricht ist ein kompaktes
JSON-Objekt, abgeschlossen durch `\n`, UTF-8-kodiert.

**Pflichtfelder jeder Nachricht:**

| Feld | Bedeutung |
|---|---|
| `msg_type` | Nachrichtentyp (`APP_HELLO`, `APP_HELLO_ACK`, `CHAT`, `APP_MSG_ACK`, `APP_PING`, `APP_PONG`, `APP_ERROR`, `APP_CLOSE`) |
| `protocol_version` | Immer `"1.0"` |
| `app_session_id` | Gesetzt nach erfolgreichem App-Handshake – **App-Ebene** (von TLS `legacy_session_id` zu unterscheiden) |
| `msg_id` | UUID-basierte Nachrichten-ID |
| `timestamp` | ISO-8601 UTC |
| `data` | Typabhängiger Nutzdaten-Block |

> **Warum `APP_`-Präfix und `app_session_id`?**
> TLS 1.3 selbst verwendet `legacy_session_id` im Handshake sowie Nachrichtentypen wie
> `client_hello`/`server_hello` (HandshakeType) und `close_notify`/Alert-Records.
> ICMP und WebSocket verwenden `PING`/`PONG`. TCP verwendet ACK-Flags.
> Das `APP_`-Präfix und der `app_`-Feldname machen auf Protokoll- und Log-Ebene eindeutig klar,
> dass es sich um App-Schicht-Konstrukte handelt und keine Verwechslung mit gleichnamigen
> TLS/TCP/ICMP-Feldern entstehen kann.

Beispiel CHAT-Nachricht:

```json
{
  "msg_type": "CHAT",
  "protocol_version": "1.0",
  "app_session_id": "sess-7f3c1234",
  "msg_id": "msg-6f0d4b0e-...",
  "timestamp": "2026-04-16T11:20:00Z",
  "data": {"sender": "alice", "text": "Hallo"}
}
```

**Zustandsautomat (intern):** `TLS_AUFGEBAUT` → `HANDSHAKE_AUSSTEHEND` → `BEREIT` (→ `VERALTET` → `SCHLIESSEN` → `GETRENNT`)

**Verbindungszustand (extern):** `VERBUNDEN` → `IDLE` → `PING_PENDING` → `GETRENNT` (+ `RECONNECTING` beim Wiederverbinden)

**Sicherheit:**
- **Vertraulichkeit & Integrität:** TLS 1.3 (AEAD) – gesamter Kanal verschlüsselt und integritätsgesichert
- **TLS-Mindestversion:** TLS 1.3 serverseitig und clientseitig erzwungen; TLS 1.2 wird abgelehnt
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
│   ├── ca_zertifikat.pem        – Gemeinsame CA (Peer A → Peer B übertragen)
│   ├── zertifikat.pem           – Eigenes Peer-Zertifikat
│   ├── schluessel.pem           – Peer-Schlüssel (NICHT verteilen)
│   └── ca_schluessel.pem        – CA-Schlüssel (nur während Setup, NICHT verteilen)
└── .gitignore
```

---

## Automatischer Reconnect

Client- und Auto-Modus versuchen nach einem unerwarteten Verbindungsabbruch automatisch,
die Verbindung wiederherzustellen. Die Wartezeit zwischen Versuchen steigt exponentiell
(Backoff) und wird durch einen zufälligen Jitter ergänzt, um Gleichzeitigkeit zu vermeiden.

| Parameter | Wert | Beschreibung |
|---|---|---|
| `MAX_RECONNECT_VERSUCHE` | 10 | Maximale Versuche vor Programmende |
| Backoff-Formel | `min(2^versuch + jitter, 60 s)` | Versuch 1 ≈ 3 s, Versuch 6 ≈ 64 s → 60 s |

Nur `quit`-Eingabe des Nutzers beendet die Schleife sofort.
Der Server-Modus verwendet bereits eine Endlosschleife und benötigt kein Reconnect.

---

## Verbindungs-Timeouts

| Konstante | Wert | Beschreibung |
|---|---|---|
| `IDLE_TIMEOUT` | 30 s | Kein Traffic → APP_PING senden |
| `PONG_TIMEOUT` | 10 s | Warten auf APP_PONG |
| `PRÜF_INTERVALL` | 5 s | Heartbeat-Prüfzyklus |
| `MARGIN` | 5 s | Sicherheitspuffer |
| `EMPFANG_TIMEOUT` | **50 s** | Abgeleitet: 30 + 10 + 5 + 5 |

> `EMPFANG_TIMEOUT` wird in `konfig.py` **automatisch** aus den obigen Werten berechnet.
> Änderungen an `IDLE_TIMEOUT` propagieren damit ohne manuelle Anpassung.

---

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| `Port already in use` | `sudo lsof -i :6769` – alten Prozess beenden |
| `SSL: CERTIFICATE_VERIFY_FAILED` | `certs/ca_zertifikat.pem` fehlt oder Peer-Zertifikat nicht von dieser CA signiert |
| `SSL: NO_CERTIFICATE_RETURNED` | Gegenseite hat kein Zertifikat gesendet – `bash certs/zertifikate_erstellen.sh` auf beiden VMs ausführen |
| Keine Verbindung nach 15 s | IP falsch, Port blockiert oder beide im Client-Try |
| Reconnect schlägt dauerhaft fehl | Nach 10 Versuchen beendet sich das Programm automatisch |
