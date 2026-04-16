# P2P Chat – Startanleitung

**Kurs:** Network Security 2026 | **Gruppe 2**
**Protokoll:** P2PChat v1.0 | **Port:** 6769 | **TLS 1.3**

---

## Voraussetzungen

- Python 3.11+ (auf Kali Linux 2025.4 vorinstalliert)
- Zwei Kali-Linux-VMs im selben VirtualBox Internal Network oder Host-Only Adapter
- `zertifikat.pem` und `schluessel.pem` im Projektverzeichnis (Generierung siehe unten)
- Nur Python-Standardbibliothek – kein `pip install` erforderlich

---

## Zertifikat generieren (einmalig, auf jeder VM)

Da im Race-to-Connect-Modus jede VM die Server-Rolle übernehmen kann,
braucht **jede VM ihr eigenes Schlüsselpaar** (`zertifikat.pem` + `schluessel.pem`).

```bash
# Auf VM1 UND auf VM2 jeweils ausführen:
openssl req -x509 -newkey rsa:4096 -keyout schluessel.pem \
  -out zertifikat.pem -days 365 -nodes \
  -subj "/CN=P2PChat/O=NetSec2026"
```

**Hinweis:** Da der Client die Zertifikatsprüfung deaktiviert hat
(`CERT_NONE`), können beide VMs unterschiedliche Self-Signed-Zertifikate
verwenden – kein gegenseitiger Austausch erforderlich.

Zertifikat pruefen:
```bash
openssl x509 -in zertifikat.pem -noout -text | grep -E "Subject:|Validity"
```

---

## Starten

### Auto-Modus – Race to Connect (empfohlen)

**VM1 (z. B. IP 192.168.100.1):**
```bash
python3 hauptprogramm.py --ziel 192.168.100.2 --port 6769 
```

**VM2 (z. B. IP 192.168.100.2):**
```bash
python3 hauptprogramm.py --ziel 192.168.100.1 --port 6769
```

Beide Peers starten gleichzeitig. Die Rolle (Server/Client) wird
automatisch bestimmt und ausgegeben.

### Manueller Modus (rückwärtskompatibel)

**VM1 – Server:**
```bash
python3 hauptprogramm.py --modus server --port 6769
```

**VM2 – Client:**
```bash
python3 hauptprogramm.py --modus client --ziel <IP_VON_VM1> --port 6769
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
python3 hauptprogramm.py --ziel <IP> --debug
```

Log-Phasen:
- **Verbindungsaufbau:** TCP-Verbindung, TLS-Handshake
- **Datenuebertragung:** Nachrichten
- **Fehler:** Timeout, Verbindungsabbruch
- **Verbindungsabbau:** Socket-Schliessen

---

## Protokoll-Uebersicht

Jede Nachricht wird als JSON-Objekt mit den Feldern `nachricht`, `zeitstempel`
und `absender` als UTF-8-codierte Bytes direkt ueber den TLS-Kanal uebertragen.

```
| JSON-Payload (n B, UTF-8) |
```

**Sicherheit:**
- **Vertraulichkeit & Integritaet:** TLS 1.3 (AEAD-Verschluesselung) – gesamter Kanal verschluesselt und integritaetsgesichert
- **TLS-Mindestversion:** TLS 1.3 wird serverseitig und clientseitig erzwungen (`minimum_version = TLSv1_3`). Verbindungsversuche mit TLS 1.2 oder aelter werden abgelehnt.

---

## Projektstruktur

| Datei              | Beschreibung                                              |
|--------------------|-----------------------------------------------------------|
| `konfig.py`        | Alle Konstanten (Port, Timeouts, Race-Parameter, Pfade)   |
| `netzwerk.py`      | TCP/TLS-Verbindungsverwaltung + `auto_verbinden()`        |
| `sitzung.py`       | Sitzungslebenszyklus, Nachrichten senden/empfangen        |
| `konsole.py`       | Konsolenbetrieb: `peer_starten()`, `server_starten()`, `client_starten()` |
| `cli_ui.py`        | Terminal-UI (Banner, Box-Chars, Prompt)                   |
| `hauptprogramm.py` | Einstiegspunkt, argparse, Orchestrierung                  |
| `zertifikat.pem`   | Self-Signed TLS-Zertifikat (auf jeder VM generieren)      |
| `schluessel.pem`   | Privater TLS-Schluessel (auf jeder VM generieren)         |

---

## Fehlerbehebung

| Problem                          | Loesung                                             |
|----------------------------------|-----------------------------------------------------|
| `Port already in use`            | `sudo lsof -i :6769` – alten Prozess beenden        |
| `SSL: CERTIFICATE_VERIFY_FAILED` | `zertifikat.pem` oder `schluessel.pem` fehlt        |
| Keine Verbindung nach 15 s       | IP falsch, Port blockiert oder beide im Client-Try  |
