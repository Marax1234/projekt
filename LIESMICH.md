# P2P Chat – Startanleitung

**Kurs:** Network Security 2026 | **Gruppe 2**
**Protokoll:** P2PChat v1.0 | **Port:** 6769 | **TLS**

---

## Voraussetzungen

- Python 3.11+ (auf Kali Linux 2025.4 vorinstalliert)
- Zwei Kali-Linux-VMs im selben VirtualBox Internal Network oder Host-Only Adapter
- `zertifikat.pem` und `schluessel.pem` im Projektverzeichnis (Generierung siehe unten)
- Nur Python-Standardbibliothek – kein `pip install` erforderlich

---

## Zertifikat generieren (einmalig, auf VM1/Server)

```bash
openssl req -x509 -newkey rsa:4096 -keyout schluessel.pem \
  -out zertifikat.pem -days 365 -nodes \
  -subj "/CN=P2PChat/O=NetSec2026"
```

**Wichtig:** Das `zertifikat.pem` muss auf **beide VMs** kopiert werden.
Der private Schluessel `schluessel.pem` bleibt **nur auf VM1** (Server-Seite).

```bash
# Zertifikat auf VM2 kopieren (Beispiel mit scp):
scp zertifikat.pem benutzer@<IP_VM2>:/pfad/zum/projekt/
```

Zertifikat pruefen:
```bash
openssl x509 -in zertifikat.pem -noout -text | grep -E "Subject:|Validity"
```

---

## Starten

### GUI-Modus (empfohlen)

**VM1 und VM2 – jeweils:**
```bash
cd /pfad/zum/projekt
python3 hauptprogramm.py --gui
```

Der Startdialog fragt ab:
- **Modus:** Server (VM1 – wartet) oder Client (VM2 – verbindet)
- **Server-IP:** IP-Adresse von VM1 (nur im Client-Modus)
- **Port:** Standard 6769
- **Anzeigename:** Frei waehlbar (erscheint im Chat)

**Reihenfolge:** Erst VM1 (Server) starten, dann VM2 (Client).

### Konsolenmodus

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
--name    <name>    Anzeigename im Chat (Standard: "Server" oder "Client")
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
# Erwartung: TLS-Handshake sichtbar, Payload verschluesselt
```

---

## Log-Datei

Die Anwendung schreibt alle Ereignisse in `p2pchat.log` (im Projektverzeichnis):

```bash
# Log in Echtzeit verfolgen:
tail -f p2pchat.log

# Log-Level erhoehen (DEBUG zeigt Nachrichtendetails):
python3 hauptprogramm.py --gui --debug
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
- **Vertraulichkeit & Integritaet:** TLS (AEAD-Verschluesselung) – gesamter Kanal verschluesselt und integritaetsgesichert

---

## Projektstruktur

| Datei              | Beschreibung                              |
|--------------------|-------------------------------------------|
| `konfig.py`        | Alle Konstanten (Port, Timeouts, Pfade)   |
| `netzwerk.py`      | TCP/TLS-Verbindungsverwaltung             |
| `sitzung.py`       | Sitzungslebenszyklus, Nachrichten senden/empfangen |
| `gui.py`           | Tkinter-Oberflaeche (Dark Mode)           |
| `hauptprogramm.py` | Einstiegspunkt, argparse, Orchestrierung  |
| `zertifikat.pem`   | Self-Signed TLS-Zertifikat                |
| `schluessel.pem`   | Privater TLS-Schluessel (nur Server)      |

---

## Fehlerbehebung

| Problem                          | Loesung                                             |
|----------------------------------|-----------------------------------------------------|
| `Port already in use`            | `sudo lsof -i :6769` – alten Prozess beenden        |
| `SSL: CERTIFICATE_VERIFY_FAILED` | `zertifikat.pem` fehlt auf Client-VM                |
| `Connection refused`             | Server noch nicht gestartet oder IP falsch          |
| GUI startet nicht                | `python3 -c "import tkinter"` – tkinter pruefen     |
