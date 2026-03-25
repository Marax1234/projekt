# Startanleitung – P2P Chat mit GUI

**Kurs:** Network Security 2026 | **Gruppe 2**
**Zwei unbekannte Laptops, beide Kali Linux in VirtualBox**

---

## Vorbereitung (einmalig)

### 1. VirtualBox-Netzwerk einrichten

Auf **beiden VMs** in VirtualBox:
- VM-Einstellungen → Netzwerk → Adapter 1 → **Host-only Adapter** (oder Internal Network)
- Beide VMs müssen denselben Adapter-Namen haben

---

### 2. Projektdateien auf beide VMs kopieren

Den Projektordner (`projekt/`) auf beide VMs bringen (USB, scp, gemeinsamer Ordner).

---

### 3. IP-Adressen herausfinden

Auf **jeder VM** ein Terminal öffnen:
```bash
ip addr show
```
Suche nach der Zeile mit `inet` bei `eth0` oder `eth1` — z.B. `192.168.56.101`.

**VM1-IP notieren** (die braucht VM2 später).

---

### 4. Zertifikat generieren (nur auf VM1 – einmalig)

```bash
cd /pfad/zum/projekt
openssl req -x509 -newkey rsa:4096 -keyout schluessel.pem \
  -out zertifikat.pem -days 365 -nodes \
  -subj "/CN=P2PChat/O=NetSec2026"
```

Das `zertifikat.pem` auf **VM2 kopieren** (`schluessel.pem` bleibt nur auf VM1):
```bash
scp zertifikat.pem benutzer@<IP_VM2>:/pfad/zum/projekt/
```

---

## Chat starten

### 5. VM1 starten (zuerst!)

```bash
cd /pfad/zum/projekt
python3 hauptprogramm.py --gui
```

Im Startdialog:

| Feld        | Eingabe                                    |
|-------------|--------------------------------------------|
| Modus       | **Server** auswählen                       |
| Port        | `6769` (bereits vorausgefüllt)             |
| Anzeigename | z.B. `Alice`                               |
| Server-IP   | *(grau/leer – nur für Client relevant)*    |

→ **Starten** klicken → VM1 wartet nun auf Verbindung.

---

### 6. VM2 starten (danach)

```bash
cd /pfad/zum/projekt
python3 hauptprogramm.py --gui
```

Im Startdialog:

| Feld        | Eingabe                        |
|-------------|--------------------------------|
| Modus       | **Client** auswählen           |
| Server-IP   | IP von VM1, z.B. `192.168.56.101` |
| Port        | `6769`                         |
| Anzeigename | z.B. `Bob`                     |

→ **Starten** klicken → Verbindung wird aufgebaut.

---

### 7. Chatten

- Nachricht ins **Eingabefeld** (unten) tippen
- **Enter** oder **Senden**-Button drücken
- Nachricht erscheint im Verlauf beider VMs
- Statusleiste zeigt: Verbindungsstatus, Peer-IP, TLS 1.3 Info

---

## Verbindung prüfen (falls es nicht klappt)

```bash
# Können sich die VMs erreichen?
ping <IP_VM1>

# Port erreichbar?
nc -zv <IP_VM1> 6769
```

| Problem                        | Lösung                                          |
|--------------------------------|-------------------------------------------------|
| `Connection refused`           | VM1 noch nicht gestartet, oder falsche IP       |
| `CERTIFICATE_VERIFY_FAILED`    | `zertifikat.pem` fehlt auf VM2                  |
| `Port already in use`          | `sudo lsof -i :6769` → Prozess beenden          |
| GUI startet nicht              | `python3 -c "import tkinter"` – tkinter prüfen  |
