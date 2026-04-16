# Limitierungen des P2P-Chat-Protokolls

Dieses Dokument beschreibt alle bekannten Einschränkungen des aktuellen Protokollentwurfs (Version 1.0).

---

## 1. Nur 1:1-Verbindung

**Beschreibung:** Das System unterstützt maximal eine gleichzeitige Verbindung.  
**Ursache:** `konfig.py:21` – `MAX_VERBINDUNGEN = 1`; der Server-Socket lauscht mit Warteschlangenlänge 1.  
**Auswirkung:** Kein Gruppenchat, kein Broadcast, keine parallelen Sitzungen möglich.

---

## 2. Kein Gruppenchat / kein Broadcast

**Beschreibung:** Die P2P-Architektur kennt keine zentrale Vermittlungsinstanz.  
**Ursache:** `sitzung.py` verwaltet genau eine `ssl.SSLSocket`-Verbindung pro Sitzung; es gibt keinen Mechanismus, Nachrichten an mehrere Peers weiterzuleiten.  
**Auswirkung:** Für Gruppenkommunikation müsste eine Mesh-Topologie oder ein dedizierter Relay-Server eingeführt werden.

---

## 3. Self-Signed-Zertifikat ohne CA-Verifikation

**Beschreibung:** Der Client prüft das Server-Zertifikat nicht gegen eine vertrauenswürdige Zertifizierungsstelle.  
**Ursache:** `netzwerk.py:93–94`:
```python
kontext.check_hostname = False
kontext.verify_mode = ssl.CERT_NONE
```
**Auswirkung:** Man-in-the-Middle-Angriffe sind in offenen Netzwerken möglich. Der Einsatz ist auf geschlossene, kontrollierte Umgebungen (z. B. VirtualBox Internal Network) beschränkt.

---

## 4. Kein persistenter Nachrichtenspeicher

**Beschreibung:** Der Chat-Verlauf wird ausschließlich im RAM der GUI gehalten.  
**Ursache:** `gui.py` schreibt Nachrichten nur in das Tkinter-Textwidget; `sitzung.py` speichert keine gesendeten oder empfangenen Nachrichten.  
**Auswirkung:** Nach Verbindungsabbau oder Programmende ist der gesamte Verlauf unwiderruflich verloren.

---

## 5. Kein NAT-Traversal

**Beschreibung:** Beide Peers müssen direkt über IP erreichbar sein.  
**Ursache:** `netzwerk.py` verwendet direkte TCP-Verbindungen (`socket.connect`); es existieren keine STUN-, TURN- oder Hole-Punching-Mechanismen.  
**Auswirkung:** Hinter NAT (z. B. Heim-Router) ist ohne Port-Forwarding oder VPN keine Verbindung möglich.

---

## 6. Fehlendes Nachrichten-Framing (Pufferlimit)

**Beschreibung:** Das Protokoll besitzt kein Framing (weder Length-Prefix noch Delimiter). Pro Empfangsaufruf werden maximal 4 096 Bytes gelesen.  
**Ursache:** `netzwerk.py:302` – ein einziger `recv(konfig.PUFFER_GROESSE)`-Aufruf ohne Reassemblierung; `konfig.py:49` – `PUFFER_GROESSE = 4096`.  
**Auswirkung:** Da TCP ein Datenstrom ist, kann `recv()` unabhängig von der Nachrichtengröße ein partielles Fragment zurückgeben — der JSON-Parser schlägt dann mit `json.JSONDecodeError` fehl. Nachrichten, deren JSON-Repräsentation 4 096 Bytes überschreitet, werden zusätzlich hart abgeschnitten.

---

## 7. Nur IPv4

**Beschreibung:** Das System unterstützt ausschließlich IPv4.  
**Ursache:** `netzwerk.py:117` und `:214` – `socket.AF_INET` ist fest kodiert.  
**Auswirkung:** Reine IPv6-Umgebungen werden nicht unterstützt.

---

## 8. Eingeschränkter Wiederverbindungsmechanismus

**Beschreibung:** Nach einem Verbindungsabbruch gibt es keine automatische Wiederverbindung.  
**Ursache:** `sitzung.py:196` – bei `ConnectionError` wird der Zustand auf `GETRENNT` gesetzt und die Empfangsschleife beendet. Im Konsolenmodus wartet der Server dank `while True`-Schleife (`konsole.py:91`) auf den nächsten Client — der Client ist jedoch one-shot und beendet sich. Im GUI-Modus erscheint der Verbindungsdialog nur einmalig beim Start; nach Verbindungsabbau gibt es für beide Seiten keine Möglichkeit zur Neuverbindung ohne Neustart der Anwendung.  
**Auswirkung:** Kurze Netzwerkunterbrechungen beenden die Client-Sitzung endgültig; im GUI-Modus gilt das auch für den Server.

---

## 9. Keine gegenseitige TLS-Authentifizierung (kein mTLS)

**Beschreibung:** Nur der Server präsentiert ein Zertifikat; der Client authentifiziert sich nicht.  
**Ursache:** `netzwerk.py:80–97` – der Client-TLS-Kontext lädt kein eigenes Zertifikat (`load_cert_chain` fehlt auf Client-Seite); `netzwerk.py:47–73` – der Server-Kontext setzt kein `verify_mode = ssl.CERT_REQUIRED` und fordert daher kein Client-Zertifikat an.  
**Auswirkung:** Die Identität des Clients ist nicht verifizierbar. Ein beliebiger Dritter, der den Port erreicht, kann sich als gültiger Chat-Peer verbinden.

---

## 10. Kein Nachrichtenformat-Versioning

**Beschreibung:** Das JSON-Protokoll enthält keine Versionsnummer.  
**Ursache:** Das Payload-Format (`nachricht`, `zeitstempel`, `absender`) ist fest in `sitzung.py:123–127` kodiert.  
**Auswirkung:** Zukünftige Protokollerweiterungen sind nicht rückwärtskompatibel; beide Peers müssen stets dieselbe Version verwenden.
