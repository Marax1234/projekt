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

## 3. Kein persistenter Nachrichtenspeicher

**Beschreibung:** Der Chat-Verlauf wird ausschließlich im RAM gehalten.  
**Ursache:** `sitzung.py` speichert keine gesendeten oder empfangenen Nachrichten; `cli_ui.py` gibt sie nur auf der Konsole aus.  
**Auswirkung:** Nach Verbindungsabbau oder Programmende ist der gesamte Verlauf unwiderruflich verloren.

---

## 4. Kein NAT-Traversal

**Beschreibung:** Beide Peers müssen direkt über IP erreichbar sein.  
**Ursache:** `netzwerk.py` verwendet direkte TCP-Verbindungen; es existieren keine STUN-, TURN- oder Hole-Punching-Mechanismen.  
**Auswirkung:** Hinter NAT (z. B. Heim-Router) ist ohne Port-Forwarding oder VPN keine Verbindung möglich.

---

## 5. Fehlendes Nachrichten-Framing (Pufferlimit)

**Beschreibung:** Das Protokoll besitzt kein Framing (weder Length-Prefix noch Delimiter). Pro Empfangsaufruf werden maximal 4 096 Bytes gelesen.  
**Ursache:** `netzwerk.py` – `daten_empfangen()` – ein einziger `recv(konfig.PUFFER_GROESSE)`-Aufruf ohne Reassemblierung; `konfig.py` – `PUFFER_GROESSE = 4096`.  
**Auswirkung:** Da TCP ein Datenstrom ist, kann `recv()` unabhängig von der Nachrichtengröße ein partielles Fragment zurückgeben — der JSON-Parser schlägt dann mit `json.JSONDecodeError` fehl. Nachrichten, deren JSON-Repräsentation 4 096 Bytes überschreitet, werden zusätzlich hart abgeschnitten.

---

## 6. Nur IPv4

**Beschreibung:** Das System unterstützt ausschließlich IPv4.  
**Ursache:** `netzwerk.py:117` und `:214` – `socket.AF_INET` ist fest kodiert.  
**Auswirkung:** Reine IPv6-Umgebungen werden nicht unterstützt.

---

## 7. Eingeschränkter Wiederverbindungsmechanismus

**Beschreibung:** Nach einem Verbindungsabbruch gibt es keine automatische Wiederverbindung.  
**Ursache:** `sitzung.py` – bei `ConnectionError` wird der Zustand auf `GETRENNT` gesetzt und die Empfangsschleife beendet. Der Server wartet dank `while True`-Schleife in `konsole.py` auf den nächsten Client — der Client ist jedoch one-shot und beendet sich.  
**Auswirkung:** Kurze Netzwerkunterbrechungen beenden die Client-Sitzung endgültig; ein Neustart der Anwendung ist erforderlich.

---

## 8. Kein Nachrichtenformat-Versioning

**Beschreibung:** Das JSON-Protokoll enthält keine Versionsnummer.  
**Ursache:** Das Payload-Format (`nachricht`, `zeitstempel`, `absender`) ist fest in `sitzung.py` kodiert.  
**Auswirkung:** Zukünftige Protokollerweiterungen sind nicht rückwärtskompatibel; beide Peers müssen stets dieselbe Version verwenden.

---

## 9. Kein App-Level-Handshake nach TLS

**Beschreibung:** Nach dem mTLS-Handshake gibt es keine Bestätigung auf Anwendungsebene, dass beide Seiten die Verbindung als aktiv betrachten.  
**Ursache:** `sitzung.py` setzt den Zustand direkt auf `VERBUNDEN` ohne einen Ping/Pong-Austausch. Ein Verbindungsabbruch zwischen TLS-Handshake und erstem `read()`/`write()` wird erst beim ersten Sendeversuch bemerkt.  
**Auswirkung:** In seltenen Randbedingungen (z. B. Netzwerkunterbrechung exakt nach dem Handshake) erscheint die Verbindung kurz als verbunden, obwohl sie bereits tot ist.

---

## 10. CA-Schlüssel wird während des Setups übertragen

**Beschreibung:** Im empfohlenen Laborworkflow überträgt Peer A den privaten CA-Schlüssel (`ca_schluessel.pem`) per HTTP an Peer B, damit Peer B sein Peer-Zertifikat selbst signieren kann.  
**Ursache:** Das Skript `certs/zertifikate_erstellen.sh --nur-peer-cert` benötigt sowohl `ca_zertifikat.pem` als auch `ca_schluessel.pem`, um die CSR zu signieren. Der HTTP-Transfer ist unverschlüsselt.  
**Auswirkung:** Wer den CA-Schlüssel besitzt, kann beliebige Zertifikate ausstellen und sich so als gültiger Peer ausgeben. Im isolierten VirtualBox Internal Network ist das Risiko gering, in offenen Netzen jedoch kritisch.  
**Abhilfe:** CA-Schlüssel per SCP (SSH-verschlüsselt) oder physisch (USB) übertragen; nach dem Setup auf beiden VMs löschen. Alternativ: Peer A signiert die CSR von Peer B zentral, ohne den CA-Schlüssel zu verteilen.
