# Limitierungen des LastRowChat-Protokolls

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

## 5. Nur IPv4

**Beschreibung:** Das System unterstützt ausschließlich IPv4.  
**Ursache:** `konfig.py:17` – `BIND_ADRESSE = "0.0.0.0"` bindet den Server-Socket nur an alle IPv4-Interfaces. `asyncio.start_server` und `asyncio.open_connection` verwenden damit ausschließlich IPv4.  
**Auswirkung:** Reine IPv6-Umgebungen werden nicht unterstützt.

---

## 6. Wiederverbindung begrenzt auf MAX_RECONNECT_VERSUCHE

**Beschreibung:** Client- und Auto-Modus versuchen nach einem Abbruch automatisch
Reconnect mit exponentiellem Backoff (bis 60 s). Nach `MAX_RECONNECT_VERSUCHE` (= 10)
erfolglosen Versuchen beendet sich das Programm.  
**Ursache:** Unendliche Wiederholungen würden eine dauerhaft nicht erreichbare Gegenstelle
nicht erkennen und CPU/Netz unnötig belasten.  
**Auswirkung:** Bei mehr als 10 aufeinanderfolgenden Fehlversuchen ist ein manueller
Neustart erforderlich. Der Server-Modus ist davon nicht betroffen (lauscht unbegrenzt).

---

## 7. CA-Schlüssel wird während des Setups übertragen

**Beschreibung:** Im empfohlenen Laborworkflow überträgt Peer A den privaten CA-Schlüssel (`ca_schluessel.pem`) per HTTP an Peer B, damit Peer B sein Peer-Zertifikat selbst signieren kann.  
**Ursache:** Das Skript `certs/zertifikate_erstellen.sh --nur-peer-cert` benötigt sowohl `ca_zertifikat.pem` als auch `ca_schluessel.pem`, um die CSR zu signieren. Der HTTP-Transfer ist unverschlüsselt.  
**Auswirkung:** Wer den CA-Schlüssel besitzt, kann beliebige Zertifikate ausstellen und sich so als gültiger Peer ausgeben. Im isolierten VirtualBox Internal Network ist das Risiko gering, in offenen Netzen jedoch kritisch.  
**Abhilfe:** CA-Schlüssel per SCP (SSH-verschlüsselt) oder physisch (USB) übertragen; nach dem Setup auf beiden VMs löschen. Alternativ: Peer A signiert die CSR von Peer B zentral, ohne den CA-Schlüssel zu verteilen.
