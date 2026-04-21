# Limitierungen des LastRowChat-Protokolls

Dieses Dokument beschreibt alle bekannten Einschränkungen des aktuellen Protokollentwurfs (Version 1.0).

---

## 1. Nur 1:1-Verbindung / kein Gruppenchat

**Beschreibung:** Das System unterstützt ausschließlich eine gleichzeitige Verbindung zwischen genau zwei Peers. Gruppenchat und Broadcast sind nicht möglich.  
**Ursache:** Die Begrenzung wird auf Anwendungsebene durchgesetzt: `server_starten()` schließt eingehende Verbindungen sofort (`writer.close()`), solange eine Sitzung aktiv ist; `auto_verbinden()` akzeptiert ausschließlich die erste eingehende Verbindung über ein geteiltes `asyncio.Future`. Darüber hinaus verwaltet `sitzung.py` genau ein Paar `asyncio.StreamReader / asyncio.StreamWriter`; es gibt keinen Mechanismus, Nachrichten an mehrere Peers weiterzuleiten.  
**Auswirkung:** Kein Gruppenchat, kein Broadcast, keine parallelen Sitzungen. Für Gruppenkommunikation wäre eine Mesh-Topologie oder ein dedizierter Relay-Server erforderlich.

---

## 2. Kein persistenter Nachrichtenspeicher

**Beschreibung:** Der Chat-Verlauf wird ausschließlich im RAM gehalten.  
**Ursache:** `sitzung.py` speichert empfangene Nachrichten nicht; `cli_ui.py` gibt sie nur auf der Konsole aus. Gesendete, noch nicht bestätigte Nachrichten werden temporär in einer `_outbox` (`collections.deque`) gehalten und nach einem Reconnect automatisch erneut gesendet (`outbox_wiederholen()`). Diese Outbox wird jedoch nicht auf Disk persistiert und geht beim Programmende verloren.  
**Auswirkung:** Nach Verbindungsabbau oder Programmende ist der gesamte Chatverlauf unwiderruflich verloren. Unbestätigte Nachrichten werden bei Reconnect innerhalb derselben Programmsitzung nachgeliefert, nicht jedoch nach einem Neustart.

---

## 3. Kein NAT-Traversal

**Beschreibung:** Beide Peers müssen direkt über IP erreichbar sein.  
**Ursache:** `netzwerk.py` verwendet direkte TCP-Verbindungen; es existieren keine STUN-, TURN- oder Hole-Punching-Mechanismen.  
**Auswirkung:** Hinter NAT (z. B. Heim-Router) ist ohne Port-Forwarding oder VPN keine Verbindung möglich.

---

## 4. Nur IPv4

**Beschreibung:** Das System unterstützt ausschließlich IPv4.  
**Ursache:** `konfig.py:17` – `BIND_ADRESSE = "0.0.0.0"` bindet den Server-Socket nur an alle IPv4-Interfaces. `asyncio.start_server` und `asyncio.open_connection` verwenden damit ausschließlich IPv4.  
**Auswirkung:** Reine IPv6-Umgebungen werden nicht unterstützt.

---

## 5. Wiederverbindung begrenzt auf MAX_RECONNECT_VERSUCHE

**Beschreibung:** Client- und Auto-Modus versuchen nach einem Abbruch automatisch
Reconnect mit exponentiellem Backoff (bis 10 s). Nach `MAX_RECONNECT_VERSUCHE` (= 10)
erfolglosen Versuchen beendet sich das Programm.  
**Ursache:** Unendliche Wiederholungen würden eine dauerhaft nicht erreichbare Gegenstelle
nicht erkennen und CPU/Netz unnötig belasten.  
**Auswirkung:** Bei mehr als 10 aufeinanderfolgenden Fehlversuchen ist ein manueller
Neustart erforderlich. Der Server-Modus ist davon nicht betroffen (lauscht unbegrenzt).

---

## 6. `check_hostname` deaktiviert im TLS-Client

**Beschreibung:** Der TLS-Client prüft nicht, ob der CN oder ein SAN des Peer-Zertifikats mit der Ziel-IP-Adresse übereinstimmt (`netzwerk.py` – `kontext.check_hostname = False`).  
**Ursache:** Python verlangt für IP-basierte Verbindungen einen expliziten `IP:`-SAN-Eintrag im Zertifikat. Da die aktuellen Zertifikate (`zertifikate_erstellen.sh`) keinen SAN enthalten, würde `check_hostname = True` den Verbindungsaufbau sofort abbrechen.  
**Ausnutzbarkeit:** Die Schwachstelle setzt voraus, dass ein Angreifer ein **gültiges CA-signiertes Zertifikat** vorlegen kann. Da der mTLS-Handshake `CERT_REQUIRED` erzwingt, schlägt jeder Verbindungsversuch ohne CA-signiertes Zertifikat bereits vor der Hostname-Prüfung fehl. Solange kein Angreifer Zugriff auf den CA-Schlüssel hat, ist die Limitierung **nicht ausnutzbar**. Im isolierten VirtualBox Internal Network, wo der CA-Schlüssel lokal auf den VMs verbleibt, ist diese Bedingung erfüllt.  
**Restrisiko:** Wird der CA-Schlüssel kompromittiert (z. B. durch unsichere HTTP-Übertragung, siehe Punkt 8), kann ein Angreifer ein eigenes CA-signiertes Zertifikat ausstellen und die fehlende Hostname-Prüfung ausnutzen, um einen MITM-Angriff durchzuführen.  

---

## 7. CA-Schlüssel wird während des Setups übertragen

**Beschreibung:** Im empfohlenen Laborworkflow überträgt Peer A den privaten CA-Schlüssel (`ca_schluessel.pem`) per HTTP an Peer B, damit Peer B sein Peer-Zertifikat selbst signieren kann.  
**Ursache:** Das Skript `certs/zertifikate_erstellen.sh --nur-peer-cert` benötigt sowohl `ca_zertifikat.pem` als auch `ca_schluessel.pem`, um die CSR zu signieren. Der HTTP-Transfer ist unverschlüsselt.  
**Auswirkung:** Wer den CA-Schlüssel besitzt, kann beliebige Zertifikate ausstellen und sich so als gültiger Peer ausgeben. Im isolierten VirtualBox Internal Network ist das Risiko gering, in offenen Netzen jedoch kritisch.  
**Abhilfe:** CA-Schlüssel per SCP (SSH-verschlüsselt) oder physisch (USB) übertragen; nach dem Setup auf beiden VMs löschen. Alternativ: Peer A signiert die CSR von Peer B zentral, ohne den CA-Schlüssel zu verteilen.
