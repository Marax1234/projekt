# KI-Nutzung – Implementierungshinweise

Dieses Dokument kennzeichnet den Einsatz von KI-Werkzeugen im Rahmen des Projekts. 

---

## 01.04.2026

Grundstruktur des Projekts aufgebaut: Modulaufteilung, zentrale Konfigurationskonstanten (`konfig.py`) sowie Basisgerüst für den Einstiegspunkt (`hauptprogramm.py`) inklusive Argument-Parsing und Logging-Initialisierung.

*Claude Sonnet 4.6, Anthropic*

---

## 03.04.2026

TLS-Kontexte für Server und Client implementiert (`netzwerk.py`): Konfiguration von mTLS (gegenseitige Zertifikatsverifikation, TLS 1.3 als Minimum) unter Nutzung des Python-`ssl`-Moduls.

*Claude Sonnet 4.6, Anthropic*

---

## 05.04.2026

NDJSON-Framing-Schicht fertiggestellt: Implementierung von `frame_senden` und `frame_empfangen` mit Größenbegrenzung (`MAX_FRAME_BYTES`) und dedizierter Timeout-Behandlung.

*Claude Sonnet 4.6, Anthropic*

---

## 07.04.2026

Race-to-Connect-Algorithmus (`auto_verbinden`) implementiert: Beide Peers starten gleichzeitig Server- und Client-Tasks; der erste erfolgreiche Verbindungsaufbau gewinnt und bricht den jeweils anderen Task ab.

*Claude Sonnet 4.6, Anthropic*

---

## 09.04.2026

Zustandsmaschine für das Sitzungsprotokoll entworfen und umgesetzt (`sitzung.py`): Sieben Zustände (`GETRENNT` bis `SCHLIESSEN`) sowie die Basisklasse `Sitzung` mit zugehörigen Enum-Typen.

*Claude Sonnet 4.6, Anthropic*

---

## 11.04.2026

Anwendungs-Handshake implementiert: Server- und Client-seitiger Austausch von `APP_HELLO` / `APP_HELLO_ACK` mit Session-ID-Bindung und Protokollversionsprüfung.

*Claude Sonnet 4.6, Anthropic*

---

## 13.04.2026

Nachrichtenversand mit ACK-Bestätigung realisiert: `chat_senden` wartet auf `APP_MSG_ACK` mit konfiguriertem Timeout; der Empfangs- und Dispatch-Loop (`_receiver_loop`) routet eingehende Frames nach Typ.

*Claude Sonnet 4.6, Anthropic*

---

## 15.04.2026

Heartbeat-Mechanismus fertiggestellt (`_heartbeat_loop`): Sendet `APP_PING` bei Inaktivität, wertet `APP_PONG`-Antworten aus und löst nach maximal zwei ausgebliebenen Antworten eine kontrollierte Trennung aus.

*Claude Sonnet 4.6, Anthropic*

---

## 17.04.2026

Nachrichtendeduplication und Outbox-Logik ergänzt: `_seen_ids` verhindert doppelte Verarbeitung per OrderedDict (FIFO, 1000 Einträge); `_outbox` speichert unbestätigte Nachrichten für eine Wiederholung nach Reconnect.

*Claude Sonnet 4.6, Anthropic*

---

## 19.04.2026

Betriebsmodi Server und Client implementiert (`konsole.py`): `server_starten` akzeptiert genau eine eingehende Verbindung; `client_starten` verbindet sich zu einem bekannten Ziel – jeweils mit Reconnect-Schleife und exponentiellem Backoff.

*Claude Sonnet 4.6, Anthropic*

---

## 20.04.2026

Peer-Modus und übergeordnete Chat-Schleife (`_chat_sitzung_fuehren`) abgeschlossen: Koordination von Empfangs-Task und asynchroner Eingabe; semantische Trennmeldungen auf Basis des Sitzungs-Trenngrunds.

*Claude Sonnet 4.6, Anthropic*

---

## 21.04.2026

Curses-basierte Terminal-UI entwickelt (`cli_ui.py`): Dreigeteiltes Layout (Chat-Fenster, Statuszeile, Eingabezeile) mit Threading-Lock für nebenläufig sicheres Rendering.

*Claude Sonnet 4.6, Anthropic*

---

## 22.04.2026

Asynchrone Eingabebehandlung und Gesamtintegration abgeschlossen: `eingabe_prompt` als thread-sicherer asyncio-Einstiegspunkt; Zusammenführung aller Module im Hauptprogramm mit TUI-Initialisierung via `curses.wrapper`.

*Claude Sonnet 4.6, Anthropic*

---


