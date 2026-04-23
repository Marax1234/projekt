# KI-Nutzungsdokumentation – LastRowChat (01.04.2026 – 21.04.2026)

**Projekt:** DHBW NetSec 2026 – Gruppe 2  
**Dokumentiert am:** 23.04.2026  
**Dieses Dokument wurde mit Unterstützung von:** Anthropic · Claude Sonnet 4.6 · 23.04.2026

Nachfolgend sind die Arbeitsphasen aufgeführt, in denen KI bei der Code-Implementierung oder Fehlerbehebung eingesetzt wurde. Nicht aufgeführte Teilaufgaben wurden eigenständig von den Projektmitgliedern bearbeitet.

---

## Dokumentierte KI-Nutzung

### 1 · 07.04.2026 – Zertifikatsskript: certs/zertifikate_erstellen.sh

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 07.04.2026 |
| **Umfang** | Teilweise KI-generiert |

KI generierte die `openssl`-Befehlssequenz für CA-Erstellung, Peer-CSR und CA-Signierung. Die Befehle wurden in `certs/zertifikate_erstellen.sh` integriert.

---

### 2 · 09.04.2026 – ACK-Implementierung: sitzung.py (chat_senden, _ack_queue)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 09.04.2026 |
| **Umfang** | Teilweise KI-generiert |

KI implementierte das Future-basierte ACK-Warte-Muster in `sitzung.py`: Sender registriert ein `asyncio.Future` unter der `msg_id`; Empfänger löst es per `APP_MSG_ACK` auf. Bei Timeout → Verbindungsabbau.

---

### 3 · 10.04.2026 – Deduplizierung: sitzung.py (_seen_ids)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 10.04.2026 |
| **Umfang** | Teilweise KI-generiert |

KI implementierte den `collections.OrderedDict`-FIFO-Cache für empfangene `msg_id`s mit fester Maximalgröße (`DEDUP_MAX_IDS`) in `sitzung.py`.

---

### 4 · 11.04.2026 – Reconnect-Backoff: netzwerk.py

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 11.04.2026 |
| **Umfang** | Teilweise KI-generiert |

KI implementierte die Backoff-Formel `min(basis * 2^versuch + random_jitter, max_wartezeit)` sowie die `MAX_RECONNECT_VERSUCHE`-Abbruchbedingung in `netzwerk.py`.

---

### 5 · 12.04.2026 – Bugfix: EOF-Behandlung in der Empfangsschleife (sitzung.py)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 12.04.2026 |
| **Umfang** | KI-generierter Bugfix |

Unbehandelter `IncompleteReadError` beim abrupten Verbindungsabbruch. KI ergänzte `try/except (asyncio.IncompleteReadError, ConnectionResetError)` als sauberen Abbruch-Pfad in der Empfangsschleife.

---

### 6 · 16.04.2026 – Bugfix: asyncio.get_event_loop() → get_running_loop() (sitzung.py)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 16.04.2026 |
| **Umfang** | KI-generierter Bugfix |

`asyncio.get_event_loop().time()` verursachte `DeprecationWarning` in Python 3.10+. KI korrigierte alle drei betroffenen Stellen in `sitzung.py` auf `asyncio.get_running_loop().time()`.

---

### 7 · 16.04.2026 – mTLS-Implementierung: netzwerk.py, konfig.py

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 16.04.2026 |
| **Umfang** | Teilweise KI-generiert |

KI implementierte `tls_kontext_server` und `tls_kontext_client` in `netzwerk.py` (TLS 1.3, `CERT_REQUIRED`, beidseitige CA-Verifikation) sowie die zugehörigen Pfad-Konstanten in `konfig.py`.

---

### 8 · 19.04.2026 – Bugfix: ACK-Queue-Blockierung im CLI-Modus (cli_ui.py)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 19.04.2026 |
| **Umfang** | KI-generierter Bugfix |

`chat_senden()` blockierte dauerhaft, da eingehende `APP_MSG_ACK`-Pakete ohne Empfangsschleife nie verarbeitet wurden. KI ergänzte einen parallelen Empfangs-Task in `cli_ui.py`.

---

### 9 · 20.04.2026 – TUI-Implementierung: curses-Ausgabe (cli_ui.py)

| | |
|---|---|
| **Anbieter** | Anthropic |
| **Modell** | Claude Sonnet 4.6 |
| **Datum** | 20.04.2026 |
| **Umfang** | Teilweise KI-generiert |

Gleichzeitige Ausgabe von Netzwerk- und Eingabe-Thread zeriss die Eingabezeile. KI implementierte die `curses`-basierte TUI (geteiltes Terminal: Ausgabefenster / Eingabezeile) in `cli_ui.py` ausschließlich mit der Python-Standardbibliothek.

---

## Erklärung

Die genannten Tätigkeiten wurden mithilfe von **Claude Sonnet 4.6 (Anthropic)** unterstützt. Architektur-, Design- und Analyseentscheidungen wurden eigenständig von den Mitgliedern der Gruppe 2 erarbeitet.
