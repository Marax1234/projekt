# KI-Nutzung

Im Rahmen dieses Projekts wurde künstliche Intelligenz zur Unterstützung bei der Erstellung von Inhalten eingesetzt.

| Datum | Anbieter | Modell | Zweck |
|-------|----------|--------|-------|
| 16.04.2026 | Anthropic | Claude Sonnet 4.6 | Unterstützung bei Dokumentation (LIMITIERUNGEN.md, aufgabe6.md, CLAUDE.md) |
| 16.04.2026 | Anthropic | Claude Sonnet 4.6 | Analyse des Codes auf Limitierungen für Aufgabe #8 |
| 16.04.2026 | Anthropic | Claude Sonnet 4.6 | Implementierung mTLS (netzwerk.py, konfig.py, zertifikate_erstellen.sh); Aktualisierung LIESMICH.md, LIMITIERUNGEN.md, TECHNISCHE_UEBERSICHT.md |
| 16.04.2026 | Anthropic | Claude Sonnet 4.6 | Robuste Verbindungsverwaltung: EmpfangsTimeout-Klasse, EMPFANG_TIMEOUT-Formel, _geschlossen-Guard, VerbindungsZustand-Enum, semantische Trennmeldungen, exponentieller Backoff mit Jitter, MAX_RECONNECT_VERSUCHE; alle betroffenen Module und Dokumentation aktualisiert |
| 16.04.2026 | Anthropic | Claude Sonnet 4.6 | Code-Review feature.md: asyncio.get_event_loop().time() → get_running_loop().time() in sitzung.py (3 Stellen); LIMITIERUNGEN.md §5 Ursache korrigiert (BIND_ADRESSE statt AF_INET) |
| 20.04.2026 | Anthropic | Claude Sonnet 4.6 | CLI Formattierung. 
Aktuell schreiben sowohl der Netzwerk-Thread (für Statusmeldungen, Heartbeats, Reconnects) als auch der Chat-Thread unkontrolliert in den Standard-Output (stdout). Das führt zu folgenden UI-Problemen: Eintreffende Statusmeldungen (wie Timeouts oder Reconnects) zerreißen die laufende Tastatureingabe des Nutzers. Die Eingabezeile scrollt unkontrolliert nach oben. Es gibt ein lokales Echo: Die rohe Eingabe des Nutzers bleibt nach dem Drücken von Enter im Terminal stehen, und danach wird sie vom Programm nochmals formatiert als Chatnachricht ausgegeben. Deine Aufgabe:
Refaktorisiere den UI-Teil dieses Codes. Nutze dafür ausschließlich das Modul "curses" aus der Python-Standardbibliothek (die App läuft auf Kali Linux, es dürfen keine externen Pakete via pip installiert werden). Die bestehende Netzwerk- und Verbindungslogik soll funktional unangetastet bleiben, aber ihre Ausgaben (print()) müssen an die neue TUI umgeleitet werden. |

## Erklärung

Die genannten Dokumente wurden mithilfe von Claude Sonnet 4.6 (Anthropic) erstellt bzw. überarbeitet. Die inhaltliche Verantwortung sowie die abschließende Prüfung der Korrektheit lagen bei den Projektmitgliedern der Gruppe 2.
