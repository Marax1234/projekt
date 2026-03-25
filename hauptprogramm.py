"""
hauptprogramm.py – Entry-Point, argparse, Orchestrierung

Beschreibung: Einstiegspunkt der Anwendung. Parst Kommandozeilenargumente,
              initialisiert Logging, und startet die Anwendung im Server- oder
              Client-Modus. Orchestriert netzwerk.py und sitzung.py fuer den
              vollstaendigen P2P-Chat-Lebenszyklus.

              Sprint 4: Signal-Handler (SIGINT/SIGTERM), exponentieller Backoff
              fuer Reconnect, EMPFANG_TIMEOUT fuer Server-Loop, nutzerfreundliche
              Fehlermeldungen ohne Traceback.

              Sprint 5: --gui Flag fuer grafische Tkinter-Oberflaeche.

Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Verwendung:
    GUI-Modus (empfohlen):
        python3 hauptprogramm.py --gui

    Server (Konsolenmodus):
        python3 hauptprogramm.py --modus server --port 6769

    Client (Konsolenmodus):
        python3 hauptprogramm.py --modus client --ziel 192.168.56.101 --port 6769

    Optionen:
        --gui     Startet die Tkinter-GUI (kein --modus erforderlich)
        --modus   server|client  (Pflichtangabe im Konsolenmodus)
        --ziel    IP-Adresse     (nur Client, Pflichtangabe im Client-Modus)
        --port    TCP-Port       (Standard: 6769)
        --name    Anzeigename    (Standard: "Server" oder "Client")
        --debug   DEBUG-Logging  (Standard: INFO)
"""

import argparse
import logging
import signal
import sys
import threading
import time

import konfig
from netzwerk import server_erstellen, verbindung_akzeptieren, verbindung_herstellen
from sitzung import Sitzung, SitzungsZustand

# Modul-Logger
logger = logging.getLogger(__name__)

# Globale Referenz auf aktive Sitzung – ermoeglicht Zugriff aus Signal-Handler
_aktive_sitzung: Sitzung | None = None


# ---------------------------------------------------------------------------
# Signal-Handler (Task 4.3)
# ---------------------------------------------------------------------------

def _signal_handler(sig: int, _frame) -> None:
    """Faengt SIGINT und SIGTERM ab, sendet DISCONNECT und beendet sauber.

    Parameter:
        sig:    Empfangenes Signal (z. B. signal.SIGINT = 2)
        _frame: Aktueller Stack-Frame (nicht verwendet)
    """
    logger.info("Signal %d empfangen – leite graceful shutdown ein", sig)
    _benutzer_meldung("Programm wird beendet – sende DISCONNECT ...")

    if _aktive_sitzung is not None and _aktive_sitzung.zustand == SitzungsZustand.VERBUNDEN:
        try:
            _aktive_sitzung.verbindungsabbau()
        except Exception as fehler:
            logger.warning("Fehler beim Verbindungsabbau im Signal-Handler: %s", fehler)

    sys.exit(0)


# ---------------------------------------------------------------------------
# Nutzer-Meldungen (Task 4.4)
# ---------------------------------------------------------------------------

def _benutzer_meldung(text: str) -> None:
    """Gibt eine lesbare, traceback-freie Meldung fuer den Nutzer aus.

    Netzwerkfehler sollen dem Nutzer als klarer Hinweistext erscheinen,
    nicht als Python-Exception-Stack. Technische Details landen im Log.

    Parameter:
        text: Lesbare Meldung (kein Traceback, keine internen Bezeichnungen)
    """
    logger.info("[MELDUNG] %s", text)


# ---------------------------------------------------------------------------
# Logging-Initialisierung
# ---------------------------------------------------------------------------

def logging_initialisieren(level: str) -> None:
    """Konfiguriert das Logging-System fuer die gesamte Anwendung.

    Parameter:
        level: Log-Level als String (DEBUG, INFO, WARNING, ERROR)
    """
    numerischer_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numerischer_level,
        format=konfig.LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),       # Ausgabe auf Konsole
            logging.FileHandler(konfig.LOG_DATEINAME, encoding="utf-8"),  # Log-Datei
        ],
    )
    logger.debug("Logging initialisiert mit Level: %s", level.upper())


# ---------------------------------------------------------------------------
# Server-Modus (Task 4.1, 4.2, 4.3, 4.4)
# ---------------------------------------------------------------------------

def server_starten(port: int, name: str) -> None:
    """Startet die Anwendung im Server-Modus.

    Lauscht dauerhaft auf neue Verbindungen. Nach einem Verbindungsabbau (normal
    oder durch Fehler) wartet der Server sofort auf den naechsten Client. Das
    ermoeglicht Reconnect-Szenarien ohne Neustart des Server-Prozesses.

    Zustandsautomat:
        Warte → Verbunden → (Nachrichtenloop) → Getrennt → Warte → ...

    Parameter:
        port: TCP-Port auf dem gelauscht wird
        name: Anzeigename fuer Log-Ausgaben
    """
    global _aktive_sitzung

    try:
        srv_socket = server_erstellen()
    except OSError as fehler:
        logger.error("Server-Socket konnte nicht erstellt werden: %s", fehler)
        _benutzer_meldung(f"Port {port} kann nicht gebunden werden. Laeuft bereits ein Server?")
        sys.exit(1)

    logger.info("Warte auf Verbindungen auf Port %d ...", port)
    _benutzer_meldung(f"Server bereit auf Port {port}. Warte auf Client-Verbindung.")

    try:
        # Aeussere Schleife: nach jedem Disconnect neuen Client akzeptieren
        while True:
            try:
                verbindung, adresse = verbindung_akzeptieren(srv_socket)
            except KeyboardInterrupt:
                # Ctrl+C waehrend accept(): sauber beenden (Signal-Handler hat Vorrang,
                # aber accept() blockiert das Signal – daher hier auch abfangen)
                logger.info("Verbindungsannahme unterbrochen")
                break
            except Exception as fehler:
                logger.error("Fehler beim Akzeptieren der Verbindung: %s", fehler)
                _benutzer_meldung("Verbindungsannahme fehlgeschlagen – beende Server.")
                break

            logger.info("TCP/TLS-Verbindung von %s akzeptiert", adresse[0])

            sitzung = Sitzung(verbindung, absender_name=name, server_modus=True)
            _aktive_sitzung = sitzung

            # Protokoll-Handshake: CONNECT empfangen, ACK senden
            if not sitzung.verbindungsaufbau():
                logger.error("Protokoll-Handshake mit %s fehlgeschlagen", adresse[0])
                _benutzer_meldung("Handshake fehlgeschlagen – warte auf naechsten Client.")
                _aktive_sitzung = None
                continue  # Naechsten Client erwarten

            _benutzer_meldung(f"Client verbunden von {adresse[0]}. Empfange Nachrichten ...")

            # Nachrichten-Empfangsschleife mit Timeout-Behandlung (Task 4.1)
            while sitzung.zustand == SitzungsZustand.VERBUNDEN:
                nachricht = sitzung.nachricht_empfangen()
                # nachricht_empfangen() gibt None zurueck bei:
                #   - DISCONNECT empfangen → Zustand wechselt zu GETRENNT
                #   - Timeout (EMPFANG_TIMEOUT) → Zustand bleibt VERBUNDEN
                #   - Schwerer Netzwerkfehler → Zustand wechselt zu GETRENNT

                if nachricht is None:
                    if sitzung.zustand == SitzungsZustand.GETRENNT:
                        # Normaler Abbau oder Verbindungsfehler
                        _benutzer_meldung(
                            "Verbindung beendet. Warte auf naechsten Client."
                        )
                    else:
                        # Timeout: kein Paket empfangen, aber Verbindung noch aktiv
                        logger.debug("Empfangs-Timeout – Verbindung noch aktiv, weiter warten")
                    break  # Innere Schleife verlassen, aeussere Schleife prueft Zustand

                # Empfangene Nachricht ausgeben
                absender = nachricht.get("absender", "Unbekannt")
                zeitstempel = nachricht.get("zeitstempel", "")
                text = nachricht.get("nachricht", "")
                logger.info("[%s] %s: %s", zeitstempel, absender, text)

            _aktive_sitzung = None

    finally:
        srv_socket.close()
        logger.info("Server-Socket geschlossen")

    logger.info("Server-Sitzung beendet")


# ---------------------------------------------------------------------------
# Client-Modus (Task 4.1, 4.2, 4.3, 4.4)
# ---------------------------------------------------------------------------

def client_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Client-Modus.

    Versucht die Verbindung mit exponentiellem Backoff (Task 4.2):
        Versuch 1: sofort
        Versuch 2: nach 1s
        Versuch 3: nach 2s
        Versuch 4: nach 4s
        Versuch 5: nach 8s → Abbruch

    Nach erfolgreichem Verbindungsaufbau: interaktive Eingabeschleife.
    Bei Verbindungsverlust: lesbare Meldung statt Traceback (Task 4.4).

    Parameter:
        ziel: IP-Adresse oder Hostname des Servers
        port: TCP-Port des Servers
        name: Anzeigename fuer Nachricht-Payloads
    """
    global _aktive_sitzung

    # --- Task 4.2: Reconnect-Schleife mit exponentiellem Backoff ---
    wartezeit = konfig.BACKOFF_BASIS  # Startwartezeit: 1s
    verbindung = None

    for versuch in range(konfig.RECONNECT_MAX_VERSUCHE + 1):
        # Versuch 0 ist der erste (sofortige) Versuch; Versuche 1-4 kommen nach Backoff
        if versuch > 0:
            logger.warning(
                "Reconnect-Versuch %d/%d – naechster Versuch in %.0fs",
                versuch, konfig.RECONNECT_MAX_VERSUCHE, wartezeit,
            )
            _benutzer_meldung(
                f"Verbindung fehlgeschlagen – Wiederholung in {wartezeit:.0f}s "
                f"(Versuch {versuch}/{konfig.RECONNECT_MAX_VERSUCHE})"
            )
            time.sleep(wartezeit)
            wartezeit = min(wartezeit * konfig.BACKOFF_FAKTOR, konfig.BACKOFF_MAX)

        try:
            verbindung = verbindung_herstellen(ziel, port)
            logger.info("Verbindung zu %s:%d hergestellt (Versuch %d)", ziel, port, versuch + 1)
            break  # Verbindung erfolgreich – Schleife verlassen
        except Exception as fehler:
            logger.error(
                "Verbindungsversuch %d zu %s:%d fehlgeschlagen: %s",
                versuch + 1, ziel, port, fehler,
            )
            if versuch == konfig.RECONNECT_MAX_VERSUCHE:
                # Alle Versuche erschoepft
                _benutzer_meldung(
                    f"Verbindung zu {ziel}:{port} nicht moeglich – alle "
                    f"{konfig.RECONNECT_MAX_VERSUCHE + 1} Versuche fehlgeschlagen."
                )
                return

    if verbindung is None:
        # Sollte durch obige Logik nie erreicht werden
        logger.error("Verbindung nach Backoff-Schleife immer noch None")
        return

    sitzung = Sitzung(verbindung, absender_name=name, server_modus=False)
    _aktive_sitzung = sitzung

    # Protokoll-Handshake: CONNECT senden, ACK empfangen
    if not sitzung.verbindungsaufbau():
        logger.error("Protokoll-Handshake (CONNECT/ACK) fehlgeschlagen")
        _benutzer_meldung("Verbindungsaufbau mit Server fehlgeschlagen.")
        _aktive_sitzung = None
        return

    logger.info("Verbunden mit %s:%d. Nachrichten eingeben, 'quit' zum Beenden.", ziel, port)
    logger.info("-" * 60)

    # Eigene Empfangsschleife im Hintergrund, damit ACKs/Nachrichten auch waehrend
    # blockierender input()-Aufrufe verarbeitet werden.
    stop_event = threading.Event()

    def _empfangs_thread() -> None:
        while not stop_event.is_set() and sitzung.zustand == SitzungsZustand.VERBUNDEN:
            nachricht = sitzung.nachricht_empfangen()

            if nachricht is None:
                if sitzung.zustand == SitzungsZustand.GETRENNT:
                    _benutzer_meldung("Verbindung wurde vom Peer beendet.")
                    break
                continue

            absender = nachricht.get("absender", "Unbekannt")
            zeitstempel = nachricht.get("zeitstempel", "")
            text = nachricht.get("nachricht", "")
            logger.info("[%s] %s: %s", zeitstempel, absender, text)

    empfang_thread = threading.Thread(
        target=_empfangs_thread,
        daemon=True,
        name="CLI-EmpfangsThread",
    )
    empfang_thread.start()

    # Interaktive Eingabeschleife
    while sitzung.zustand == SitzungsZustand.VERBUNDEN:
        try:
            eingabe = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            # Ctrl+D oder Ctrl+C: sauberer Abbruch (Signal-Handler sendet DISCONNECT)
            logger.info("Eingabe unterbrochen – trenne Verbindung")
            break

        if not eingabe:
            continue  # Leere Eingabe ignorieren

        if eingabe.lower() in ("quit", "exit", "q"):
            logger.info("Nutzer hat Verbindungsabbau angefordert")
            break

        # Nachricht senden (nachricht_senden hat eigene Retry-Logik)
        if not sitzung.nachricht_senden(eingabe):
            logger.error("Nachricht konnte nicht gesendet werden – Verbindung verloren")
            _benutzer_meldung("Nachricht konnte nicht uebertragen werden – Verbindung getrennt.")
            break

    stop_event.set()

    # Verbindung sauber abbauen falls noch aktiv (DISCONNECT + ACK)
    if sitzung.zustand == SitzungsZustand.VERBUNDEN:
        sitzung.verbindungsabbau()

    _aktive_sitzung = None
    logger.info("Client-Sitzung beendet")


# ---------------------------------------------------------------------------
# Argument-Parser
# ---------------------------------------------------------------------------

def argumente_parsen() -> argparse.Namespace:
    """Parst die Kommandozeilenargumente und gibt ein Namespace-Objekt zurueck.

    Rueckgabe:
        Geparste Argumente als argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        prog="hauptprogramm.py",
        description="P2P-Chat-Protokoll – Network Security 2026",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  Server:  python3 hauptprogramm.py --modus server --port 6769\n"
            "  Client:  python3 hauptprogramm.py --modus client --ziel 192.168.56.101 --port 6769"
        ),
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        default=False,
        help="Startet die grafische Tkinter-Oberflaeche (--modus nicht erforderlich)",
    )
    parser.add_argument(
        "--modus",
        choices=["server", "client"],
        required=False,
        default=None,
        help="Betriebsmodus: 'server' lauscht auf Verbindungen, 'client' verbindet sich "
             "(Pflichtangabe im Konsolenmodus, nicht benoetigt mit --gui)",
    )
    parser.add_argument(
        "--ziel",
        metavar="IP",
        default=None,
        help="Ziel-IP-Adresse des Servers (nur im Client-Modus erforderlich)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=konfig.PORT,
        help=f"TCP-Port (Standard: {konfig.PORT})",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Anzeigename fuer diesen Peer (Standard: 'Server' oder 'Client')",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Aktiviert DEBUG-Log-Level (Standard: INFO)",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

def gui_starten() -> None:
    """Startet die grafische Tkinter-Oberflaeche (Sprint 5).

    Importiert gui.py lazy (nur wenn --gui angegeben), damit tkinter
    nicht geladen wird wenn nur der Konsolenmodus genutzt wird.
    """
    try:
        from gui import gui_starten as _gui_starten
        _gui_starten()
    except ImportError as fehler:
        logger.error("GUI-Modul konnte nicht geladen werden: %s", fehler)
        _benutzer_meldung("GUI nicht verfuegbar – tkinter moeglicherweise nicht installiert.")
        sys.exit(1)


def main() -> None:
    """Hauptfunktion: Parst Argumente, initialisiert Logging, registriert
    Signal-Handler und startet den gewaehlten Modus (GUI oder Konsole)."""
    args = argumente_parsen()

    # Log-Level festlegen
    log_level = "DEBUG" if args.debug else konfig.LOG_LEVEL
    logging_initialisieren(log_level)

    # Task 4.3: Signal-Handler fuer SIGINT (Ctrl+C) und SIGTERM registrieren
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    logger.debug("Signal-Handler fuer SIGINT und SIGTERM registriert")

    # Sprint 5: GUI-Modus hat Vorrang – kein --modus erforderlich
    if args.gui:
        logger.info("Starte P2P-Chat im GUI-Modus (Port: %d)", args.port)
        gui_starten()
        return

    # Konsolenmodus: --modus ist Pflichtangabe
    if not args.modus:
        logger.error("--modus (server|client) oder --gui ist erforderlich")
        _benutzer_meldung("Fehler: --modus server|client angeben oder --gui fuer die GUI nutzen.")
        sys.exit(1)

    # Validierung: Client benoetigt --ziel
    if args.modus == "client" and not args.ziel:
        logger.error("Im Client-Modus ist --ziel (IP-Adresse des Servers) erforderlich")
        _benutzer_meldung("Fehler: --ziel IP-Adresse angeben (z. B. --ziel 192.168.56.101)")
        sys.exit(1)

    # Anzeigenamen setzen (Standard aus Modus ableiten)
    name = args.name or ("Server" if args.modus == "server" else "Client")

    logger.info(
        "Starte P2P-Chat im %s-Modus (Name: %s, Port: %d)",
        args.modus.upper(), name, args.port,
    )

    if args.modus == "server":
        server_starten(args.port, name)
    else:
        client_starten(args.ziel, args.port, name)


if __name__ == "__main__":
    main()
