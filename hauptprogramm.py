"""
hauptprogramm.py – Entry-Point, argparse, Orchestrierung

Beschreibung: Einstiegspunkt der Anwendung. Parst Kommandozeilenargumente,
              initialisiert Logging, registriert Signal-Handler und startet
              die Anwendung im GUI-, Server- oder Client-Modus.

              Konsolenbetrieb:  konsole.py  (server_starten / client_starten)
              Terminal-UI:      cli_ui.py   (Box-Chars, figlet-Banner)
              Grafische UI:     gui.py      (Tkinter, nur mit --gui geladen)

Autor:        Gruppe 2
Datum:        2026-03-26
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
import sys

import konfig
import konsole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging-Initialisierung
# ---------------------------------------------------------------------------

def _logging_initialisieren(level: str) -> None:
    """Konfiguriert das Logging-System für die gesamte Anwendung.

    Parameter:
        level: Log-Level als String (DEBUG, INFO, WARNING, ERROR)
    """
    numerischer_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numerischer_level,
        format=konfig.LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(konfig.LOG_DATEINAME, encoding="utf-8"),
        ],
    )
    logger.debug("Logging initialisiert mit Level: %s", level.upper())


# ---------------------------------------------------------------------------
# Argument-Parser
# ---------------------------------------------------------------------------

def _argumente_parsen() -> argparse.Namespace:
    """Parst die Kommandozeilenargumente und gibt ein Namespace-Objekt zurück."""
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
        help="Startet die grafische Tkinter-Oberfläche (--modus nicht erforderlich)",
    )
    parser.add_argument(
        "--modus",
        choices=["server", "client"],
        required=False,
        default=None,
        help="Betriebsmodus: 'server' lauscht auf Verbindungen, 'client' verbindet sich",
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
        help="Anzeigename für diesen Peer (Standard: 'Server' oder 'Client')",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Aktiviert DEBUG-Log-Level (Standard: INFO)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# GUI-Start (lazy import – tkinter nur laden wenn wirklich benötigt)
# ---------------------------------------------------------------------------

def _gui_starten() -> None:
    """Startet die grafische Tkinter-Oberfläche."""
    try:
        from gui import gui_starten
        gui_starten()
    except ImportError as fehler:
        logger.error("GUI-Modul konnte nicht geladen werden: %s", fehler)
        print("GUI nicht verfügbar – tkinter möglicherweise nicht installiert.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

def main() -> None:
    """Parst Argumente, initialisiert Logging, registriert Signal-Handler
    und startet den gewählten Modus (GUI oder Konsole)."""
    args = _argumente_parsen()

    log_level = "DEBUG" if args.debug else konfig.LOG_LEVEL
    _logging_initialisieren(log_level)

    # GUI-Modus hat Vorrang
    if args.gui:
        logger.info("Starte P2P-Chat im GUI-Modus (Port: %d)", args.port)
        _gui_starten()
        return

    # Konsolenmodus: --modus ist Pflichtangabe
    if not args.modus:
        logger.error("--modus (server|client) oder --gui ist erforderlich")
        print("Fehler: --modus server|client angeben oder --gui für die GUI nutzen.")
        sys.exit(1)

    if args.modus == "client" and not args.ziel:
        logger.error("Im Client-Modus ist --ziel (IP-Adresse des Servers) erforderlich")
        print("Fehler: --ziel IP-Adresse angeben (z. B. --ziel 192.168.56.101)")
        sys.exit(1)

    name = args.name or ("Server" if args.modus == "server" else "Client")
    logger.info(
        "Starte P2P-Chat im %s-Modus (Name: %s, Port: %d)",
        args.modus.upper(), name, args.port,
    )

    if args.modus == "server":
        konsole.server_starten(args.port, name)
    else:
        konsole.client_starten(args.ziel, args.port, name)


if __name__ == "__main__":
    main()
