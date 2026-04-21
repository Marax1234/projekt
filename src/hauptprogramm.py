"""
hauptprogramm.py – Entry-Point, argparse, Orchestrierung

Beschreibung: Einstiegspunkt der Anwendung. Parst Kommandozeilenargumente,
              initialisiert Logging, und startet die Anwendung via asyncio.run().

              Konsolenbetrieb:  konsole.py  (peer_starten / server_starten / client_starten)
              Terminal-UI:      cli_ui.py   (Box-Chars, figlet-Banner)

Autor:        Gruppe 2
Datum:        2026-03-26
Modul:        Network Security 2026

Verwendung:
    Auto-Modus (Race to Connect) – beide Peers starten gleichzeitig:
        VM1:  python3 src/hauptprogramm.py --ziel <IP_VM2> --port 49200
        VM2:  python3 src/hauptprogramm.py --ziel <IP_VM1> --port 49200
        Die Server/Client-Rolle wird automatisch bestimmt.

    Manueller Modus (rückwärtskompatibel):
        Server:  python3 src/hauptprogramm.py --modus server --port 49200
        Client:  python3 src/hauptprogramm.py --modus client --ziel 192.168.56.101 --port 49200

    Optionen:
        --ziel    IP-Adresse des anderen Peers (Race-to-Connect-Modus)
        --modus   server|client  (manueller Modus, rückwärtskompatibel)
        --port    TCP-Port       (Standard: 49200)
        --name    Anzeigename    (Standard: "Peer", "Server" oder "Client")
        --debug   DEBUG-Logging  (Standard: WARNING)
"""

import argparse
import asyncio
import curses
import logging
import sys

import cli_ui
import konfig
import konsole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging-Initialisierung
# ---------------------------------------------------------------------------

def _logging_initialisieren(level: str) -> None:
    """Konfiguriert das Logging-System für die gesamte Anwendung.

    Im Normalbetrieb werden Logs ausschließlich in die Datei geschrieben, damit
    kein Logger-Output die CLI-Ausgabe verschmutzt. Mit --debug wird zusätzlich
    auf stdout geloggt.
    """
    numerischer_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [
        logging.FileHandler(konfig.LOG_DATEINAME, encoding="utf-8"),
    ]
    if level.upper() == "DEBUG":
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=numerischer_level,
        format=konfig.LOG_FORMAT,
        handlers=handlers,
    )
    logger.debug("Logging initialisiert mit Level: %s", level.upper())


# ---------------------------------------------------------------------------
# Argument-Parser
# ---------------------------------------------------------------------------

def _argumente_parsen() -> argparse.Namespace:
    """Parst die Kommandozeilenargumente und gibt ein Namespace-Objekt zurück."""
    parser = argparse.ArgumentParser(
        prog="hauptprogramm.py",
        description="LastRowChat-Protokoll – Network Security 2026",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  Auto (empfohlen): VM1: python3 src/hauptprogramm.py --ziel <IP_VM2>\n"
            "                    VM2: python3 src/hauptprogramm.py --ziel <IP_VM1>\n"
            "  Manuell (Server): python3 src/hauptprogramm.py --modus server\n"
            "  Manuell (Client): python3 src/hauptprogramm.py --modus client --ziel 192.168.56.101"
        ),
    )
    parser.add_argument(
        "--ziel",
        metavar="IP",
        default=None,
        help=(
            "IP-Adresse des anderen Peers. Im Auto-Modus (ohne --modus) starten "
            "beide Peers gleichzeitig mit der IP des jeweils anderen."
        ),
    )
    parser.add_argument(
        "--modus",
        choices=["server", "client"],
        required=False,
        default=None,
        help=(
            "Optionaler manueller Modus (rückwärtskompatibel): "
            "'server' lauscht, 'client' verbindet. Ohne --modus: Race-to-Connect."
        ),
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
        help="Anzeigename für diesen Peer (Standard: 'Peer', 'Server' oder 'Client')",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Aktiviert DEBUG-Log-Level (Standard: WARNING)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

def main() -> None:
    """Parst Argumente, zeigt Banner, fragt Benutzernamen und startet die curses-TUI.

    Die Abfrage des Benutzernamens und der Banner werden vor ``curses.wrapper()``
    ausgegeben, sodass normales print()/input() möglich ist. Danach übernimmt
    curses.wrapper() die Terminal-Steuerung und setzt das Terminal beim Beenden
    (auch bei Absturz) zuverlässig zurück.
    """
    args = _argumente_parsen()

    log_level = "DEBUG" if args.debug else konfig.LOG_LEVEL
    _logging_initialisieren(log_level)

    # Modus-Validierung vor TUI-Start
    if not args.modus and not args.ziel:
        logger.error("Kein Modus angegeben: --ziel IP oder --modus server|client")
        print(
            "Fehler: Bitte angeben:\n"
            "  Auto-Modus:  --ziel <IP_des_anderen_Peers>\n"
            "  Manuell:     --modus server|client"
        )
        sys.exit(1)

    if args.modus == "client" and not args.ziel:
        logger.error("Im Client-Modus ist --ziel (IP-Adresse des Servers) erforderlich")
        print("Fehler: --ziel IP-Adresse angeben (z. B. --ziel 192.168.56.101)")
        sys.exit(1)

    # Standard-Anzeigename ermitteln
    if args.ziel and not args.modus:
        standard_name = "Peer"
    elif args.modus == "server":
        standard_name = "Server"
    else:
        standard_name = "Client"

    # Pre-TUI: Banner und Benutzernamen-Abfrage (nutzt print/input vor curses)
    cli_ui.banner_anzeigen()
    print()
    name = args.name or cli_ui.username_abfragen(standard_name)

    logger.info(
        "Starte LastRowChat (Modus: %s, Name: %s, Port: %d)",
        args.modus or "auto", name, args.port,
    )

    # Innere asynchrone Chat-Funktion – läuft innerhalb der TUI
    async def _chat() -> None:
        if args.ziel and not args.modus:
            await konsole.peer_starten(args.ziel, args.port, name)
        elif args.modus == "server":
            await konsole.server_starten(args.port, name)
        else:
            await konsole.client_starten(args.ziel, args.port, name)

    # curses.wrapper initialisiert ncurses, ruft _curses_main auf und stellt
    # das Terminal beim Beenden (auch bei Exception) sauber wieder her.
    def _curses_main(stdscr) -> None:
        cli_ui.tui_starten(stdscr)
        asyncio.run(_chat())

    try:
        curses.wrapper(_curses_main)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
