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
        VM1:  python3 hauptprogramm.py --ziel <IP_VM2> --port 6769
        VM2:  python3 hauptprogramm.py --ziel <IP_VM1> --port 6769
        Die Server/Client-Rolle wird automatisch bestimmt.

    Manueller Modus (rückwärtskompatibel):
        Server:  python3 hauptprogramm.py --modus server --port 6769
        Client:  python3 hauptprogramm.py --modus client --ziel 192.168.56.101 --port 6769

    Optionen:
        --ziel    IP-Adresse des anderen Peers (Race-to-Connect-Modus)
        --modus   server|client  (manueller Modus, rückwärtskompatibel)
        --port    TCP-Port       (Standard: 6769)
        --name    Anzeigename    (Standard: "Peer", "Server" oder "Client")
        --debug   DEBUG-Logging  (Standard: INFO)
"""

import argparse
import asyncio
import logging
import sys

import konfig
import konsole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging-Initialisierung
# ---------------------------------------------------------------------------

def _logging_initialisieren(level: str) -> None:
    """Konfiguriert das Logging-System für die gesamte Anwendung."""
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
            "  Auto (empfohlen): VM1: python3 hauptprogramm.py --ziel <IP_VM2>\n"
            "                    VM2: python3 hauptprogramm.py --ziel <IP_VM1>\n"
            "  Manuell (Server): python3 hauptprogramm.py --modus server\n"
            "  Manuell (Client): python3 hauptprogramm.py --modus client --ziel 192.168.56.101"
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
        help="Aktiviert DEBUG-Log-Level (Standard: INFO)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

async def main() -> None:
    """Parst Argumente, initialisiert Logging und startet den gewählten Modus."""
    args = _argumente_parsen()

    log_level = "DEBUG" if args.debug else konfig.LOG_LEVEL
    _logging_initialisieren(log_level)

    # 1. Auto-Modus (Race to Connect): --ziel angegeben, kein --modus
    if args.ziel and not args.modus:
        name = args.name or "Peer"
        logger.info(
            "Starte P2P-Chat im Auto-Modus (Ziel: %s, Name: %s, Port: %d)",
            args.ziel, name, args.port,
        )
        await konsole.peer_starten(args.ziel, args.port, name)
        return

    # 2. Manueller Modus (rückwärtskompatibel): --modus server|client
    if not args.modus:
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

    name = args.name or ("Server" if args.modus == "server" else "Client")
    logger.info(
        "Starte P2P-Chat im manuellen %s-Modus (Name: %s, Port: %d)",
        args.modus.upper(), name, args.port,
    )

    if args.modus == "server":
        await konsole.server_starten(args.port, name)
    else:
        await konsole.client_starten(args.ziel, args.port, name)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
