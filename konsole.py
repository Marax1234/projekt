"""
konsole.py – Server- und Client-Modus (Konsolenbetrieb)

Beschreibung: Enthaelt die Startfunktionen fuer den interaktiven Konsolenbetrieb.
              Server-Modus lauscht dauerhaft auf neue Verbindungen; Client-Modus
              verbindet sich einmalig mit dem angegebenen Ziel. Beide nutzen
              cli_ui.py fuer die Terminal-Ausgabe.

Autor:        Gruppe 2
Datum:        2026-03-26
Modul:        Network Security 2026
"""

import logging
import select
import sys
import threading

import cli_ui
from netzwerk import server_erstellen, verbindung_akzeptieren, verbindung_herstellen
from sitzung import Sitzung, SitzungsZustand

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gemeinsame Empfangs-Schleife
# ---------------------------------------------------------------------------

def _empfangs_schleife(sitzung: Sitzung, trenn_ereignis: threading.Event, herkunft: str) -> None:
    """Empfaengt Nachrichten in einem Hintergrund-Thread.

    Laeuft solange die Sitzung aktiv ist. Bei Verbindungsabbruch (Gegenseite
    schliesst Socket) setzt nachricht_empfangen den Zustand auf GETRENNT,
    woraufhin diese Schleife endet und das Trenn-Ereignis ausloest.

    Parameter:
        sitzung:        Aktive Sitzung
        trenn_ereignis: Wird gesetzt, wenn die Verbindung enden soll
        herkunft:       Bezeichnung der Gegenseite fuer Meldungen (z.B. "Client")
    """
    while sitzung.zustand == SitzungsZustand.VERBUNDEN and not trenn_ereignis.is_set():
        nachricht = sitzung.nachricht_empfangen()
        if nachricht is None:
            if sitzung.zustand != SitzungsZustand.VERBUNDEN:
                # Verbindung wurde von der Gegenseite geschlossen
                cli_ui.info_zeile(f"Verbindung vom {herkunft} beendet")
                trenn_ereignis.set()
                return
            continue  # Timeout – Verbindung noch aktiv
        absender    = nachricht.get("absender", "Unbekannt")   # Anzeigename des Senders
        zeitstempel = nachricht.get("zeitstempel", "")         # ISO-8601-Zeitstempel
        text        = nachricht.get("nachricht", "")           # Nachrichtentext
        cli_ui.nachricht_ausgeben(absender, text, zeitstempel)
        logger.info("[%s] %s: %s", zeitstempel, absender, text)
    trenn_ereignis.set()


# ---------------------------------------------------------------------------
# Server-Modus
# ---------------------------------------------------------------------------

def server_starten(port: int, name: str) -> None:
    """Startet die Anwendung im Server-Modus.

    Lauscht dauerhaft auf neue Verbindungen. Nach einem Verbindungsabbau
    wartet der Server sofort auf den naechsten Client.

    Parameter:
        port: TCP-Port auf dem gelauscht wird
        name: Anzeigename fuer Log-Ausgaben und Nachrichten
    """
    cli_ui.banner_anzeigen()
    print()
    cli_ui.status_box("server", port, name)
    print()

    try:
        srv_socket = server_erstellen()
    except OSError as fehler:
        logger.error("Server-Socket konnte nicht erstellt werden: %s", fehler)
        cli_ui.info_zeile(f"Port {port} kann nicht gebunden werden. Laeuft bereits ein Server?")
        sys.exit(1)

    logger.info("Warte auf Verbindungen auf Port %d ...", port)
    cli_ui.info_zeile(f"Warte auf Client-Verbindung auf Port {port} ...")
    cli_ui.info_zeile("'quit' eingeben um den Server zu beenden")
    print()

    try:
        while True:
            # Auf Client-Verbindung oder stdin-Eingabe warten (max. 1s)
            lesbar, _, _ = select.select([srv_socket, sys.stdin], [], [], 1.0)

            if sys.stdin in lesbar:
                zeile = sys.stdin.readline().strip()
                if zeile.lower() in ("quit", "exit", "q"):
                    logger.info("Nutzer hat quit im Lausch-Zustand eingegeben")
                    cli_ui.info_zeile("Server wird beendet")
                    sys.exit(0)

            if srv_socket not in lesbar:
                continue  # Kein Client innerhalb 1s – wieder warten

            try:
                verbindung, adresse = verbindung_akzeptieren(srv_socket)
            except KeyboardInterrupt:
                logger.info("Verbindungsannahme unterbrochen")
                break
            except Exception as fehler:
                logger.error("Fehler beim Akzeptieren der Verbindung: %s", fehler)
                cli_ui.info_zeile("Verbindungsannahme fehlgeschlagen – beende Server")
                break

            logger.info("TCP/TLS-Verbindung von %s akzeptiert", adresse[0])

            # Sitzung direkt im Zustand VERBUNDEN – TCP+TLS haben den Aufbau abgeschlossen
            sitzung = Sitzung(verbindung, absender_name=name, server_modus=True)

            cli_ui.info_zeile(f"Client verbunden: {adresse[0]}")
            cli_ui.trennlinie()
            print(f"  Nachrichten eingeben · 'quit' zum Beenden")
            cli_ui.trennlinie()
            print()

            trenn_ereignis = threading.Event()  # Signalisiert Ende der Chat-Runde
            empfangs_thread = threading.Thread(
                target=_empfangs_schleife,
                args=(sitzung, trenn_ereignis, "Client"),
                daemon=True,
                name="ServerEmpfang",
            )
            empfangs_thread.start()

            quit_durch_nutzer = False  # Merker ob Nutzer quit eingegeben hat

            while sitzung.zustand == SitzungsZustand.VERBUNDEN and not trenn_ereignis.is_set():
                try:
                    eingabe = cli_ui.eingabe_prompt(trenn_ereignis)
                except (EOFError, KeyboardInterrupt):
                    break
                if eingabe is None:  # Verbindung von Gegenseite getrennt
                    break
                if not eingabe:
                    continue
                if eingabe.lower() in ("quit", "exit", "q"):
                    quit_durch_nutzer = True
                    break
                if not sitzung.nachricht_senden(eingabe):
                    cli_ui.info_zeile("Nachricht nicht uebertragen – Verbindung getrennt")
                    break

            trenn_ereignis.set()
            if sitzung.zustand == SitzungsZustand.VERBUNDEN:
                sitzung.verbindungsabbau()
            empfangs_thread.join(timeout=2.0)

            print()
            cli_ui.trennlinie()
            if quit_durch_nutzer:
                cli_ui.info_zeile("Verbindung beendet · Server wird beendet")
                cli_ui.trennlinie()
                sys.exit(0)

            cli_ui.info_zeile("Verbindung beendet · Warte auf naechsten Client")
            cli_ui.trennlinie()
            print()

    finally:
        srv_socket.close()  # Server-Socket immer schliessen
        logger.info("Server-Socket geschlossen")

    logger.info("Server-Sitzung beendet")


# ---------------------------------------------------------------------------
# Client-Modus
# ---------------------------------------------------------------------------

def client_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Client-Modus.

    Verbindet sich einmalig mit dem angegebenen Ziel. Schlaegt der Aufbau fehl,
    wird das Programm beendet.

    Parameter:
        ziel: IP-Adresse oder Hostname des Servers
        port: TCP-Port des Servers
        name: Anzeigename fuer Nachricht-Payloads
    """
    cli_ui.banner_anzeigen()
    print()
    cli_ui.status_box("client", port, name)
    print()

    cli_ui.info_zeile(f"Verbinde mit {ziel}:{port} ...")
    try:
        verbindung = verbindung_herstellen(ziel, port)
        logger.info("Verbindung zu %s:%d hergestellt", ziel, port)
    except Exception as fehler:
        logger.error("Verbindungsaufbau zu %s:%d fehlgeschlagen: %s", ziel, port, fehler)
        cli_ui.info_zeile(f"Verbindung zu {ziel}:{port} nicht moeglich")
        return

    # Sitzung direkt im Zustand VERBUNDEN – TCP+TLS haben den Aufbau abgeschlossen
    sitzung = Sitzung(verbindung, absender_name=name, server_modus=False)

    cli_ui.info_zeile(f"Verbunden mit {ziel}:{port}")
    cli_ui.trennlinie()
    print(f"  Nachrichten eingeben · 'quit' zum Beenden")
    cli_ui.trennlinie()
    print()

    trenn_ereignis = threading.Event()  # Signalisiert Ende der Chat-Runde
    empfangs_thread = threading.Thread(
        target=_empfangs_schleife,
        args=(sitzung, trenn_ereignis, "Server"),
        daemon=True,
        name="ClientEmpfang",
    )
    empfangs_thread.start()

    while sitzung.zustand == SitzungsZustand.VERBUNDEN and not trenn_ereignis.is_set():
        try:
            eingabe = cli_ui.eingabe_prompt(trenn_ereignis)
        except (EOFError, KeyboardInterrupt):
            logger.info("Eingabe unterbrochen – trenne Verbindung")
            break
        if eingabe is None:  # Verbindung vom Server getrennt – Programm beenden
            break
        if not eingabe:
            continue
        if eingabe.lower() in ("quit", "exit", "q"):
            logger.info("Nutzer hat Verbindungsabbau angefordert")
            break
        if not sitzung.nachricht_senden(eingabe):
            logger.error("Nachricht konnte nicht gesendet werden – Verbindung verloren")
            cli_ui.info_zeile("Nachricht nicht uebertragen – Verbindung getrennt")
            break

    trenn_ereignis.set()
    if sitzung.zustand == SitzungsZustand.VERBUNDEN:
        sitzung.verbindungsabbau()
    empfangs_thread.join(timeout=2.0)

    print()
    cli_ui.trennlinie()
    cli_ui.info_zeile("Verbindung beendet")
    cli_ui.trennlinie()

    logger.info("Client-Sitzung beendet")
