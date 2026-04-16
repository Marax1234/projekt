"""
konsole.py – Server- und Client-Modus (Konsolenbetrieb)

Beschreibung: Enthält die Startfunktionen für den interaktiven Konsolenbetrieb.
              Server-Modus lauscht dauerhaft auf neue Verbindungen; Client-Modus
              verbindet sich einmalig mit dem angegebenen Ziel. Beide nutzen
              cli_ui.py für die Terminal-Ausgabe.

              Nach TLS-Verbindungsaufbau führt Sitzung.verbinden() den
              App-Handshake (HELLO/HELLO_ACK) durch, bevor Chat-Nachrichten
              gesendet oder empfangen werden.

Autor:        Gruppe 2
Datum:        2026-04-16
Modul:        Network Security 2026
"""

import asyncio
import logging
import sys
import threading

import cli_ui
import konfig
from netzwerk import auto_verbinden, tls_kontext_server, verbindung_herstellen
from sitzung import Sitzung

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gemeinsame Empfangs-Schleife
# ---------------------------------------------------------------------------

async def _empfangs_schleife(sitzung: Sitzung, herkunft: str) -> None:
    """Liest CHAT-Nachrichten aus der UI-Queue und gibt sie auf dem Terminal aus.

    Läuft als asyncio Task. Beendet sich wenn die Sitzung None in die Queue
    schreibt (Verbindungsende oder Fehler).

    Parameter:
        sitzung:  Aktive Sitzung
        herkunft: Bezeichnung der Gegenseite für Meldungen (z.B. "Client")
    """
    while True:
        frame = await sitzung.naechste_chat_nachricht()
        if frame is None:
            if not sitzung.ist_aktiv:
                cli_ui.info_zeile(f"Verbindung vom {herkunft} beendet")
            return

        payload     = frame.get("payload", {})
        absender    = payload.get("sender", "Unbekannt")
        text        = payload.get("text", "")
        zeitstempel = frame.get("timestamp", "")
        cli_ui.nachricht_ausgeben(absender, text, zeitstempel)
        logger.info("[%s] %s: %s", zeitstempel, absender, text)


# ---------------------------------------------------------------------------
# Gemeinsame Chat-Sitzungsführung
# ---------------------------------------------------------------------------

async def _chat_sitzung_fuehren(sitzung: Sitzung, herkunft: str) -> bool:
    """Führt eine Chat-Sitzung durch: Empfang und Eingabe laufen parallel.

    Empfang läuft als asyncio Task. Nutzereingabe läuft via asyncio.to_thread,
    damit der Event-Loop nicht blockiert. cli_ui.eingabe_prompt (mit
    threading.Event) vermittelt zuverlässig, wenn die Gegenseite trennt.

    Parameter:
        sitzung:  Aktive Sitzung (muss sich bereits im Zustand BEREIT befinden)
        herkunft: Bezeichnung der Gegenseite (z.B. "Client", "Server", "Peer")

    Rückgabe:
        True wenn Nutzer 'quit' eingegeben hat, sonst False.
    """
    trenn_ereignis = threading.Event()
    quit_durch_nutzer = False

    async def _empfang_mit_signal() -> None:
        """Empfangs-Schleife – setzt trenn_ereignis wenn Verbindung endet."""
        await _empfangs_schleife(sitzung, herkunft)
        trenn_ereignis.set()

    empfang_task = asyncio.create_task(_empfang_mit_signal())

    try:
        while sitzung.ist_aktiv and not trenn_ereignis.is_set():
            try:
                eingabe = await asyncio.to_thread(cli_ui.eingabe_prompt, trenn_ereignis)
            except (EOFError, KeyboardInterrupt):
                logger.info("Eingabe unterbrochen – trenne Verbindung")
                break
            if eingabe is None:
                break  # Verbindung von Gegenseite getrennt
            if not eingabe:
                continue
            if eingabe.lower() in ("quit", "exit", "q"):
                quit_durch_nutzer = True
                break
            if not await sitzung.chat_senden(eingabe):
                cli_ui.info_zeile("Nachricht nicht übertragen – Verbindung getrennt")
                break
    finally:
        trenn_ereignis.set()
        empfang_task.cancel()
        try:
            await empfang_task
        except asyncio.CancelledError:
            pass

    if sitzung.ist_aktiv:
        await sitzung.verbindungsabbau()

    return quit_durch_nutzer


# ---------------------------------------------------------------------------
# Auto-Modus (Race to Connect) – keine manuelle Rollenwahl
# ---------------------------------------------------------------------------

async def peer_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Race-to-Connect-Modus.

    Parameter:
        ziel: IP-Adresse des anderen Peers
        port: TCP-Port
        name: Anzeigename für Nachrichten
    """
    cli_ui.banner_anzeigen()
    print()
    cli_ui.status_box("auto", port, name)
    print()

    cli_ui.info_zeile(f"Race to Connect mit {ziel}:{port} ...")
    cli_ui.info_zeile("Warte auf Verbindung oder verbinde – Rolle wird automatisch bestimmt")
    print()

    try:
        reader, writer, ist_server = await auto_verbinden(ziel, port)
    except ConnectionError as fehler:
        logger.error("Race-to-Connect fehlgeschlagen: %s", fehler)
        cli_ui.info_zeile(f"Keine Verbindung zu {ziel}:{port} – Timeout überschritten")
        return
    except Exception as fehler:
        logger.error("Unerwarteter Fehler beim Race-to-Connect: %s", fehler)
        cli_ui.info_zeile(f"Verbindungsaufbau fehlgeschlagen: {fehler}")
        return

    rolle = "Server" if ist_server else "Client"
    logger.info("TLS verbunden als %s mit %s:%d", rolle, ziel, port)

    sitzung = Sitzung(reader, writer, absender_name=name, server_modus=ist_server)

    cli_ui.info_zeile(f"TLS verbunden als {rolle} – führe App-Handshake durch ...")
    try:
        await sitzung.verbinden()
    except ConnectionError as fehler:
        logger.error("App-Handshake fehlgeschlagen: %s", fehler)
        cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
        return

    cli_ui.info_zeile(f"Verbunden als {rolle} mit {ziel}:{port}")
    cli_ui.trennlinie()
    print("  Nachrichten eingeben · 'quit' zum Beenden")
    cli_ui.trennlinie()
    print()

    await _chat_sitzung_fuehren(sitzung, "Peer")

    print()
    cli_ui.trennlinie()
    cli_ui.info_zeile("Verbindung beendet")
    cli_ui.trennlinie()

    logger.info("Peer-Sitzung beendet")


# ---------------------------------------------------------------------------
# Server-Modus
# ---------------------------------------------------------------------------

async def server_starten(port: int, name: str) -> None:
    """Startet die Anwendung im Server-Modus.

    Lauscht dauerhaft auf neue Verbindungen. Nach einem Verbindungsabbau
    wartet der Server sofort auf den nächsten Client. Ctrl+C beendet den Server.
    'quit' während einer aktiven Sitzung beendet den Server nach der Sitzung.

    Parameter:
        port: TCP-Port auf dem gelauscht wird
        name: Anzeigename für Nachrichten
    """
    cli_ui.banner_anzeigen()
    print()
    cli_ui.status_box("server", port, name)
    print()

    # Future wird pro Client-Zyklus neu gesetzt
    naechster: asyncio.Future = asyncio.get_running_loop().create_future()

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal naechster
        if not naechster.done():
            naechster.set_result((reader, writer))
        else:
            writer.close()
            await writer.wait_closed()

    try:
        server = await asyncio.start_server(
            _handle, konfig.BIND_ADRESSE, port, ssl=tls_kontext_server(),
        )
    except OSError as fehler:
        logger.error("Server-Socket konnte nicht erstellt werden: %s", fehler)
        cli_ui.info_zeile(f"Port {port} kann nicht gebunden werden. Läuft bereits ein Server?")
        sys.exit(1)

    logger.info("Warte auf Verbindungen auf Port %d ...", port)

    async with server:
        while True:
            cli_ui.info_zeile(f"Warte auf Client-Verbindung auf Port {port} ...")
            cli_ui.info_zeile("Ctrl+C zum Beenden des Servers")
            print()

            reader, writer = await naechster
            naechster = asyncio.get_running_loop().create_future()  # für nächsten Client

            adresse = writer.get_extra_info("peername")
            logger.info("TCP/TLS-Verbindung von %s akzeptiert", adresse[0])

            sitzung = Sitzung(reader, writer, absender_name=name, server_modus=True)

            cli_ui.info_zeile(f"Client verbunden: {adresse[0]} – führe App-Handshake durch ...")
            try:
                await sitzung.verbinden()
            except ConnectionError as fehler:
                logger.error("App-Handshake mit %s fehlgeschlagen: %s", adresse[0], fehler)
                cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
                continue

            cli_ui.info_zeile(f"Sitzung bereit mit {adresse[0]}")
            cli_ui.trennlinie()
            print("  Nachrichten eingeben · 'quit' zum Beenden")
            cli_ui.trennlinie()
            print()

            quit_durch_nutzer = await _chat_sitzung_fuehren(sitzung, "Client")

            print()
            cli_ui.trennlinie()
            if quit_durch_nutzer:
                cli_ui.info_zeile("Verbindung beendet · Server wird beendet")
                cli_ui.trennlinie()
                return

            cli_ui.info_zeile("Verbindung beendet · Warte auf nächsten Client")
            cli_ui.trennlinie()
            print()

    logger.info("Server-Sitzung beendet")


# ---------------------------------------------------------------------------
# Client-Modus
# ---------------------------------------------------------------------------

async def client_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Client-Modus.

    Verbindet sich einmalig mit dem angegebenen Ziel.

    Parameter:
        ziel: IP-Adresse oder Hostname des Servers
        port: TCP-Port des Servers
        name: Anzeigename für Nachricht-Payloads
    """
    cli_ui.banner_anzeigen()
    print()
    cli_ui.status_box("client", port, name)
    print()

    cli_ui.info_zeile(f"Verbinde mit {ziel}:{port} ...")
    try:
        reader, writer = await verbindung_herstellen(ziel, port)
        logger.info("TLS-Verbindung zu %s:%d hergestellt", ziel, port)
    except Exception as fehler:
        logger.error("Verbindungsaufbau zu %s:%d fehlgeschlagen: %s", ziel, port, fehler)
        cli_ui.info_zeile(f"Verbindung zu {ziel}:{port} nicht möglich")
        return

    sitzung = Sitzung(reader, writer, absender_name=name, server_modus=False)

    cli_ui.info_zeile(f"TLS verbunden mit {ziel}:{port} – führe App-Handshake durch ...")
    try:
        await sitzung.verbinden()
    except ConnectionError as fehler:
        logger.error("App-Handshake fehlgeschlagen: %s", fehler)
        cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
        return

    cli_ui.info_zeile(f"Sitzung bereit mit {ziel}:{port}")
    cli_ui.trennlinie()
    print("  Nachrichten eingeben · 'quit' zum Beenden")
    cli_ui.trennlinie()
    print()

    await _chat_sitzung_fuehren(sitzung, "Server")

    print()
    cli_ui.trennlinie()
    cli_ui.info_zeile("Verbindung beendet")
    cli_ui.trennlinie()

    logger.info("Client-Sitzung beendet")
