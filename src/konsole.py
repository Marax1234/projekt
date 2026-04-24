"""
konsole.py – Server- und Client-Modus (Konsolenbetrieb)

Beschreibung: Enthält die Startfunktionen für den interaktiven Konsolenbetrieb.
              Server-Modus lauscht dauerhaft auf neue Verbindungen; Client-Modus
              verbindet sich einmalig mit dem angegebenen Ziel. Beide nutzen
              cli_ui.py für die Terminal-Ausgabe.

              Nach TLS-Verbindungsaufbau führt Sitzung.verbinden() den
              App-Handshake (APP_HELLO/APP_HELLO_ACK) durch, bevor Chat-Nachrichten
              gesendet oder empfangen werden.

Autor:        Gruppe 2
Datum:        2026-04-16
Modul:        Network Security 2026
"""

import asyncio
import collections
import logging
import random
import sys
import threading

import cli_ui
import konfig
from netzwerk import FrameZuGross, auto_verbinden, tls_kontext_server, verbindung_herstellen, _keepalive_setzen
from sitzung import Sitzung

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Peer-Identität aus mTLS-Zertifikat
# ---------------------------------------------------------------------------

def _peer_cn_aus_zertifikat(ssl_objekt) -> str:
    """Extrahiert den CommonName aus dem mTLS-Peer-Zertifikat.

    Parameter:
        ssl_objekt: ssl.SSLObject aus writer.get_extra_info("ssl_object")

    Rückgabe:
        CommonName-String oder "" wenn nicht verfügbar.
    """
    if ssl_objekt is None:
        return ""
    try:
        cert = ssl_objekt.getpeercert()
        if not cert:
            return ""
        for rdnseq in cert.get("subject", ()):
            for key, value in rdnseq:
                if key == "commonName":
                    return str(value)
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Backoff-Berechnung für Reconnect
# ---------------------------------------------------------------------------

def _backoff_sekunden(versuch: int, basis: float = 2.0, maximum: float = 10.0) -> float:
    """Berechnet Wartezeit für exponentielles Backoff mit Jitter.

    Parameter:
        versuch: Anzahl bisheriger Fehlversuche (> 0).
        basis:   Basis des Exponenten (Standard: 2.0).
        maximum: Maximale Wartezeit in Sekunden (Standard: 10.0).
                 Begrenzt auf 10 s, damit Reconnects nicht zu lange auf sich
                 warten lassen (2^4 = 16 s würde sonst schon überschritten).

    Rückgabe:
        Wartezeit in Sekunden (capped bei maximum).
    """
    return min(basis ** versuch + random.uniform(0, 1), maximum)


# ---------------------------------------------------------------------------
# Semantische Trennmeldungen
# ---------------------------------------------------------------------------

def _zeige_trenn_meldung(sitzung: Sitzung, herkunft: str) -> None:
    """Zeigt eine zum Trenngrund passende Meldung auf dem Terminal.

    Bildet sitzung.trenn_grund auf eine sprechende Nutzer-Meldung ab:
    - TCP_GETRENNT / PEER_CLOSE → „Verbindung vom Peer beendet"
    - EMPFANG_TIMEOUT           → „Zeitüberschreitung – keine Daten vom Peer"
    - HEARTBEAT_TIMEOUT         → „Heartbeat-Timeout – Peer nicht erreichbar"
    - NUTZER_QUIT               → (keine Meldung, Nutzer hat bewusst beendet)
    - Sonstiges                 → „Verbindung zu Peer unterbrochen"
    """
    grund = sitzung.trenn_grund
    if grund in ("TCP_GETRENNT", "PEER_CLOSE"):
        cli_ui.info_zeile(f"Verbindung vom {herkunft} beendet")
    elif grund == "EMPFANG_TIMEOUT":
        cli_ui.info_zeile(f"Zeitüberschreitung – keine Daten vom {herkunft}")
    elif grund == "HEARTBEAT_TIMEOUT":
        cli_ui.info_zeile(f"Heartbeat-Timeout – {herkunft} nicht erreichbar")
    elif grund == "NUTZER_QUIT":
        pass  # Nutzer hat selbst beendet – keine redundante Meldung
    else:
        cli_ui.info_zeile(f"Verbindung zu {herkunft} unterbrochen ({grund})")


# ---------------------------------------------------------------------------
# Gemeinsame Empfangs-Schleife
# ---------------------------------------------------------------------------

async def _empfangs_schleife(sitzung: Sitzung, herkunft: str) -> None:
    """Liest CHAT-Nachrichten aus der UI-Queue und gibt sie auf dem Terminal aus.

    Läuft als asyncio Task. Beendet sich wenn die Sitzung None in die Queue
    schreibt (Verbindungsende oder Fehler). Zeigt anschließend eine semantisch
    korrekte Trennmeldung basierend auf sitzung.trenn_grund.

    Parameter:
        sitzung:  Aktive Sitzung
        herkunft: Bezeichnung der Gegenseite für Meldungen (z.B. "Client")
    """
    while True:
        frame = await sitzung.naechste_chat_nachricht()
        if frame is None:
            _zeige_trenn_meldung(sitzung, herkunft)
            return

        payload     = frame.get("data", {})
        absender    = payload.get("sender", "Unbekannt")
        text        = payload.get("text", "")
        zeitstempel = frame.get("timestamp", "")
        cli_ui.nachricht_ausgeben(absender, text, zeitstempel)


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

    # Fix Bug 2: Eingabe-Task läuft permanent im Hintergrund, auch während
    # chat_senden auf ein ACK wartet, damit die TUI nicht einfriert.
    eingabe_task: asyncio.Task | None = None

    try:
        while sitzung.ist_aktiv and not trenn_ereignis.is_set():
            if eingabe_task is None:
                eingabe_task = asyncio.ensure_future(
                    asyncio.to_thread(cli_ui.eingabe_prompt, trenn_ereignis)
                )
            try:
                eingabe = await eingabe_task
            except (EOFError, KeyboardInterrupt):
                logger.info("Eingabe unterbrochen – trenne Verbindung")
                eingabe_task = None
                break
            eingabe_task = None

            if eingabe is None:
                break  # Verbindung von Gegenseite getrennt
            if not eingabe:
                continue
            if eingabe.lower() in ("quit", "exit", "q"):
                quit_durch_nutzer = True
                break

            # Nächsten Eingabe-Task sofort starten, bevor chat_senden blockiert
            # (Fix Bug 2: Tippen während ACK-Wartezeit wird jetzt angezeigt)
            eingabe_task = asyncio.ensure_future(
                asyncio.to_thread(cli_ui.eingabe_prompt, trenn_ereignis)
            )

            # Fix Bug 1: eigene Nachricht sofort anzeigen, unabhängig vom ACK
            cli_ui.eigene_nachricht_ausgeben(sitzung.absender_name, eingabe)

            try:
                gesendet = await sitzung.chat_senden(eingabe)
            except FrameZuGross:
                cli_ui.info_zeile(
                    f"Nachricht zu lang – maximal {konfig.MAX_FRAME_BYTES} Bytes erlaubt"
                )
                continue
            if not gesendet:
                cli_ui.info_zeile("Nachricht nicht übertragen – Verbindung getrennt")
                break
    finally:
        trenn_ereignis.set()
        if eingabe_task is not None:
            eingabe_task.cancel()
            try:
                await eingabe_task
            except (asyncio.CancelledError, EOFError, KeyboardInterrupt):
                pass
        empfang_task.cancel()
        try:
            await empfang_task
        except asyncio.CancelledError:
            pass

    if sitzung.ist_aktiv:
        await sitzung.verbindungsabbau()

    # Peer hat die Verbindung geordnet beendet → kein Reconnect
    peer_hat_beendet = sitzung.trenn_grund == "PEER_CLOSE"
    return quit_durch_nutzer or peer_hat_beendet


# ---------------------------------------------------------------------------
# Auto-Modus (Race to Connect) – keine manuelle Rollenwahl
# ---------------------------------------------------------------------------

async def peer_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Race-to-Connect-Modus mit automatischem Reconnect.

    Nach einem unerwarteten Verbindungsabbruch wird automatisch mit exponentiellem
    Backoff + Jitter versucht, die Verbindung wiederherzustellen
    (max. MAX_RECONNECT_VERSUCHE Versuche). Erst wenn der Nutzer 'quit' eingibt,
    wird die Schleife beendet.

    Parameter:
        ziel: IP-Adresse des anderen Peers
        port: TCP-Port
        name: Anzeigename für Nachrichten
    """
    cli_ui.status_box("auto", port, name)
    cli_ui.leerzeile()

    versuch = 0
    # Outbox-Zustand über Reconnects hinweg beibehalten
    _outbox: collections.deque[tuple[int, str]] = collections.deque()
    _naechste_seq: int = 0
    _resume_token: str = ""
    _zuletzt_empfangene_seq: int = -1

    while True:
        # Backoff vor Reconnect-Versuchen
        if versuch > 0:
            if versuch >= konfig.MAX_RECONNECT_VERSUCHE:
                cli_ui.fehler_zeile("Peer dauerhaft nicht erreichbar. Programm wird beendet.")
                break
            wartezeit = _backoff_sekunden(versuch)
            cli_ui.info_zeile(
                f"Verbindung verloren – Reconnect-Versuch {versuch} in {wartezeit:.0f} s ..."
            )
            await asyncio.sleep(wartezeit)

        cli_ui.info_zeile(f"Race to Connect mit {ziel}:{port} ...")
        if versuch == 0:
            cli_ui.info_zeile("Warte auf Verbindung oder verbinde – Rolle wird automatisch bestimmt")
        cli_ui.leerzeile()

        try:
            reader, writer, ist_server = await auto_verbinden(ziel, port)
        except ConnectionError as fehler:
            logger.error("Race-to-Connect fehlgeschlagen: %s", fehler)
            cli_ui.info_zeile(f"Keine Verbindung zu {ziel}:{port} – Timeout überschritten")
            versuch += 1
            continue
        except Exception as fehler:
            logger.error("Unerwarteter Fehler beim Race-to-Connect: %s", fehler)
            cli_ui.info_zeile(f"Verbindungsaufbau fehlgeschlagen: {fehler}")
            versuch += 1
            continue

        versuch = 0  # Reset nach erfolgreicher Verbindung
        rolle = "Server" if ist_server else "Client"
        logger.info("TLS verbunden als %s mit %s:%d", rolle, ziel, port)

        sitzung = Sitzung(reader, writer, absender_name=name, server_modus=ist_server)
        sitzung.sitzungs_zustand_uebernehmen(
            _outbox, _naechste_seq, _resume_token, _zuletzt_empfangene_seq
        )

        cli_ui.info_zeile(f"TLS verbunden als {rolle} – führe App-Handshake durch ...")
        try:
            await sitzung.verbinden()
        except ConnectionError as fehler:
            logger.error("App-Handshake fehlgeschlagen: %s", fehler)
            cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
            versuch += 1
            continue

        # Ausstehende Nachrichten aus der Outbox erneut senden
        if _outbox:
            cli_ui.info_zeile(f"Sende {len(_outbox)} ausstehende Nachricht(en) nach Reconnect ...")
            await sitzung.outbox_wiederholen()

        cli_ui.info_zeile(f"Verbunden als {rolle} mit {ziel}:{port}")
        cli_ui.trennlinie()
        cli_ui.chat_hinweis()
        cli_ui.trennlinie()
        cli_ui.leerzeile()

        quit_durch_nutzer = await _chat_sitzung_fuehren(sitzung, "Peer")

        # Outbox-Zustand für nächsten Reconnect sichern
        _outbox = sitzung._outbox
        _naechste_seq = sitzung._naechste_seq
        _resume_token = sitzung._resume_token
        _zuletzt_empfangene_seq = sitzung._zuletzt_empfangene_seq

        if quit_durch_nutzer:
            break

        versuch += 1  # Unerwartetes Ende → Reconnect vorbereiten

    cli_ui.leerzeile()
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
    cli_ui.status_box("server", port, name)
    cli_ui.leerzeile()

    # Future wird pro Client-Zyklus neu gesetzt
    naechster: asyncio.Future = asyncio.get_running_loop().create_future()

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal naechster
        # TCP Keep-Alive auf akzeptiertem Socket setzen
        sock = writer.get_extra_info("socket")
        if sock:
            _keepalive_setzen(sock)
        if not naechster.done():
            naechster.set_result((reader, writer))
        else:
            writer.close()
            await writer.wait_closed()

    try:
        server = await asyncio.start_server(
            _handle,
            konfig.BIND_ADRESSE,
            port,
            ssl=tls_kontext_server(),
            limit=konfig.MAX_FRAME_BYTES,
        )
    except OSError as fehler:
        logger.error("Server-Socket konnte nicht erstellt werden: %s", fehler)
        cli_ui.info_zeile(f"Port {port} kann nicht gebunden werden. Läuft bereits ein Server?")
        sys.exit(1)

    logger.info("Warte auf Verbindungen auf Port %d ...", port)

    # Peer-Identität und Outbox-Zustand sitzungsübergreifend tracken
    _letzter_peer_cn: str = ""
    _outbox: collections.deque[tuple[int, str]] = collections.deque()
    _naechste_seq: int = 0
    _resume_token: str = ""
    _zuletzt_empfangene_seq: int = -1

    async with server:
        while True:
            cli_ui.info_zeile(f"Warte auf Client-Verbindung auf Port {port} ...")
            cli_ui.info_zeile("Ctrl+C zum Beenden des Servers")
            cli_ui.leerzeile()

            reader, writer = await naechster
            naechster = asyncio.get_running_loop().create_future()  # für nächsten Client

            adresse = writer.get_extra_info("peername")
            logger.info("TCP/TLS-Verbindung von %s akzeptiert", adresse[0])

            # Peer-Identität aus mTLS-Zertifikat ermitteln
            ssl_obj = writer.get_extra_info("ssl_object")
            peer_cn = _peer_cn_aus_zertifikat(ssl_obj)
            ist_wiederverbindung = bool(peer_cn and peer_cn == _letzter_peer_cn)
            if peer_cn:
                _letzter_peer_cn = peer_cn

            if ist_wiederverbindung:
                cli_ui.info_zeile(f"Bekannter Peer wiederverbunden: {peer_cn} ({adresse[0]})")
            elif peer_cn:
                cli_ui.info_zeile(f"Neuer Client verbunden: {peer_cn} ({adresse[0]})")
                # Neuer Peer → Outbox-Zustand zurücksetzen
                _outbox = collections.deque()
                _naechste_seq = 0
                _resume_token = ""
                _zuletzt_empfangene_seq = -1

            sitzung = Sitzung(reader, writer, absender_name=name, server_modus=True)
            sitzung.sitzungs_zustand_uebernehmen(
                _outbox, _naechste_seq, _resume_token, _zuletzt_empfangene_seq
            )

            cli_ui.info_zeile(f"Client verbunden: {adresse[0]} – führe App-Handshake durch ...")
            try:
                await sitzung.verbinden()
            except ConnectionError as fehler:
                logger.error("App-Handshake mit %s fehlgeschlagen: %s", adresse[0], fehler)
                cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
                continue

            # Ausstehende Nachrichten bei Wiederverbindung erneut senden
            if ist_wiederverbindung and _outbox:
                cli_ui.info_zeile(f"Sende {len(_outbox)} ausstehende Nachricht(en) nach Reconnect ...")
                await sitzung.outbox_wiederholen()

            cli_ui.info_zeile(f"Sitzung bereit mit {adresse[0]}")
            cli_ui.trennlinie()
            cli_ui.chat_hinweis()
            cli_ui.trennlinie()
            cli_ui.leerzeile()

            quit_durch_nutzer = await _chat_sitzung_fuehren(sitzung, "Client")

            # Outbox-Zustand für nächste Verbindung sichern
            _outbox = sitzung._outbox
            _naechste_seq = sitzung._naechste_seq
            _resume_token = sitzung._resume_token
            _zuletzt_empfangene_seq = sitzung._zuletzt_empfangene_seq

            cli_ui.leerzeile()
            cli_ui.trennlinie()
            if quit_durch_nutzer:
                cli_ui.info_zeile("Verbindung beendet · Server wird beendet")
                cli_ui.trennlinie()
                return

            cli_ui.info_zeile("Verbindung beendet · Warte auf nächsten Client")
            cli_ui.trennlinie()
            cli_ui.leerzeile()

    logger.info("Server-Sitzung beendet")


# ---------------------------------------------------------------------------
# Client-Modus
# ---------------------------------------------------------------------------

async def client_starten(ziel: str, port: int, name: str) -> None:
    """Startet die Anwendung im Client-Modus mit automatischem Reconnect.

    Nach einem unerwarteten Verbindungsabbruch wird automatisch mit exponentiellem
    Backoff + Jitter versucht, die Verbindung wiederherzustellen
    (max. MAX_RECONNECT_VERSUCHE Versuche). Erst wenn der Nutzer 'quit' eingibt,
    wird die Schleife beendet.

    Parameter:
        ziel: IP-Adresse oder Hostname des Servers
        port: TCP-Port des Servers
        name: Anzeigename für Nachricht-Payloads
    """
    cli_ui.status_box("client", port, name)
    cli_ui.leerzeile()

    versuch = 0
    # Outbox-Zustand über Reconnects hinweg beibehalten
    _outbox: collections.deque[tuple[int, str]] = collections.deque()
    _naechste_seq: int = 0
    _resume_token: str = ""
    _zuletzt_empfangene_seq: int = -1

    while True:
        # Backoff vor Reconnect-Versuchen
        if versuch > 0:
            if versuch >= konfig.MAX_RECONNECT_VERSUCHE:
                cli_ui.fehler_zeile("Server dauerhaft nicht erreichbar. Programm wird beendet.")
                break
            wartezeit = _backoff_sekunden(versuch)
            cli_ui.info_zeile(
                f"Verbindung verloren – Reconnect-Versuch {versuch} in {wartezeit:.0f} s ..."
            )
            await asyncio.sleep(wartezeit)

        cli_ui.info_zeile(f"Verbinde mit {ziel}:{port} ...")
        try:
            reader, writer = await verbindung_herstellen(ziel, port)
            logger.info("TLS-Verbindung zu %s:%d hergestellt", ziel, port)
        except (ConnectionError, OSError) as fehler:
            logger.error("Verbindungsaufbau zu %s:%d fehlgeschlagen: %s", ziel, port, fehler)
            cli_ui.info_zeile(f"Verbindung zu {ziel}:{port} nicht möglich")
            versuch += 1
            continue

        versuch = 0  # Reset nach erfolgreicher Verbindung

        sitzung = Sitzung(reader, writer, absender_name=name, server_modus=False)
        sitzung.sitzungs_zustand_uebernehmen(
            _outbox, _naechste_seq, _resume_token, _zuletzt_empfangene_seq
        )

        cli_ui.info_zeile(f"TLS verbunden mit {ziel}:{port} – führe App-Handshake durch ...")
        try:
            await sitzung.verbinden()
        except ConnectionError as fehler:
            logger.error("App-Handshake fehlgeschlagen: %s", fehler)
            cli_ui.info_zeile(f"Handshake fehlgeschlagen: {fehler}")
            versuch += 1
            continue

        # Ausstehende Nachrichten nach Reconnect erneut senden
        if _outbox:
            cli_ui.info_zeile(f"Sende {len(_outbox)} ausstehende Nachricht(en) nach Reconnect ...")
            await sitzung.outbox_wiederholen()

        cli_ui.info_zeile(f"Sitzung bereit mit {ziel}:{port}")
        cli_ui.trennlinie()
        cli_ui.chat_hinweis()
        cli_ui.trennlinie()
        cli_ui.leerzeile()

        quit_durch_nutzer = await _chat_sitzung_fuehren(sitzung, "Server")

        # Outbox-Zustand für nächsten Reconnect sichern
        _outbox = sitzung._outbox
        _naechste_seq = sitzung._naechste_seq
        _resume_token = sitzung._resume_token
        _zuletzt_empfangene_seq = sitzung._zuletzt_empfangene_seq

        if quit_durch_nutzer:
            break

        versuch += 1  # Unerwartetes Ende → Reconnect vorbereiten

    cli_ui.leerzeile()
    cli_ui.trennlinie()
    cli_ui.info_zeile("Verbindung beendet")
    cli_ui.trennlinie()

    logger.info("Client-Sitzung beendet")
