"""
netzwerk.py – TCP/mTLS-Verbindung, Senden, Empfangen (asyncio)

Beschreibung: Verwaltet mTLS-Verbindungen über asyncio-Streams.
              Beide Seiten authentifizieren sich gegenseitig mit CA-signierten
              Zertifikaten (CERT_REQUIRED). Stellt Funktionen für Verbindungsaufbau
              (Client + Race-to-Connect), Daten senden und empfangen bereit.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Testschritte – Race-to-Connect (2 Terminals, gleichzeitig starten):
    Terminal 1 (VM1, IP z.B. 192.168.56.101):
        python3 -c "
        import sys, asyncio; sys.path.insert(0, 'src')
        from netzwerk import auto_verbinden
        async def t():
            r, w, s = await auto_verbinden('192.168.56.102')
            print('Rolle:', 'Server' if s else 'Client')
        asyncio.run(t())
        "

    Terminal 2 (VM2, IP z.B. 192.168.56.102):
        python3 -c "
        import sys, asyncio; sys.path.insert(0, 'src')
        from netzwerk import auto_verbinden
        async def t():
            r, w, s = await auto_verbinden('192.168.56.101')
            print('Rolle:', 'Server' if s else 'Client')
        asyncio.run(t())
        "

    Wireshark-Validierung:
        tshark -i eth0 -f "tcp port 49200" -Y "tls.handshake" -c 10
        # Erwartung: TLS 1.3-Handshake sichtbar (Record Version 0x0304), Payload verschlüsselt
"""

import asyncio
import json
import logging
import socket as _socket_modul
import ssl

import konfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TCP Keep-Alive Konfiguration
# ---------------------------------------------------------------------------

def _keepalive_setzen(sock: _socket_modul.socket) -> None:
    """Konfiguriert TCP Keep-Alive auf einem Socket.

    SO_KEEPALIVE aktiviert das OS-Level-Keep-Alive. Die erweiterten Optionen
    (KEEPIDLE, KEEPINTVL, KEEPCNT) sind plattformabhängig (Linux/macOS/Win10+);
    nicht verfügbare Optionen werden stillschweigend übersprungen.
    """
    sock.setsockopt(_socket_modul.SOL_SOCKET, _socket_modul.SO_KEEPALIVE, 1)
    if hasattr(_socket_modul, "TCP_KEEPIDLE"):
        sock.setsockopt(_socket_modul.IPPROTO_TCP, _socket_modul.TCP_KEEPIDLE, 5)
    if hasattr(_socket_modul, "TCP_KEEPINTVL"):
        sock.setsockopt(_socket_modul.IPPROTO_TCP, _socket_modul.TCP_KEEPINTVL, 3)
    if hasattr(_socket_modul, "TCP_KEEPCNT"):
        sock.setsockopt(_socket_modul.IPPROTO_TCP, _socket_modul.TCP_KEEPCNT, 3)
    logger.debug("TCP Keep-Alive konfiguriert (fd=%s)", sock.fileno())


# ---------------------------------------------------------------------------
# Task 2.2 – TLS-Kontext für den Server
# ---------------------------------------------------------------------------

def tls_kontext_server() -> ssl.SSLContext:
    """Erstellt den mTLS-Kontext für die Server-Seite.

    Lädt eigenes Zertifikat/Schlüssel und fordert vom Client ein gültiges,
    CA-signiertes Zertifikat (CERT_REQUIRED). TLS 1.3 Mindestversion.

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Server.

    Wirft:
        ssl.SSLError: Bei ungültigem Zertifikat oder Schlüssel.
        FileNotFoundError: Wenn Zertifikat-, Schlüssel- oder CA-Datei fehlt.
    """
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.load_cert_chain(
        certfile=str(konfig.ZERTIFIKAT_PFAD),
        keyfile=str(konfig.SCHLUESSEL_PFAD),
    )
    kontext.verify_mode = ssl.CERT_REQUIRED
    kontext.load_verify_locations(cafile=str(konfig.CA_ZERTIFIKAT_PFAD))
    logger.debug(
        "mTLS-Server-Kontext erstellt: Zertifikat=%s, CA=%s, min_version=TLSv1.3",
        konfig.ZERTIFIKAT_PFAD,
        konfig.CA_ZERTIFIKAT_PFAD,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.3 – TLS-Kontext für den Client
# ---------------------------------------------------------------------------

def tls_kontext_client() -> ssl.SSLContext:
    """Erstellt den mTLS-Kontext für die Client-Seite.

    Präsentiert eigenes CA-signiertes Zertifikat und verifiziert das
    Server-Zertifikat gegen die CA (CERT_REQUIRED). TLS 1.3 Mindestversion.
    check_hostname ist deaktiviert, da Peers über IP-Adressen erreichbar sind.

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Client.

    Wirft:
        FileNotFoundError: Wenn Zertifikat-, Schlüssel- oder CA-Datei fehlt.
    """
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.load_cert_chain(
        certfile=str(konfig.ZERTIFIKAT_PFAD),
        keyfile=str(konfig.SCHLUESSEL_PFAD),
    )
    kontext.check_hostname = False
    kontext.verify_mode = ssl.CERT_REQUIRED
    kontext.load_verify_locations(cafile=str(konfig.CA_ZERTIFIKAT_PFAD))
    logger.debug(
        "mTLS-Client-Kontext erstellt: Zertifikat=%s, CA=%s, min_version=TLSv1.3",
        konfig.ZERTIFIKAT_PFAD,
        konfig.CA_ZERTIFIKAT_PFAD,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.5 – Verbindung herstellen (Client)
# ---------------------------------------------------------------------------

async def verbindung_herstellen(
    server_ip: str,
    port: int = konfig.PORT,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Stellt eine TLS-Verbindung zum Server her.

    Parameter:
        server_ip: IP-Adresse oder Hostname des Ziel-Servers.
        port:      Ziel-Port (Standard: konfig.PORT = 49200).

    Rückgabe:
        (reader, writer) – fertig verbundene TLS-Streams.
        Der StreamReader-Puffer ist auf konfig.MAX_FRAME_BYTES begrenzt.

    Wirft:
        ssl.SSLError:        Bei fehlgeschlagenem TLS-Handshake.
        OSError:             Bei Verbindungsfehlern.
        asyncio.TimeoutError: Bei überschrittenem VERBINDUNGS_TIMEOUT.
    """
    kontext = tls_kontext_client()
    logger.info("Verbinde zu %s:%d ...", server_ip, port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                server_ip, port, ssl=kontext, limit=konfig.MAX_FRAME_BYTES
            ),
            timeout=konfig.VERBINDUNGS_TIMEOUT,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as fehler:
        logger.error("Verbindung zu %s:%d fehlgeschlagen: %s", server_ip, port, fehler)
        raise

    # TCP Keep-Alive auf dem darunterliegenden Socket setzen (unterhalb TLS-Schicht)
    sock = writer.get_extra_info("socket")
    if sock:
        _keepalive_setzen(sock)

    logger.info(
        "TLS-Verbindung hergestellt – Server: %s:%d, Cipher: %s",
        server_ip, port,
        writer.get_extra_info("cipher"),
    )
    return reader, writer


# ---------------------------------------------------------------------------
# Race-to-Connect – automatische Rollenzuweisung
# ---------------------------------------------------------------------------

async def auto_verbinden(
    ziel_ip: str,
    port: int = konfig.PORT,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
    """Stellt eine P2P-Verbindung her ohne explizite Server/Client-Rollenwahl.

    Beide Peers starten gleichzeitig einen Server-Task (accept) und einen
    Client-Task (connect). Wer zuerst eine Verbindung bekommt, bestimmt die
    Rolle automatisch – „Race to Connect".

    Ablauf:
        1. Server-Task: bindet Port, wartet auf accept()
        2. Client-Task: wartet kurz (RACE_CLIENT_VERZOEGERUNG), dann connect()
        3. Wer zuerst verbindet, setzt ein geteiltes ergebnis-Future
        4. asyncio.wait_for auf dieses Future – Timeout oder Ergebnis
        5. Beide Tasks werden danach sauber abgebrochen

    Parameter:
        ziel_ip: IP-Adresse des anderen Peers.
        port:    TCP-Port (Standard: konfig.PORT = 49200).

    Rückgabe:
        (reader, writer, ist_server):
            reader/writer – fertig verbundene TLS-Streams
            ist_server    – True wenn dieser Peer Server-Rolle übernommen hat

    Wirft:
        ConnectionError: Wenn innerhalb von RACE_TIMEOUT keine Verbindung
                         zustande kam oder beide Tasks fehlgeschlagen sind.
    """

    # Geteiltes Future: wer zuerst verbindet (Server- oder Client-Task) setzt es.
    ergebnis: asyncio.Future[
        tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]
    ] = asyncio.get_running_loop().create_future()

    async def _server_versuch() -> None:
        """Lauscht auf eingehende Verbindungen und meldet die erste via ergebnis."""
        async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            sock = w.get_extra_info("socket")
            if sock:
                _keepalive_setzen(sock)
            if not ergebnis.done():
                ergebnis.set_result((r, w, True))
            else:
                w.close()
                await w.wait_closed()

        server = await asyncio.start_server(
            _handle,
            host=konfig.BIND_ADRESSE,
            port=port,
            ssl=tls_kontext_server(),
            limit=konfig.MAX_FRAME_BYTES,
        )
        try:
            await asyncio.sleep(konfig.RACE_TIMEOUT)  # hält Server bis Timeout am Leben
        finally:
            server.close()  # stoppt neue Verbindungen; bestehende bleiben offen

    async def _client_versuch() -> None:
        """Wartet kurz, verbindet sich und meldet Erfolg via ergebnis."""
        await asyncio.sleep(konfig.RACE_CLIENT_VERZOEGERUNG)
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    ziel_ip, port, ssl=tls_kontext_client(), limit=konfig.MAX_FRAME_BYTES
                ),
                timeout=konfig.VERBINDUNGS_TIMEOUT,
            )
        except Exception:
            return  # Verbindungsfehler ist OK – Server-Task läuft weiter
        # TCP Keep-Alive nach erfolgreichem TLS-Aufbau setzen
        sock = w.get_extra_info("socket")
        if sock:
            _keepalive_setzen(sock)
        if not ergebnis.done():
            ergebnis.set_result((r, w, False))
        else:
            w.close()
            await w.wait_closed()

    logger.info(
        "Race-to-Connect gestartet: Ziel=%s Port=%d Timeout=%.0fs",
        ziel_ip, port, konfig.RACE_TIMEOUT,
    )

    server_task = asyncio.create_task(_server_versuch(), name="RaceServer")
    client_task = asyncio.create_task(_client_versuch(), name="RaceClient")

    try:
        reader, writer, ist_server = await asyncio.wait_for(
            ergebnis, timeout=konfig.RACE_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        raise ConnectionError(
            f"Race-to-Connect: Keine Verbindung zu {ziel_ip}:{port} "
            f"innerhalb von {konfig.RACE_TIMEOUT:.0f} Sekunden."
        )
    finally:
        for task in (server_task, client_task):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    logger.info(
        "Race-to-Connect: %s-Rolle übernommen%s",
        "Server" if ist_server else "Client",
        "" if ist_server else f" (Server: {ziel_ip}:{port})",
    )
    return reader, writer, ist_server


# ---------------------------------------------------------------------------
# Protokoll-Framing – NDJSON (newline-delimited JSON)
# ---------------------------------------------------------------------------

class EmpfangsTimeout(ConnectionError):
    """Wird ausgelöst wenn innerhalb von EMPFANG_TIMEOUT kein Frame eintrifft.

    Unterklasse von ConnectionError – separat fangbar, damit Empfangs-Timeout
    von echten Verbindungsfehlern (TCP FIN/RST, SSL-Fehler) unterschieden
    werden kann.
    """


class FrameZuGross(ConnectionError):
    """Wird ausgelöst wenn ein empfangener Frame das Größenlimit überschreitet.

    Unterklasse von ConnectionError – separat fangbar, damit Frame-Größen-
    verletzungen von normalen Verbindungsfehlern und Timeouts unterschieden
    werden können. Nach diesem Fehler ist der StreamReader in einem inkonsistenten
    Zustand; die Verbindung muss sofort geschlossen werden.
    """


async def frame_senden(writer: asyncio.StreamWriter, frame: dict) -> None:
    """Serialisiert einen dict als NDJSON-Zeile und sendet ihn über den Stream.

    Format: kompaktes JSON + '\\n', UTF-8-kodiert.

    Parameter:
        writer: Aktiver asyncio StreamWriter.
        frame:  Protokoll-Frame als dict.

    Wirft:
        FrameZuGross: Wenn der serialisierte Frame konfig.MAX_FRAME_BYTES überschreitet.
        OSError:      Bei Netzwerkfehlern.
        ssl.SSLError: Bei TLS-Fehlern.
    """
    linie = json.dumps(frame, ensure_ascii=False) + "\n"
    rohdaten = linie.encode("utf-8")
    if len(rohdaten) > konfig.MAX_FRAME_BYTES:
        raise FrameZuGross(
            f"Frame zu groß: {len(rohdaten)} Bytes (Limit: {konfig.MAX_FRAME_BYTES})"
        )
    try:
        writer.write(rohdaten)
        await writer.drain()
    except (OSError, ssl.SSLError) as fehler:
        logger.error("frame_senden fehlgeschlagen: %s", fehler)
        raise
    logger.debug("Frame gesendet: msg_type=%s", frame.get("msg_type"))


async def frame_empfangen(reader: asyncio.StreamReader) -> dict:
    """Liest eine NDJSON-Zeile vom Stream und gibt das deserialisierte dict zurück.

    Verwendet readuntil() statt readline(), damit das über open_connection()
    gesetzte StreamReader-Limit (MAX_FRAME_BYTES) greift. Ein Frame der das
    Limit überschreitet, löst FrameZuGross aus – die Verbindung muss danach
    sofort geschlossen werden, da der Reader-Puffer in einem inkonsistenten
    Zustand ist.

    Parameter:
        reader: Aktiver asyncio StreamReader (Limit = konfig.MAX_FRAME_BYTES).

    Rückgabe:
        Deserialisierter Frame als dict.

    Wirft:
        EmpfangsTimeout:     Wenn innerhalb EMPFANG_TIMEOUT kein Frame eintrifft.
        FrameZuGross:        Wenn der Frame MAX_FRAME_BYTES überschreitet.
        ConnectionError:     Wenn die Verbindung getrennt wurde (leerer Read).
        json.JSONDecodeError: Bei ungültigem JSON.
        OSError:             Bei Netzwerkfehlern.
        ssl.SSLError:        Bei TLS-Fehlern.
    """
    try:
        rohdaten = await asyncio.wait_for(
            reader.readuntil(b"\n"),
            timeout=konfig.EMPFANG_TIMEOUT,
        )
    except asyncio.LimitOverrunError:
        logger.error(
            "frame_empfangen: Frame überschreitet Größenlimit von %d Bytes",
            konfig.MAX_FRAME_BYTES,
        )
        raise FrameZuGross(
            f"Frame zu groß – Limit: {konfig.MAX_FRAME_BYTES} Bytes"
        )
    except asyncio.TimeoutError:
        logger.error("frame_empfangen: Timeout nach %.0fs", konfig.EMPFANG_TIMEOUT)
        raise EmpfangsTimeout(
            f"Empfangs-Timeout nach {konfig.EMPFANG_TIMEOUT:.0f} s – kein Frame vom Peer"
        )
    except (OSError, ssl.SSLError) as fehler:
        logger.error("frame_empfangen fehlgeschlagen: %s", fehler)
        raise

    if not rohdaten:
        raise ConnectionError("Verbindung getrennt")

    frame = json.loads(rohdaten.decode("utf-8"))
    logger.debug("Frame empfangen: msg_type=%s", frame.get("msg_type"))
    return frame


# ---------------------------------------------------------------------------
# Task 2.6a – Daten senden (Raw-Bytes, Legacy)
# ---------------------------------------------------------------------------

async def daten_senden(writer: asyncio.StreamWriter, daten: bytes) -> None:
    """Sendet Bytes-Daten über die TLS-Verbindung.

    Parameter:
        writer: Der aktive asyncio StreamWriter.
        daten:  Die zu sendenden Nutzdaten als Bytes.

    Wirft:
        OSError:      Bei Netzwerkfehlern während des Sendens.
        ssl.SSLError: Bei TLS-Fehlern.
    """
    try:
        writer.write(daten)
        await writer.drain()
    except (OSError, ssl.SSLError) as fehler:
        logger.error("Senden fehlgeschlagen (%d Bytes): %s", len(daten), fehler)
        raise

    logger.debug("Gesendet: %d Bytes Nutzdaten", len(daten))


# ---------------------------------------------------------------------------
# Task 2.6b – Daten empfangen (Raw-Bytes, Legacy)
# ---------------------------------------------------------------------------

async def daten_empfangen(reader: asyncio.StreamReader) -> bytes:
    """Empfängt ein Datenpaket von der TLS-Verbindung.

    Liest bis zu PUFFER_GROESSE Bytes vom TLS-Stream.

    Parameter:
        reader: Der aktive asyncio StreamReader.

    Rückgabe:
        Die empfangenen Nutzdaten als Bytes.

    Wirft:
        ConnectionError: Wenn die Verbindung getrennt wurde (leerer Read).
        OSError:         Bei Netzwerkfehlern.
        ssl.SSLError:    Bei TLS-Fehlern.
    """
    try:
        chunk = await reader.read(konfig.PUFFER_GROESSE)
    except (OSError, ssl.SSLError) as fehler:
        logger.error("Empfangsfehler: %s", fehler)
        raise

    if not chunk:
        raise ConnectionError("Verbindung getrennt")

    logger.debug("Empfangen: %d Bytes Nutzdaten", len(chunk))
    return chunk
