"""
netzwerk.py – TCP/TLS-Verbindung, Senden, Empfangen (asyncio)

Beschreibung: Verwaltet TLS-Verbindungen über asyncio-Streams.
              Stellt Funktionen für Verbindungsaufbau (Client + Race-to-Connect),
              Daten senden und empfangen bereit.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Testschritte – Race-to-Connect (2 Terminals, gleichzeitig starten):
    Terminal 1 (VM1, IP z.B. 192.168.56.101):
        python3 -c "
        import asyncio
        from netzwerk import auto_verbinden
        async def t():
            r, w, s = await auto_verbinden('192.168.56.102')
            print('Rolle:', 'Server' if s else 'Client')
        asyncio.run(t())
        "

    Terminal 2 (VM2, IP z.B. 192.168.56.102):
        python3 -c "
        import asyncio
        from netzwerk import auto_verbinden
        async def t():
            r, w, s = await auto_verbinden('192.168.56.101')
            print('Rolle:', 'Server' if s else 'Client')
        asyncio.run(t())
        "

    Wireshark-Validierung:
        tshark -i eth0 -f "tcp port 6769" -Y "tls.handshake" -c 10
        # Erwartung: TLS 1.3-Handshake sichtbar (Record Version 0x0304), Payload verschlüsselt
"""

import asyncio
import logging
import ssl

import konfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task 2.2 – TLS-Kontext für den Server
# ---------------------------------------------------------------------------

def tls_kontext_server() -> ssl.SSLContext:
    """Erstellt den TLS-Kontext für die Server-Seite.

    Lädt Zertifikat und privaten Schlüssel aus den in konfig.py
    definierten Pfaden. TLS 1.3 wird als Mindestversion erzwungen.

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Server.

    Wirft:
        ssl.SSLError: Bei ungültigem Zertifikat oder Schlüssel.
        FileNotFoundError: Wenn Zertifikat- oder Schlüsseldatei fehlt.
    """
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.load_cert_chain(
        certfile=str(konfig.ZERTIFIKAT_PFAD),
        keyfile=str(konfig.SCHLUESSEL_PFAD),
    )
    logger.debug(
        "TLS-Server-Kontext erstellt: Zertifikat=%s, min_version=TLSv1.3",
        konfig.ZERTIFIKAT_PFAD,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.3 – TLS-Kontext für den Client
# ---------------------------------------------------------------------------

def tls_kontext_client() -> ssl.SSLContext:
    """Erstellt den TLS-Kontext für die Client-Seite.

    TLS 1.3 wird als Mindestversion erzwungen. Zertifikatsprüfung ist
    deaktiviert (Self-Signed-Zertifikate in der Entwicklungsumgebung).

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Client.
    """
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.check_hostname = False
    kontext.verify_mode = ssl.CERT_NONE
    logger.debug("TLS-Client-Kontext erstellt: verify_mode=CERT_NONE, min_version=TLSv1.3")
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
        port:      Ziel-Port (Standard: konfig.PORT = 6769).

    Rückgabe:
        (reader, writer) – fertig verbundene TLS-Streams.

    Wirft:
        ssl.SSLError:        Bei fehlgeschlagenem TLS-Handshake.
        OSError:             Bei Verbindungsfehlern.
        asyncio.TimeoutError: Bei überschrittenem VERBINDUNGS_TIMEOUT.
    """
    kontext = tls_kontext_client()
    logger.info("Verbinde zu %s:%d ...", server_ip, port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server_ip, port, ssl=kontext),
            timeout=konfig.VERBINDUNGS_TIMEOUT,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as fehler:
        logger.error("Verbindung zu %s:%d fehlgeschlagen: %s", server_ip, port, fehler)
        raise

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
        3. asyncio.wait(FIRST_COMPLETED) – Gewinner liefert die Verbindung
        4. Verlierer-Task wird per cancel() sauber abgebrochen

    Parameter:
        ziel_ip: IP-Adresse des anderen Peers.
        port:    TCP-Port (Standard: konfig.PORT = 6769).

    Rückgabe:
        (reader, writer, ist_server):
            reader/writer – fertig verbundene TLS-Streams
            ist_server    – True wenn dieser Peer Server-Rolle übernommen hat

    Wirft:
        ConnectionError: Wenn innerhalb von RACE_TIMEOUT keine Verbindung
                         zustande kam oder beide Tasks fehlgeschlagen sind.
    """

    async def _server_versuch() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Bindet den Port und wartet auf einen eingehenden Connect."""
        kontext = tls_kontext_server()
        verbunden: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            if not verbunden.done():
                verbunden.set_result((r, w))
            else:
                w.close()
                await w.wait_closed()

        server = await asyncio.start_server(
            _handle, host=konfig.BIND_ADRESSE, port=port, ssl=kontext,
        )
        try:
            return await asyncio.wait_for(verbunden, timeout=konfig.RACE_TIMEOUT)
        finally:
            server.close()
            # server.wait_closed() würde blockieren bis ALLE aktiven
            # Verbindungen geschlossen sind – d.h. bis die Chat-Sitzung endet.
            # Wir rufen es daher NICHT ab; server.close() genügt, um
            # weitere Verbindungsannahmen zu stoppen.

    async def _client_versuch() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Wartet kurz, dann verbindet sich zum Gegenpeer."""
        await asyncio.sleep(konfig.RACE_CLIENT_VERZOEGERUNG)
        kontext = tls_kontext_client()
        return await asyncio.wait_for(
            asyncio.open_connection(ziel_ip, port, ssl=kontext),
            timeout=konfig.VERBINDUNGS_TIMEOUT,
        )

    logger.info(
        "Race-to-Connect gestartet: Ziel=%s Port=%d Timeout=%.0fs",
        ziel_ip, port, konfig.RACE_TIMEOUT,
    )

    server_task = asyncio.create_task(_server_versuch(), name="RaceServer")
    client_task = asyncio.create_task(_client_versuch(), name="RaceClient")

    # Warte auf ersten *erfolgreichen* Task – ein fehlgeschlagener Task (z.B.
    # ECONNREFUSED beim Client) darf den noch-wartenden Server-Task NICHT
    # abbrechen. Daher wird in einer Schleife weitergewartet solange noch Tasks
    # laufen und noch kein Gewinner gefunden wurde.
    remaining: set[asyncio.Task] = {server_task, client_task}
    winner: asyncio.Task | None = None

    while remaining and winner is None:
        done, remaining = await asyncio.wait(
            remaining,
            return_when=asyncio.FIRST_COMPLETED,
            timeout=konfig.RACE_TIMEOUT + 1,
        )
        if not done:  # Timeout der äußeren Schleife
            break
        for task in done:
            if not task.cancelled() and task.exception() is None:
                winner = task
                break

    for task in remaining:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    if winner is None:
        last_exc = next(
            (t.exception() for t in (server_task, client_task)
             if t.done() and not t.cancelled() and t.exception() is not None),
            None,
        )
        if last_exc:
            raise ConnectionError(f"Race-to-Connect fehlgeschlagen: {last_exc}")
        raise ConnectionError(
            f"Race-to-Connect: Keine Verbindung zu {ziel_ip}:{port} "
            f"innerhalb von {konfig.RACE_TIMEOUT:.0f} Sekunden."
        )

    reader, writer = winner.result()
    ist_server = (winner is server_task)

    logger.info(
        "Race-to-Connect: %s-Rolle übernommen%s",
        "Server" if ist_server else "Client",
        "" if ist_server else f" (Server: {ziel_ip}:{port})",
    )
    return reader, writer, ist_server


# ---------------------------------------------------------------------------
# Task 2.6 – Daten senden
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
# Task 2.6 – Daten empfangen
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
