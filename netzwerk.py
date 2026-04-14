"""
netzwerk.py – TCP/TLS-Verbindung, Senden, Empfangen

Beschreibung: Verwaltet TCP-Sockets mit TLS-Verschlüsselung. Stellt Funktionen
              für Verbindungsaufbau (Server + Client), Daten senden und empfangen
              bereit.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Testschritte (2 Terminals):
    Terminal 1 (Server):
        python3 -c "
        from netzwerk import server_erstellen, verbindung_akzeptieren, daten_empfangen
        srv = server_erstellen()
        conn, addr = verbindung_akzeptieren(srv)
        print(f'Verbunden mit {addr}')
        print(daten_empfangen(conn))
        "

    Terminal 2 (Client):
        python3 -c "
        from netzwerk import verbindung_herstellen, daten_senden
        conn = verbindung_herstellen('127.0.0.1')
        daten_senden(conn, b'Hallo TLS!')
        "

    Wireshark-Validierung:
        tshark -i eth0 -f \"tcp port 6769\" -Y \"tls.handshake\" -c 10
        # Erwartung: TLS-Handshake sichtbar, Payload verschlüsselt
"""

import logging
import socket
import ssl

import konfig

# Modul-Logger – alle Netzwerk-Ereignisse werden hier protokolliert
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task 2.2 – TLS-Kontext für den Server
# ---------------------------------------------------------------------------

def tls_kontext_server() -> ssl.SSLContext:
    """Erstellt den TLS-Kontext für die Server-Seite.

    Lädt Zertifikat und privaten Schlüssel aus den in konfig.py
    definierten Pfaden.

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Server.

    Wirft:
        ssl.SSLError: Bei ungültigem Zertifikat oder Schlüssel.
        FileNotFoundError: Wenn Zertifikat- oder Schlüsseldatei fehlt.
    """
    # SERVER_AUTH: Server authentifiziert sich gegenüber dem Client
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Zertifikat und privaten Schlüssel laden
    kontext.load_cert_chain(
        certfile=str(konfig.ZERTIFIKAT_PFAD),
        keyfile=str(konfig.SCHLUESSEL_PFAD),
    )

    logger.debug(
        "TLS-Server-Kontext erstellt: Zertifikat=%s",
        konfig.ZERTIFIKAT_PFAD,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.3 – TLS-Kontext für den Client
# ---------------------------------------------------------------------------

def tls_kontext_client() -> ssl.SSLContext:
    """Erstellt den TLS-Kontext für die Client-Seite.

    Für die Entwicklungsumgebung mit Self-Signed-Zertifikaten wird die
    Zertifikatsprüfung deaktiviert (CERT_NONE, check_hostname=False).

    Rückgabe:
        Fertig konfigurierter ssl.SSLContext für den Client.
    """
    # CLIENT_AUTH: Für die Verbindung als Client verwenden
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Dev-Modus: Self-Signed-Zertifikat akzeptieren (kein CA-Verify)
    kontext.check_hostname = False          # Hostname-Prüfung deaktiviert
    kontext.verify_mode = ssl.CERT_NONE    # Zertifikatsprüfung deaktiviert

    logger.debug("TLS-Client-Kontext erstellt: verify_mode=CERT_NONE")
    return kontext


# ---------------------------------------------------------------------------
# Task 2.1 – Server-Socket erstellen
# ---------------------------------------------------------------------------

def server_erstellen() -> socket.socket:
    """Erstellt und bindet einen TCP-Socket für den Server-Betrieb.

    Der Socket wird an BIND_ADRESSE:PORT gebunden, auf SO_REUSEADDR
    gesetzt (schneller Neustart nach Absturz) und in den Lausch-Zustand
    versetzt.

    Rückgabe:
        Gebundener und lauschender TCP-Socket (noch ohne TLS).

    Wirft:
        OSError: Wenn der Port bereits belegt ist oder Bind fehlschlägt.
    """
    srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 TCP-Socket

    # Sofortigen Neustart ohne TIME_WAIT-Wartezeit ermöglichen
    srv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # An Adresse und Port binden
    srv_socket.bind((konfig.BIND_ADRESSE, konfig.PORT))

    # Lausch-Warteschlange aktivieren (max. 1 Verbindung für P2P)
    srv_socket.listen(konfig.MAX_VERBINDUNGEN)

    logger.info(
        "Server-Socket erstellt: lauscht auf %s:%d",
        konfig.BIND_ADRESSE,
        konfig.PORT,
    )
    return srv_socket


# ---------------------------------------------------------------------------
# Task 2.4 – Verbindung akzeptieren
# ---------------------------------------------------------------------------

def verbindung_akzeptieren(srv_socket: socket.socket) -> tuple[ssl.SSLSocket, tuple]:
    """Wartet auf eine eingehende Verbindung und schliesst den TLS-Handshake ab.

    Blockiert, bis ein Client sich verbindet. Umwickelt den rohen TCP-Socket
    anschliessend mit dem Server-TLS-Kontext und führt den TLS-Handshake
    durch.

    Parameter:
        srv_socket: Der lauschende TCP-Server-Socket (von server_erstellen()).

    Rückgabe:
        Tupel (tls_socket, adresse) – tls_socket ist verwendungsbereit.

    Wirft:
        ssl.SSLError: Bei fehlgeschlagenem TLS-Handshake.
        OSError: Bei Netzwerkfehlern.
    """
    logger.info("Warte auf eingehende Verbindung ...")

    try:
        roh_socket, adresse = srv_socket.accept()  # Blockiert bis Client verbindet
    except OSError as fehler:
        logger.error("Fehler beim Akzeptieren der Verbindung: %s", fehler)
        raise

    logger.info("TCP-Verbindung von %s:%d akzeptiert", adresse[0], adresse[1])

    # Sende-Timeout setzen, damit blockierende Sends nicht ewig warten
    roh_socket.settimeout(konfig.SENDE_TIMEOUT)

    # TLS-Kontext laden und Handshake durchführen
    tls_kontext = tls_kontext_server()
    try:
        tls_socket: ssl.SSLSocket = tls_kontext.wrap_socket(
            roh_socket,
            server_side=True,  # Server-Rolle: präsentiert Zertifikat
        )
    except ssl.SSLError as fehler:
        logger.error("TLS-Handshake fehlgeschlagen (Server): %s", fehler)
        roh_socket.close()
        raise

    logger.info(
        "TLS-Handshake abgeschlossen – Peer: %s, Cipher: %s",
        adresse,
        tls_socket.cipher(),
    )
    return tls_socket, adresse


# ---------------------------------------------------------------------------
# Task 2.5 – Verbindung herstellen (Client)
# ---------------------------------------------------------------------------

def verbindung_herstellen(
    server_ip: str,
    port: int = konfig.PORT,
) -> ssl.SSLSocket:
    """Stellt eine TLS-Verbindung zum Server her.

    Erstellt einen TCP-Socket, konfiguriert Timeouts,
    verbindet sich zum Server und führt den TLS-Handshake durch.

    Parameter:
        server_ip: IP-Adresse oder Hostname des Ziel-Servers.
        port:      Ziel-Port (Standard: konfig.PORT = 6769).

    Rückgabe:
        Fertig verbundener und handshaked ssl.SSLSocket.

    Wirft:
        ssl.SSLError: Bei fehlgeschlagenem TLS-Handshake.
        OSError: Bei Verbindungsfehlern (z. B. Server nicht erreichbar).
    """
    roh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 TCP-Socket

    # Verbindungs-Timeout setzen, damit der Client nicht ewig blockiert
    roh_socket.settimeout(konfig.VERBINDUNGS_TIMEOUT)

    logger.info("Verbinde zu %s:%d ...", server_ip, port)

    try:
        roh_socket.connect((server_ip, port))
    except OSError as fehler:
        logger.error("Verbindung zu %s:%d fehlgeschlagen: %s", server_ip, port, fehler)
        roh_socket.close()
        raise

    logger.info("TCP-Verbindung zu %s:%d hergestellt", server_ip, port)

    # Nach erfolgreichem Connect auf Sende/Empfangs-Timeout umschalten
    roh_socket.settimeout(konfig.SENDE_TIMEOUT)

    # TLS-Kontext laden und Handshake durchführen
    tls_kontext = tls_kontext_client()
    try:
        tls_socket: ssl.SSLSocket = tls_kontext.wrap_socket(
            roh_socket,
            server_side=False,  # Client-Rolle: prüft Zertifikat des Servers
            server_hostname=None,  # Kein SNI nötig (Self-Signed, check_hostname=False)
        )
    except ssl.SSLError as fehler:
        logger.error("TLS-Handshake fehlgeschlagen (Client): %s", fehler)
        roh_socket.close()
        raise

    logger.info(
        "TLS-Handshake abgeschlossen – Server: %s:%d, Cipher: %s",
        server_ip,
        port,
        tls_socket.cipher(),
    )
    return tls_socket


# ---------------------------------------------------------------------------
# Task 2.6 – Daten senden
# ---------------------------------------------------------------------------

def daten_senden(verbindung: ssl.SSLSocket, daten: bytes) -> None:
    """Sendet Bytes-Daten über die TLS-Verbindung.

    Parameter:
        verbindung: Die aktive TLS-Socket-Verbindung.
        daten:      Die zu sendenden Nutzdaten als Bytes.

    Wirft:
        OSError:      Bei Netzwerkfehlern während des Sendens.
        ssl.SSLError: Bei TLS-Fehlern.
    """
    laenge = len(daten)  # Länge der Nutzdaten für das Logging

    try:
        verbindung.sendall(daten)  # Alle Bytes atomar senden
    except (OSError, ssl.SSLError) as fehler:
        logger.error("Senden fehlgeschlagen (%d Bytes): %s", laenge, fehler)
        raise

    logger.debug("Gesendet: %d Bytes Nutzdaten", laenge)


# ---------------------------------------------------------------------------
# Task 2.6 – Daten empfangen
# ---------------------------------------------------------------------------

def daten_empfangen(verbindung: ssl.SSLSocket) -> bytes:
    """Empfängt ein Datenpaket von der TLS-Verbindung.

    Liest bis zu PUFFER_GROESSE Bytes vom TLS-Socket.

    Parameter:
        verbindung: Die aktive TLS-Socket-Verbindung.

    Rückgabe:
        Die empfangenen Nutzdaten als Bytes.

    Wirft:
        ConnectionError: Wenn die Verbindung getrennt wurde.
        OSError:         Bei Netzwerkfehlern.
        ssl.SSLError:    Bei TLS-Fehlern.
    """
    try:
        chunk = verbindung.recv(konfig.PUFFER_GROESSE)  # Empfang eines TLS-Records
    except (OSError, ssl.SSLError) as fehler:
        if isinstance(fehler, (socket.timeout, TimeoutError)):
            logger.debug("Empfangs-Timeout")
        else:
            logger.error("Empfangsfehler: %s", fehler)
        raise

    if not chunk:
        # Leeres Ergebnis = Verbindung vom Peer getrennt
        raise ConnectionError("Verbindung getrennt")

    logger.debug("Empfangen: %d Bytes Nutzdaten", len(chunk))
    return chunk
