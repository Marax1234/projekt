"""
netzwerk.py – TCP/TLS-Verbindung, Senden, Empfangen

Beschreibung: Verwaltet TCP-Sockets mit TLS 1.3-Verschluesselung. Stellt Funktionen
              fuer Verbindungsaufbau (Server + Client), Daten senden und empfangen
              bereit. Alle Uebertragungen sind laengen-prefixed (4 Byte Big Endian).
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
        daten_senden(conn, b'Hallo TLS 1.3!')
        "

    Wireshark-Validierung:
        tshark -i eth0 -f \"tcp port 6769\" -Y \"tls.handshake\" -c 10
        # Erwartung: TLS 1.3 Handshake sichtbar, Payload verschluesselt
"""

import logging
import socket
import ssl
import struct

import konfig

# Modul-Logger – alle Netzwerk-Ereignisse werden hier protokolliert
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task 2.2 – TLS-Kontext fuer den Server
# ---------------------------------------------------------------------------

def tls_kontext_server() -> ssl.SSLContext:
    """Erstellt den TLS 1.3-Kontext fuer die Server-Seite.

    Laedt Zertifikat und privaten Schluessel aus den in konfig.py
    definierten Pfaden. TLS-Versionen unterhalb von 1.3 sind explizit
    deaktiviert.

    Rueckgabe:
        Fertig konfigurierter ssl.SSLContext fuer den Server.

    Wirft:
        ssl.SSLError: Bei ungueltigem Zertifikat oder Schluessel.
        FileNotFoundError: Wenn Zertifikat- oder Schluesseldatei fehlt.
    """
    # SERVER_AUTH: Server authentifiziert sich gegenueber dem Client
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Nur TLS 1.3 erlauben – aeltere Versionen explizit sperren
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.maximum_version = ssl.TLSVersion.TLSv1_3

    # Zertifikat und privaten Schluessel laden
    kontext.load_cert_chain(
        certfile=str(konfig.ZERTIFIKAT_PFAD),
        keyfile=str(konfig.SCHLUESSEL_PFAD),
    )

    logger.debug(
        "TLS-Server-Kontext erstellt: minimum=%s, Zertifikat=%s",
        kontext.minimum_version,
        konfig.ZERTIFIKAT_PFAD,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.3 – TLS-Kontext fuer den Client
# ---------------------------------------------------------------------------

def tls_kontext_client() -> ssl.SSLContext:
    """Erstellt den TLS 1.3-Kontext fuer die Client-Seite.

    Fuer die Entwicklungsumgebung mit Self-Signed-Zertifikaten wird die
    Zertifikatspruefung deaktiviert (CERT_NONE, check_hostname=False).
    TLS-Versionen unterhalb von 1.3 sind explizit deaktiviert.

    Rueckgabe:
        Fertig konfigurierter ssl.SSLContext fuer den Client.
    """
    # CLIENT_AUTH: Fuer die Verbindung als Client verwenden
    kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Nur TLS 1.3 erlauben – aeltere Versionen explizit sperren
    kontext.minimum_version = ssl.TLSVersion.TLSv1_3
    kontext.maximum_version = ssl.TLSVersion.TLSv1_3

    # Dev-Modus: Self-Signed-Zertifikat akzeptieren (kein CA-Verify)
    kontext.check_hostname = False          # Hostname-Pruefung deaktiviert
    kontext.verify_mode = ssl.CERT_NONE    # Zertifikatspruefung deaktiviert

    logger.debug(
        "TLS-Client-Kontext erstellt: minimum=%s, verify_mode=CERT_NONE",
        kontext.minimum_version,
    )
    return kontext


# ---------------------------------------------------------------------------
# Task 2.7 – TCP-Keepalive konfigurieren (Hilfsfunktion)
# ---------------------------------------------------------------------------

def _keepalive_konfigurieren(sock: socket.socket) -> None:
    """Aktiviert und konfiguriert TCP-Keepalive auf einem Socket.

    Setzt SO_KEEPALIVE sowie (auf Linux) TCP_KEEPIDLE, TCP_KEEPINTVL
    und TCP_KEEPCNT, um abgestorbene Verbindungen fruehzeitig zu erkennen.
    Auf Nicht-Linux-Systemen wird nur SO_KEEPALIVE gesetzt.

    Parameter:
        sock: Der zu konfigurierende TCP-Socket.
    """
    if not konfig.KEEPALIVE_AKTIV:
        return

    # Keepalive grundsaetzlich aktivieren
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Plattformspezifische Feineinstellungen (Linux)
    if hasattr(socket, "TCP_KEEPIDLE"):
        # Sekunden Inaktivitaet, bevor der erste Keepalive-Probe gesendet wird
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, konfig.KEEPALIVE_IDLE)
    if hasattr(socket, "TCP_KEEPINTVL"):
        # Sekunden zwischen zwei Keepalive-Probes
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, konfig.KEEPALIVE_INTERVALL)
    if hasattr(socket, "TCP_KEEPCNT"):
        # Anzahl unbeantworteter Probes, bevor die Verbindung als tot gilt
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, konfig.KEEPALIVE_PROBES)

    logger.debug(
        "Keepalive konfiguriert: idle=%ds, intervall=%ds, probes=%d",
        konfig.KEEPALIVE_IDLE,
        konfig.KEEPALIVE_INTERVALL,
        konfig.KEEPALIVE_PROBES,
    )


# ---------------------------------------------------------------------------
# Task 2.1 – Server-Socket erstellen
# ---------------------------------------------------------------------------

def server_erstellen() -> socket.socket:
    """Erstellt und bindet einen TCP-Socket fuer den Server-Betrieb.

    Der Socket wird an BIND_ADRESSE:PORT gebunden, auf SO_REUSEADDR
    gesetzt (schneller Neustart nach Absturz) und in den Lausch-Zustand
    versetzt. Keepalive wird bereits auf dem Basis-Socket aktiviert, damit
    alle akzeptierten Verbindungen die Einstellung erben.

    Rueckgabe:
        Gebundener und lauschender TCP-Socket (noch ohne TLS).

    Wirft:
        OSError: Wenn der Port bereits belegt ist oder Bind fehlschlaegt.
    """
    srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 TCP-Socket

    # Sofortigen Neustart ohne TIME_WAIT-Wartezeit ermoeglichen
    srv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Keepalive auf dem Server-Socket konfigurieren
    _keepalive_konfigurieren(srv_socket)

    # An Adresse und Port binden
    srv_socket.bind((konfig.BIND_ADRESSE, konfig.PORT))

    # Lausch-Warteschlange aktivieren (max. 1 Verbindung fuer P2P)
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
    anschliessend mit dem Server-TLS-Kontext und fuehrt den TLS 1.3 Handshake
    durch.

    Parameter:
        srv_socket: Der lauschende TCP-Server-Socket (von server_erstellen()).

    Rueckgabe:
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

    # Keepalive auf dem akzeptierten Socket sicherstellen
    _keepalive_konfigurieren(roh_socket)

    # Sende-Timeout setzen, damit blockierende Sends nicht ewig warten
    roh_socket.settimeout(konfig.SENDE_TIMEOUT)

    # TLS-Kontext laden und Handshake durchfuehren
    tls_kontext = tls_kontext_server()
    try:
        tls_socket: ssl.SSLSocket = tls_kontext.wrap_socket(
            roh_socket,
            server_side=True,  # Server-Rolle: praesentiert Zertifikat
        )
    except ssl.SSLError as fehler:
        logger.error("TLS-Handshake fehlgeschlagen (Server): %s", fehler)
        roh_socket.close()
        raise

    logger.info(
        "TLS 1.3 Handshake abgeschlossen – Peer: %s, Cipher: %s",
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
    """Stellt eine TLS 1.3-Verbindung zum Server her.

    Erstellt einen TCP-Socket, konfiguriert Keepalive und Timeouts,
    verbindet sich zum Server und fuehrt den TLS-Handshake durch.

    Parameter:
        server_ip: IP-Adresse oder Hostname des Ziel-Servers.
        port:      Ziel-Port (Standard: konfig.PORT = 6769).

    Rueckgabe:
        Fertig verbundener und handshaked ssl.SSLSocket.

    Wirft:
        ssl.SSLError: Bei fehlgeschlagenem TLS-Handshake.
        OSError: Bei Verbindungsfehlern (z. B. Server nicht erreichbar).
    """
    roh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 TCP-Socket

    # Verbindungs-Timeout setzen, damit der Client nicht ewig blockiert
    roh_socket.settimeout(konfig.VERBINDUNGS_TIMEOUT)

    # Keepalive aktivieren
    _keepalive_konfigurieren(roh_socket)

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

    # TLS-Kontext laden und Handshake durchfuehren
    tls_kontext = tls_kontext_client()
    try:
        tls_socket: ssl.SSLSocket = tls_kontext.wrap_socket(
            roh_socket,
            server_side=False,  # Client-Rolle: prueft Zertifikat des Servers
            server_hostname=None,  # Kein SNI noetig (Self-Signed, check_hostname=False)
        )
    except ssl.SSLError as fehler:
        logger.error("TLS-Handshake fehlgeschlagen (Client): %s", fehler)
        roh_socket.close()
        raise

    logger.info(
        "TLS 1.3 Handshake abgeschlossen – Server: %s:%d, Cipher: %s",
        server_ip,
        port,
        tls_socket.cipher(),
    )
    return tls_socket


# ---------------------------------------------------------------------------
# Task 2.6 – Daten senden (laengen-prefixed)
# ---------------------------------------------------------------------------

def daten_senden(verbindung: ssl.SSLSocket, daten: bytes) -> None:
    """Sendet Bytes-Daten laengen-prefixed ueber die TLS-Verbindung.

    Dem Nutzdaten-Paket wird ein 4-Byte-Header (Big Endian, uint32)
    vorangestellt, der die Laenge der Nutzdaten angibt. So kann der
    Empfaenger exakt die richtige Anzahl Bytes lesen.

    Protokoll-Frame:
        | Laenge (4B, uint32, Big Endian) | Nutzdaten (nB) |

    Parameter:
        verbindung: Die aktive TLS-Socket-Verbindung.
        daten:      Die zu sendenden Nutzdaten als Bytes.

    Wirft:
        ValueError: Wenn die Nutzdaten die maximale Groesse ueberschreiten.
        OSError:    Bei Netzwerkfehlern waehrend des Sendens.
        ssl.SSLError: Bei TLS-Fehlern.
    """
    laenge = len(daten)

    if laenge > konfig.MAX_PAYLOAD_GROESSE:
        raise ValueError(
            f"Nutzdaten zu gross: {laenge} Bytes > Maximum {konfig.MAX_PAYLOAD_GROESSE} Bytes"
        )

    # 4-Byte-Laengen-Prefix im Network Byte Order (Big Endian) berechnen
    # Format: '!I' = unsigned int, 4 Bytes, Big Endian
    laengen_prefix = struct.pack("!I", laenge)

    try:
        verbindung.sendall(laengen_prefix + daten)  # Atomarer Sendeaufruf
    except (OSError, ssl.SSLError) as fehler:
        logger.error("Senden fehlgeschlagen (%d Bytes): %s", laenge, fehler)
        raise

    logger.debug("Gesendet: %d Bytes Nutzdaten", laenge)


# ---------------------------------------------------------------------------
# Task 2.6 – Daten empfangen (laengen-prefixed)
# ---------------------------------------------------------------------------

def daten_empfangen(verbindung: ssl.SSLSocket) -> bytes:
    """Empfaengt ein laengen-prefixed Paket von der TLS-Verbindung.

    Liest zunaechst den 4-Byte-Laengen-Header, dann exakt die angegebene
    Anzahl Nutzdaten-Bytes. Verhindert so Datenverlust durch TCP-Segmentierung.

    Protokoll-Frame:
        | Laenge (4B, uint32, Big Endian) | Nutzdaten (nB) |

    Parameter:
        verbindung: Die aktive TLS-Socket-Verbindung.

    Rueckgabe:
        Die empfangenen Nutzdaten als Bytes.

    Wirft:
        ConnectionError: Wenn die Verbindung waehrend des Empfangs getrennt wird.
        OSError:         Bei Netzwerkfehlern.
        ssl.SSLError:    Bei TLS-Fehlern.
    """
    # Schritt 1: Exakt 4 Bytes fuer den Laengen-Header lesen
    laengen_bytes = _exakt_lesen(verbindung, 4)

    # Format: '!I' = unsigned int, 4 Bytes, Big Endian
    (nutzdaten_laenge,) = struct.unpack("!I", laengen_bytes)

    if nutzdaten_laenge == 0:
        logger.debug("Leeres Paket empfangen (0 Bytes Nutzdaten)")
        return b""

    if nutzdaten_laenge > konfig.MAX_PAYLOAD_GROESSE:
        raise ValueError(
            f"Angekuendigte Nutzdaten-Laenge zu gross: {nutzdaten_laenge} Bytes"
        )

    # Schritt 2: Exakt die angekuendigte Anzahl Nutzdaten-Bytes lesen
    nutzdaten = _exakt_lesen(verbindung, nutzdaten_laenge)

    logger.debug("Empfangen: %d Bytes Nutzdaten", nutzdaten_laenge)
    return nutzdaten


def _exakt_lesen(verbindung: ssl.SSLSocket, anzahl_bytes: int) -> bytes:
    """Liest exakt die angegebene Anzahl Bytes vom Socket.

    Wiederholt recv() bis alle Bytes angekommen sind. Notwendig, weil
    TCP ein Strom-Protokoll ist und recv() weniger Bytes liefern kann
    als angefordert.

    Parameter:
        verbindung:   Die aktive TLS-Socket-Verbindung.
        anzahl_bytes: Exakte Anzahl der zu lesenden Bytes.

    Rueckgabe:
        Bytes-Objekt mit genau anzahl_bytes Bytes.

    Wirft:
        ConnectionError: Wenn die Verbindung vor Vollstaendigkeit getrennt wird.
        OSError:         Bei Netzwerkfehlern.
    """
    puffer = bytearray()  # Empfangspuffer fuer unvollstaendige Reads

    while len(puffer) < anzahl_bytes:
        noch_noetig = anzahl_bytes - len(puffer)  # Verbleibende Bytes

        try:
            chunk = verbindung.recv(min(noch_noetig, konfig.PUFFER_GROESSE))
        except (OSError, ssl.SSLError) as fehler:
            logger.error("Empfangsfehler nach %d/%d Bytes: %s", len(puffer), anzahl_bytes, fehler)
            raise

        if not chunk:
            # Leeres chunk = Verbindung vom Peer getrennt
            raise ConnectionError(
                f"Verbindung getrennt nach {len(puffer)}/{anzahl_bytes} Bytes"
            )

        puffer.extend(chunk)

    return bytes(puffer)
