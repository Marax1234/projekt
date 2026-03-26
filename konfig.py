"""
konfig.py – Konfigurationskonstanten

Beschreibung: Zentrale Konfigurationsdatei fuer alle Konstanten des P2P-Chat-Protokolls.
              Alle Module importieren Werte ausschliesslich von hier.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""

import pathlib

# ---------------------------------------------------------------------------
# Netzwerk
# ---------------------------------------------------------------------------
PORT: int = 6769                      # Standard-TCP-Port fuer P2P-Chat
BIND_ADRESSE: str = "0.0.0.0"        # Lausch-Adresse fuer den Server
VERBINDUNGS_TIMEOUT: float = 10.0    # Sekunden bis Verbindungsaufbau abbricht
EMPFANG_TIMEOUT: float = 30.0        # Sekunden bis Empfangs-Timeout
SENDE_TIMEOUT: float = 10.0          # Sekunden bis Sende-Timeout
MAX_VERBINDUNGEN: int = 1            # Maximale gleichzeitige Verbindungen (P2P = 1)

# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
ZERTIFIKAT_PFAD: pathlib.Path = pathlib.Path(__file__).parent / "zertifikat.pem"
SCHLUESSEL_PFAD: pathlib.Path = pathlib.Path(__file__).parent / "schluessel.pem"

# ---------------------------------------------------------------------------
# Protokoll
# ---------------------------------------------------------------------------
PROTOKOLL_VERSION: int = 0x01        # Aktuelle Protokollversion
HEADER_GROESSE: int = 42             # Bytes: 1 (Version) + 1 (Typ) + 4 (Seq) + 4 (Laenge) + 32 (HMAC)
MAX_PAYLOAD_GROESSE: int = 65535     # Maximale Payload-Groesse in Bytes

# Nachrichtentypen
TYP_CONNECT: int = 0x01             # Verbindungsaufbau-Paket
TYP_DATA: int = 0x02                # Datennachricht
TYP_DISCONNECT: int = 0x03         # Verbindungsabbau-Paket
TYP_ACK: int = 0x04                 # Bestaetigung

# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------
HMAC_ALGORITHMUS: str = "sha256"     # Hash-Algorithmus fuer HMAC
HMAC_LAENGE: int = 32                # HMAC-SHA256 Ausgabelaenge in Bytes
GETEILTES_GEHEIMNIS: bytes = b"NetSec2026-P2PChat-SharedSecret"  # HMAC-Schluessel

# ---------------------------------------------------------------------------
# Wiederverbindung / Retry
# ---------------------------------------------------------------------------
MAX_WIEDERHOLUNGEN: int = 3          # Maximale Sendewiederholungen bei Timeout
BACKOFF_BASIS: float = 1.0           # Basis-Wartezeit in Sekunden (exponentiell)
BACKOFF_FAKTOR: float = 2.0          # Multiplikator fuer exponentiellen Backoff
BACKOFF_MAX: float = 30.0            # Maximale Wartezeit zwischen Versuchen
RECONNECT_MAX_VERSUCHE: int = 4      # Reconnect-Versuche: 1s→2s→4s→8s→Abbruch

# ---------------------------------------------------------------------------
# Heartbeat (Sprint 4.6 – optional, fuer Sprint 6 vorgesehen)
# ---------------------------------------------------------------------------
HEARTBEAT_AKTIV: bool = False        # App-Layer-Keepalive deaktiviert (Sprint 6)
HEARTBEAT_INTERVALL: float = 30.0   # Sekunden zwischen Heartbeat-Pings

# ---------------------------------------------------------------------------
# Keepalive
# ---------------------------------------------------------------------------
KEEPALIVE_AKTIV: bool = True         # TCP SO_KEEPALIVE aktivieren
KEEPALIVE_IDLE: int = 60             # Sekunden Inaktivitaet vor erstem Keepalive-Probe
KEEPALIVE_INTERVALL: int = 10        # Sekunden zwischen Keepalive-Probes
KEEPALIVE_PROBES: int = 5            # Anzahl Probes bevor Verbindung als tot gilt

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "WARNING"              # Standard-Log-Level (DEBUG, INFO, WARNING, ERROR)
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATEINAME: str = "p2pchat.log"   # Log-Datei im Projektverzeichnis

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
FENSTER_TITEL: str = "P2P Chat – NetSec 2026"
FENSTER_BREITE: int = 800
FENSTER_HOEHE: int = 600
SCHRIFTART: tuple = ("Courier", 11)  # Monospace-Schrift fuer Chat-Verlauf
GUI_QUEUE_INTERVALL: int = 100       # Millisekunden fuer root.after() Queue-Polling

# ---------------------------------------------------------------------------
# Anwendung
# ---------------------------------------------------------------------------
APP_VERSION: str = "1.0"             # Anwendungsversion (fuer CONNECT-Paket)
PUFFER_GROESSE: int = 4096           # Empfangspuffer in Bytes
