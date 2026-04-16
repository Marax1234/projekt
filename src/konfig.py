"""
konfig.py – Konfigurationskonstanten

Beschreibung: Zentrale Konfigurationsdatei für alle Konstanten des P2P-Chat-Protokolls.
              Alle Module importieren Werte ausschliesslich von hier.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""

import pathlib

# ---------------------------------------------------------------------------
# Netzwerk
# ---------------------------------------------------------------------------
PORT: int = 6769                      # Standard-TCP-Port für P2P-Chat
BIND_ADRESSE: str = "0.0.0.0"        # Lausch-Adresse für den Server
VERBINDUNGS_TIMEOUT: float = 10.0    # Sekunden bis Verbindungsaufbau abbricht
SENDE_TIMEOUT: float = 10.0          # Sekunden bis Sende-Timeout
MAX_VERBINDUNGEN: int = 1            # Maximale gleichzeitige Verbindungen (P2P = 1)
RACE_TIMEOUT: float = 15.0           # Gesamtwartezeit Race-to-Connect (Sekunden)
RACE_CLIENT_VERZOEGERUNG: float = 0.3  # Verzögerung des Client-Tasks im Race (Sekunden)

# ---------------------------------------------------------------------------
# TLS (mTLS – gegenseitige Authentifizierung)
# ---------------------------------------------------------------------------
_PROJEKT_WURZEL: pathlib.Path = pathlib.Path(__file__).parent.parent
ZERTIFIKAT_PFAD: pathlib.Path = _PROJEKT_WURZEL / "certs" / "zertifikat.pem"
SCHLUESSEL_PFAD: pathlib.Path = _PROJEKT_WURZEL / "certs" / "schluessel.pem"
CA_ZERTIFIKAT_PFAD: pathlib.Path = _PROJEKT_WURZEL / "certs" / "ca_zertifikat.pem"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "WARNING"              # Standard-Log-Level (DEBUG, INFO, WARNING, ERROR)
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATEINAME: str = "p2pchat.log"   # Log-Datei im Projektverzeichnis

# ---------------------------------------------------------------------------
# Anwendungsprotokoll
# ---------------------------------------------------------------------------
APP_VERSION: str = "1.0"              # Anwendungsversion
PROTOKOLL_VERSION: str = "1.0"        # Protokollversion (HELLO-Handshake)
PUFFER_GROESSE: int = 4096            # Empfangspuffer in Bytes (Legacy)
MAX_FRAME_BYTES: int = 65_536         # Maximale NDJSON-Frame-Größe in Bytes (DoS-Schutz)

# Timeouts (Sekunden)
HANDSHAKE_TIMEOUT: float = 5.0        # App-Handshake (HELLO/HELLO_ACK)
ACK_TIMEOUT: float = 5.0              # CHAT → APP_MSG_ACK
IDLE_TIMEOUT:    float = 30.0         # Wartezeit bis zum ersten APP_PING
PONG_TIMEOUT:    float = 10.0         # Wartezeit auf APP_PONG
PRÜF_INTERVALL:  float =  5.0         # Heartbeat-Prüfzyklus
MARGIN:          float =  5.0         # Sicherheitspuffer Empfangs-Timeout
CLOSE_TIMEOUT:   float =  2.0         # Graceful-Close-Warte-Zeit

# Abgeleitet – nie manuell anpassen:
EMPFANG_TIMEOUT: float = IDLE_TIMEOUT + PONG_TIMEOUT + PRÜF_INTERVALL + MARGIN  # = 50 s

# Heartbeat
HEARTBEAT_MAX_FEHLSCHLAEGE: int = 2   # Verpasste PONGs bis Verbindung geschlossen wird

# Reconnect
MAX_RECONNECT_VERSUCHE: int = 10      # Maximale Reconnect-Versuche vor Abbruch

# Deduplizierung
DEDUP_MAX_IDS: int = 1000             # Max. gecachte msg_ids pro Session
