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
EMPFANG_TIMEOUT: float = 30.0        # Sekunden bis Empfangs-Timeout
SENDE_TIMEOUT: float = 10.0          # Sekunden bis Sende-Timeout
MAX_VERBINDUNGEN: int = 1            # Maximale gleichzeitige Verbindungen (P2P = 1)
RACE_TIMEOUT: float = 15.0           # Gesamtwartezeit Race-to-Connect (Sekunden)
RACE_CLIENT_VERZOEGERUNG: float = 0.3  # Verzögerung des Client-Threads im Race (Sekunden)

# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
ZERTIFIKAT_PFAD: pathlib.Path = pathlib.Path(__file__).parent / "zertifikat.pem"
SCHLUESSEL_PFAD: pathlib.Path = pathlib.Path(__file__).parent / "schluessel.pem"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "WARNING"              # Standard-Log-Level (DEBUG, INFO, WARNING, ERROR)
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATEINAME: str = "p2pchat.log"   # Log-Datei im Projektverzeichnis

# ---------------------------------------------------------------------------
# Anwendung
# ---------------------------------------------------------------------------
APP_VERSION: str = "1.0"             # Anwendungsversion
PUFFER_GROESSE: int = 4096           # Empfangspuffer in Bytes
