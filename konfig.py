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
APP_VERSION: str = "1.0"             # Anwendungsversion
PUFFER_GROESSE: int = 4096           # Empfangspuffer in Bytes
